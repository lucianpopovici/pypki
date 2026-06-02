#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Code-signing portal orchestrator.

Accepts CI/CD artifact submissions with in-toto attestations and an OIDC
identity token, issues an ephemeral code-signing certificate, signs the
artifact provenance, records everything in the Merkle transparency log,
and returns a verification bundle.

This is "Sigstore for your private code."  Pairs naturally with GitHub Actions,
GitLab CI, or any build runner that produces an OIDC token and in-toto
attestations.

Stdlib + cryptography only; no sigstore/in-toto pip deps.
"""

import base64
import dataclasses
import hashlib
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

import intoto
import merkle_log
from intoto import DSSEEnvelope, SLSAStatement, parse_envelope, parse_slsa_statement

log = logging.getLogger("pypki.codesign")

_PYPKI_CODESIGN_PREDICATE = "https://pypki.dev/attestations/codesign/v1"

# ---------------------------------------------------------------------------
# Issuer configuration
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class CodeSignIssuer:
    """A trusted OIDC issuer for CI build runner identity tokens."""
    url:              str
    audience:         str
    identity_claim:   str = "sub"
    identity_pattern: str = ".*"   # regex matched against identity_claim value


def load_issuers_file(path: str) -> List[CodeSignIssuer]:
    """Load issuer configuration from a JSON file."""
    doc = json.loads(open(path).read())
    return [
        CodeSignIssuer(
            url=i["url"],
            audience=i["audience"],
            identity_claim=i.get("identity_claim", "sub"),
            identity_pattern=i.get("identity_pattern", ".*"),
        )
        for i in doc.get("issuers", [])
    ]


# ---------------------------------------------------------------------------
# OIDC token validation for build runners
# ---------------------------------------------------------------------------

def validate_build_token(
    token: str,
    issuers: List[CodeSignIssuer],
    jwks_cache_map: Dict[str, Any],  # issuer_url → JWKSCache
) -> tuple:
    """
    Validate an OIDC token against the configured issuers.

    Returns (identity, issuer_url).
    Raises ValueError for unknown issuers or invalid tokens.
    """
    import oidc as _oidc

    # Decode the header to find issuer
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed OIDC token")
    import json as _json
    payload = _json.loads(_oidc._b64url_decode(parts[1]))
    token_iss = payload.get("iss", "")

    for issuer in issuers:
        if issuer.url != token_iss:
            continue
        cache = jwks_cache_map.get(issuer.url)
        if cache is None:
            raise ValueError(f"No JWKS cache for issuer: {issuer.url!r}")
        # Get JWKS for the key id
        hdr = _json.loads(_oidc._b64url_decode(parts[0]))
        kid = hdr.get("kid", "")
        jwks = cache.get_jwks_for_kid(kid) if hasattr(cache, "get_jwks_for_kid") else cache
        claims = _oidc.verify_id_token(
            token, jwks, issuer.url, issuer.audience
        )
        identity = claims.get(issuer.identity_claim, "")
        if not re.match(issuer.identity_pattern, identity):
            raise ValueError(
                f"Identity {identity!r} does not match issuer pattern {issuer.identity_pattern!r}"
            )
        return identity, issuer.url

    raise ValueError(f"OIDC token issuer {token_iss!r} is not in the trusted issuers list")


# ---------------------------------------------------------------------------
# Codesign service
# ---------------------------------------------------------------------------

class CodeSignService:
    """
    Orchestrates the code-signing portal workflow.

    Parameters
    ----------
    ca                    : CertificateAuthority
    db                    : Database connection (PKI DB)
    issuers               : List of trusted CodeSignIssuer entries
    jwks_cache_map        : Dict[issuer_url → JWKSCache] for token validation
    ephemeral_validity_s  : Lifetime of ephemeral signing certs (default 600s)
    max_artifact_bytes    : Maximum artifact size check in submission (soft limit)
    max_attestation_count : Maximum number of attestations per submission
    audit_log             : AuditLog instance (optional)
    """

    def __init__(
        self,
        ca,
        db,
        issuers: List[CodeSignIssuer],
        jwks_cache_map: Optional[Dict[str, Any]] = None,
        ephemeral_validity_s: int = 600,
        max_artifact_bytes: int  = 500 * 1024 * 1024,
        max_attestation_count: int = 16,
        audit_log=None,
    ) -> None:
        self._ca                   = ca
        self._db                   = db
        self._issuers              = issuers
        self._jwks_cache_map       = jwks_cache_map or {}
        self._ephemeral_validity_s = ephemeral_validity_s
        self._max_artifact_bytes   = max_artifact_bytes
        self._max_attestation_count= max_attestation_count
        self._audit_log            = audit_log

    def submit(
        self,
        artifacts: List[Dict],          # [{name, digest: {sha256: ...}}]
        attestations_b64: List[str],    # base64-encoded DSSE envelopes
        oidc_token: str,
        requester_ip: str = "",
    ) -> Dict[str, Any]:
        """
        Process a code-signing submission.

        1. Validate OIDC token → identity + issuer
        2. Decode and parse DSSE attestations
        3. Issue ephemeral code-signing cert with identity as URI SAN
        4. Sign a PyPKI codesign attestation with the ephemeral key
        5. Append to Merkle log
        6. Record in codesign_log_entries
        7. Zeroize the ephemeral private key
        8. Return the verification bundle

        Raises ValueError for invalid input, PermissionError for policy denial.
        """
        # Validate input counts
        if len(attestations_b64) > self._max_attestation_count:
            raise ValueError(
                f"Too many attestations: {len(attestations_b64)} > {self._max_attestation_count}"
            )

        # Step 1: validate OIDC token
        identity, issuer_url = validate_build_token(
            oidc_token, self._issuers, self._jwks_cache_map
        )
        log.info("Code-sign submission: identity=%s issuer=%s", identity, issuer_url)

        # Step 2: decode attestations
        envelopes: List[DSSEEnvelope] = []
        statements: List[SLSAStatement] = []
        for i, b64 in enumerate(attestations_b64):
            try:
                raw  = base64.b64decode(b64)
                env  = parse_envelope(raw)
                envelopes.append(env)
                try:
                    stmt = parse_slsa_statement(env.payload)
                    statements.append(stmt)
                except Exception as exc:
                    log.debug("Attestation %d is not a SLSA statement: %s", i, exc)
            except Exception as exc:
                raise ValueError(f"Attestation {i}: {exc}") from exc

        # Step 3: issue ephemeral cert
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives.serialization import Encoding
        ephemeral_priv = _ec.generate_private_key(_ec.SECP256R1())
        ephemeral_pub  = ephemeral_priv.public_key()

        # URI SAN carries the OIDC identity (Sigstore convention)
        cert = self._ca.issue_certificate(
            subject_str   = f"CN=ephemeral-codesign",
            public_key    = ephemeral_pub,
            profile       = "code_signing_ephemeral",
            validity_days = max(1, self._ephemeral_validity_s // 86400),
            san_uris      = [identity],
            requester_ip  = requester_ip,
            protocol      = "codesign-portal",
        )
        cert_pem     = cert.public_bytes(Encoding.PEM).decode()
        cert_serial  = format(cert.serial_number, "x")

        # Step 4: build + sign a PyPKI codesign attestation
        attestation_hashes = [intoto.envelope_hash(e) for e in envelopes]
        codesign_payload = json.dumps({
            "_type":          "https://in-toto.io/Statement/v1",
            "predicateType":  _PYPKI_CODESIGN_PREDICATE,
            "subject":        artifacts,
            "predicate": {
                "signing_identity":   identity,
                "issuer":             issuer_url,
                "attestation_hashes": attestation_hashes,
                "signed_at":          int(time.time()),
            },
        }).encode()
        codesign_env = intoto.sign_envelope(intoto.DSSE_CONTENT_TYPE, codesign_payload, ephemeral_priv)
        signature    = codesign_env.signatures[0].sig

        # Step 5: append to Merkle log
        entry_hash   = hashlib.sha256(codesign_env.to_json().encode()).digest()
        seq, leaf    = merkle_log.append(entry_hash, self._db)
        entry_id     = f"{seq:04d}-{entry_hash.hex()[:16]}"

        # Step 6: record in DB
        now   = int(time.time())
        self._db.execute(
            "INSERT INTO codesign_log_entries "
            "(id, sequence, logged_at, artifact_digests, signing_identity, issuer, "
            "ephemeral_cert_pem, ephemeral_serial, signature, attestation_chain, "
            "policy_decisions, tree_node_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry_id, seq, now,
                json.dumps(artifacts),
                identity, issuer_url,
                cert_pem, cert_serial,
                signature,
                json.dumps(attestation_hashes),
                json.dumps([]),
                leaf,
            ),
        )

        # Store attestation envelopes
        for env in envelopes:
            ehash = intoto.envelope_hash(env)
            try:
                self._db.execute(
                    "INSERT OR IGNORE INTO codesign_attestations "
                    "(hash, envelope_json, predicate_type, received_at) VALUES (?, ?, ?, ?)",
                    (ehash, env.to_json(), env.payload_type, now),
                )
            except Exception:
                pass

        # Step 7: zeroize ephemeral key (Python can't truly zeroize memory; we discard the ref)
        del ephemeral_priv

        if self._audit_log:
            try:
                self._audit_log.record(
                    "codesign.submit",
                    f"entry={entry_id} identity={identity} artifacts={len(artifacts)}",
                    requester_ip,
                )
            except Exception:
                pass

        # Step 8: return bundle
        bundle = {
            "format":          "pypki-codesign/v1",
            "entry_id":        entry_id,
            "signing_identity":identity,
            "issuer":          issuer_url,
            "cert_pem":        cert_pem,
            "signature":       base64.b64encode(signature).decode(),
            "codesign_envelope": base64.b64encode(codesign_env.to_json().encode()).decode(),
            "merkle": {
                "sequence":   seq,
                "leaf_hash":  leaf.hex(),
                "tree_size":  merkle_log.tree_size(self._db),
            },
        }
        return {
            "log_entry_id":       entry_id,
            "bundle":             base64.b64encode(json.dumps(bundle).encode()).decode(),
            "ephemeral_cert_pem": cert_pem,
            "signature":          base64.b64encode(signature).decode(),
        }

    def verify(self, artifact_digest: str) -> Dict[str, Any]:
        """
        Return all log entries for an artifact identified by its digest.

        artifact_digest: hex digest (any algorithm) — matched as substring
        of the stored artifact_digests JSON.
        """
        digest_lower = artifact_digest.lower()
        rows = self._db.fetchall(
            "SELECT * FROM codesign_log_entries "
            "WHERE artifact_digests LIKE ? ORDER BY logged_at",
            (f"%{digest_lower}%",),
        )
        if not rows:
            return {"found": False, "log_entries": []}
        entries = []
        for row in rows:
            proof = merkle_log.inclusion_proof(
                row["sequence"],
                merkle_log.tree_size(self._db),
                self._db,
            )
            entries.append({
                "id":                row["id"],
                "sequence":          row["sequence"],
                "logged_at":         row["logged_at"],
                "signing_identity":  row["signing_identity"],
                "issuer":            row["issuer"],
                "ephemeral_cert_pem":row["ephemeral_cert_pem"],
                "signature":         base64.b64encode(bytes(row["signature"])).decode(),
                "artifact_digests":  json.loads(row["artifact_digests"] or "[]"),
                "attestation_chain": json.loads(row["attestation_chain"] or "[]"),
                "policy_decisions":  json.loads(row["policy_decisions"] or "[]"),
                "inclusion_proof":   [h.hex() for h in proof],
            })
        return {"found": True, "log_entries": entries}

    def get_entry(self, entry_id: str) -> Optional[Dict]:
        """Return a single log entry by ID."""
        row = self._db.fetchone(
            "SELECT * FROM codesign_log_entries WHERE id = ?", (entry_id,)
        )
        if row is None:
            return None
        return {
            "id":                row["id"],
            "sequence":          row["sequence"],
            "logged_at":         row["logged_at"],
            "signing_identity":  row["signing_identity"],
            "issuer":            row["issuer"],
            "ephemeral_cert_pem":row["ephemeral_cert_pem"],
            "signature":         base64.b64encode(bytes(row["signature"])).decode(),
            "artifact_digests":  json.loads(row["artifact_digests"] or "[]"),
        }

    def get_checkpoint(self) -> Dict:
        """Return the current signed tree head."""
        sz   = merkle_log.tree_size(self._db)
        r    = merkle_log.root_hash(self._db)
        row  = self._db.fetchone(
            "SELECT * FROM codesign_checkpoints ORDER BY tree_size DESC LIMIT 1"
        )
        return {
            "tree_size":  sz,
            "root_hash":  r.hex(),
            "checkpoint": dict(row) if row else None,
        }

    def search(
        self,
        artifact_digest: Optional[str] = None,
        identity: Optional[str] = None,
    ) -> List[Dict]:
        """Search log entries by artifact digest and/or identity."""
        conds: list = []
        params: list = []
        if artifact_digest:
            conds.append("artifact_digests LIKE ?")
            params.append(f"%{artifact_digest.lower()}%")
        if identity:
            conds.append("signing_identity LIKE ?")
            params.append(f"%{identity}%")
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = self._db.fetchall(
            f"SELECT id, sequence, logged_at, signing_identity, issuer, artifact_digests "
            f"FROM codesign_log_entries {where} ORDER BY logged_at DESC LIMIT 100",
            tuple(params),
        )
        return [dict(r) for r in rows]
