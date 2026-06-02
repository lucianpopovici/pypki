#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
in-toto DSSE (Dead Simple Signing Envelope) and SLSA statement handling.

Implements DSSE as specified at:
  https://github.com/secure-systems-lab/dsse/blob/master/envelope.md

and SLSA Provenance v1:
  https://slsa.dev/spec/v1.0/provenance

Stdlib + cryptography only; no in-toto pip package.
"""

import base64
import dataclasses
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("pypki.intoto")

# ---------------------------------------------------------------------------
# PAE — Pre-Authentication Encoding (DSSE §3.3)
# ---------------------------------------------------------------------------

DSSE_CONTENT_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """
    Compute the DSSE Pre-Authentication Encoding.

    PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body

    This is the canonical input to the signature over a DSSE envelope.
    """
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1"
        + b" " + str(len(pt)).encode() + b" " + pt
        + b" " + str(len(payload)).encode() + b" " + payload
    )


# ---------------------------------------------------------------------------
# DSSE Envelope
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class DSSESignature:
    keyid: str    # may be empty
    sig:   bytes  # raw signature bytes


@dataclasses.dataclass
class DSSEEnvelope:
    payload_type: str
    payload:      bytes          # decoded payload
    signatures:   List[DSSESignature]

    @property
    def pae_bytes(self) -> bytes:
        return pae(self.payload_type, self.payload)

    @property
    def payload_json(self) -> dict:
        return json.loads(self.payload)

    def to_dict(self) -> dict:
        return {
            "payloadType": self.payload_type,
            "payload":     base64.standard_b64encode(self.payload).decode(),
            "signatures":  [
                {"keyid": s.keyid, "sig": base64.standard_b64encode(s.sig).decode()}
                for s in self.signatures
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def parse_envelope(data: str | bytes) -> DSSEEnvelope:
    """Parse a DSSE envelope from JSON (string or bytes)."""
    if isinstance(data, (str, bytes)):
        doc = json.loads(data)
    else:
        doc = data

    payload_type = doc.get("payloadType", DSSE_CONTENT_TYPE)
    payload_b64  = doc.get("payload", "")
    try:
        payload = base64.standard_b64decode(payload_b64)
    except Exception as exc:
        raise ValueError(f"DSSE payload is not valid base64: {exc}") from exc

    sigs = []
    for s in doc.get("signatures", []):
        try:
            sig_bytes = base64.standard_b64decode(s.get("sig", ""))
        except Exception:
            sig_bytes = b""
        sigs.append(DSSESignature(keyid=s.get("keyid", ""), sig=sig_bytes))

    return DSSEEnvelope(payload_type=payload_type, payload=payload, signatures=sigs)


def verify_envelope(env: DSSEEnvelope, public_key) -> bool:
    """
    Verify that at least one signature in the envelope is valid for public_key.

    Supports ECDSA P-256/P-384 and Ed25519.
    Returns True if any signature verifies; False otherwise.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    msg = env.pae_bytes
    for sig in env.signatures:
        if not sig.sig:
            continue
        try:
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(sig.sig, msg, ec.ECDSA(hashes.SHA256()))
                return True
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(sig.sig, msg)
                return True
        except InvalidSignature:
            continue
        except Exception as exc:
            log.debug("DSSE signature check error: %s", exc)
            continue
    return False


def sign_envelope(payload_type: str, payload: bytes, private_key) -> DSSEEnvelope:
    """Create a signed DSSE envelope."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    msg = pae(payload_type, payload)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        sig_bytes = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    else:
        sig_bytes = private_key.sign(msg)

    return DSSEEnvelope(
        payload_type=payload_type,
        payload=payload,
        signatures=[DSSESignature(keyid="", sig=sig_bytes)],
    )


def envelope_hash(env: DSSEEnvelope) -> str:
    """Return SHA-256 hex of the canonical JSON of the envelope."""
    return hashlib.sha256(env.to_json().encode()).hexdigest()


# ---------------------------------------------------------------------------
# SLSA Provenance v1 decoder
# ---------------------------------------------------------------------------

SLSA_PROVENANCE_V1_TYPE = "https://slsa.dev/provenance/v1"
STATEMENT_TYPE           = "https://in-toto.io/Statement/v1"


@dataclasses.dataclass
class SLSAStatement:
    predicate_type: str
    subjects:       List[Dict[str, Any]]   # [{name, digest: {sha256: ...}}, ...]
    builder_id:     str   = ""
    build_type:     str   = ""
    source_uri:     str   = ""
    source_ref:     str   = ""
    materials:      List[Dict] = dataclasses.field(default_factory=list)
    raw:            dict  = dataclasses.field(default_factory=dict)


def parse_slsa_statement(payload: bytes) -> SLSAStatement:
    """
    Parse an in-toto statement JSON payload.

    Handles SLSA Provenance v1 and gracefully extracts what it can from
    other predicate types (e.g. SLSA v0.2, SBOM, VSA).
    """
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Statement is not valid JSON: {exc}") from exc

    predicate_type = doc.get("predicateType", "")
    subjects = doc.get("subject", [])
    predicate = doc.get("predicate", {})

    builder_id  = ""
    build_type  = ""
    source_uri  = ""
    source_ref  = ""
    materials: list = []

    if predicate_type == SLSA_PROVENANCE_V1_TYPE:
        # SLSA Provenance v1
        builder_id = (predicate.get("builder") or {}).get("id", "")
        build_type = predicate.get("buildType", "")
        inv_cfg    = (predicate.get("invocation") or {}).get("configSource", {})
        source_uri = inv_cfg.get("uri", "")
        source_ref = inv_cfg.get("ref", "")
        materials  = predicate.get("materials", [])
    elif "builder" in predicate:
        # SLSA Provenance v0.2 / similar
        builder_id = (predicate.get("builder") or {}).get("id", "")
        build_type = predicate.get("buildType", "")
        recipe     = predicate.get("recipe", {})
        source_uri = recipe.get("entryPoint", "")
        materials  = predicate.get("materials", [])

    return SLSAStatement(
        predicate_type=predicate_type,
        subjects=subjects,
        builder_id=builder_id,
        build_type=build_type,
        source_uri=source_uri,
        source_ref=source_ref,
        materials=materials,
        raw=doc,
    )


def extract_artifact_digests(stmt: SLSAStatement) -> Dict[str, str]:
    """Return a flat {alg: hex} dict from the statement's subject digests."""
    result = {}
    for subj in stmt.subjects:
        for alg, val in (subj.get("digest") or {}).items():
            result[alg.lower()] = val.lower()
    return result
