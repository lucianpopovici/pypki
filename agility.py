#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
agility.py -- Cryptographic Agility and PQ Migration Tracker

Classifier, aggregator, and forecaster for the /api/agility/* endpoints.
All queries run against the certificates table using the denormalized
crypto_class column populated at issuance time.
"""

from __future__ import annotations

import datetime
import logging
import threading
from typing import Optional

from cryptography import x509

log = logging.getLogger("agility")

# ---------------------------------------------------------------------------
# OID constants
# ---------------------------------------------------------------------------

_OID_ML_DSA: frozenset = frozenset({
    "2.16.840.1.101.3.4.3.17",
    "2.16.840.1.101.3.4.3.18",
    "2.16.840.1.101.3.4.3.19",
})

_OID_SLH_DSA: frozenset = frozenset({
    "2.16.840.1.101.3.4.3.20",
    "2.16.840.1.101.3.4.3.21",
    "2.16.840.1.101.3.4.3.22",
    "2.16.840.1.101.3.4.3.23",
    "2.16.840.1.101.3.4.3.24",
    "2.16.840.1.101.3.4.3.25",
    "2.16.840.1.101.3.4.3.26",
    "2.16.840.1.101.3.4.3.27",
    "2.16.840.1.101.3.4.3.28",
    "2.16.840.1.101.3.4.3.29",
    "2.16.840.1.101.3.4.3.30",
    "2.16.840.1.101.3.4.3.31",
})

_OID_COMPOSITE: frozenset = frozenset({
    "2.16.840.1.114027.80.8.1.13",
    "2.16.840.1.114027.80.8.1.16",
    "2.16.840.1.114027.80.8.1.21",
    "2.16.840.1.114027.80.8.1.27",
})

_OID_RSA   = "1.2.840.113549.1.1.1"
_OID_EC    = "1.2.840.10045.2.1"
_OID_EDDSA: frozenset = frozenset({"1.3.101.112", "1.3.101.113"})
_OID_RELATED_CERT = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.36")

CLASSES: tuple = (
    "classical-rsa",
    "classical-ec",
    "classical-eddsa",
    "hybrid-9763",
    "composite-mldsa",
    "mldsa-only",
    "slhdsa-only",
    "unknown",
)
PQ_CLASSES: frozenset = frozenset({
    "hybrid-9763", "composite-mldsa", "mldsa-only", "slhdsa-only"
})

DEFAULT_CAVEATS: list = [
    "Linear extrapolation; real adoption is typically S-shaped.",
    "Forecast assumes no policy intervention. Setting a PQ deadline policy will compress the timeline.",
]

# ---------------------------------------------------------------------------
# DER SPKI OID extraction
# ---------------------------------------------------------------------------

def _decode_oid_bytes(data: bytes) -> str:
    parts = [data[0] // 40, data[0] % 40]
    i, val = 1, 0
    while i < len(data):
        b = data[i]; i += 1
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _read_tlv(data: bytes, pos: int) -> tuple:
    tag = data[pos]; pos += 1
    b   = data[pos]; pos += 1
    if b & 0x80:
        n      = b & 0x7f
        length = int.from_bytes(data[pos:pos + n], "big")
        pos   += n
    else:
        length = b
    return tag, pos, length


def _spki_oid_from_der(der: bytes) -> str:
    try:
        _, pos, _ = _read_tlv(der, 0)
        _, pos, _ = _read_tlv(der, pos)
        if der[pos] == 0xa0:
            _, pos, l = _read_tlv(der, pos); pos += l
        _, pos, l = _read_tlv(der, pos); pos += l  # serial
        _, pos, l = _read_tlv(der, pos); pos += l  # signature
        _, pos, l = _read_tlv(der, pos); pos += l  # issuer
        _, pos, l = _read_tlv(der, pos); pos += l  # validity
        _, pos, l = _read_tlv(der, pos); pos += l  # subject
        _, pos, _ = _read_tlv(der, pos)            # SPKI SEQUENCE
        _, pos, _ = _read_tlv(der, pos)            # algorithm SEQUENCE
        tag, pos, oid_len = _read_tlv(der, pos)
        if tag != 0x06:
            return "unknown"
        return _decode_oid_bytes(der[pos:pos + oid_len])
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def classify_der(der: bytes) -> str:
    """
    Classify a DER-encoded X.509 certificate into one of the CLASSES values.
    Returns 'unknown' on parse error; never raises.
    """
    if not der:
        return "unknown"
    spki_oid = _spki_oid_from_der(der)
    if spki_oid in _OID_COMPOSITE:
        return "composite-mldsa"
    if spki_oid in _OID_ML_DSA:
        return "mldsa-only"
    if spki_oid in _OID_SLH_DSA:
        return "slhdsa-only"
    # Classical: check for RFC 9763 pairing via id-pe-relatedCert extension
    try:
        cert = x509.load_der_x509_certificate(der)
        cert.extensions.get_extension_for_oid(_OID_RELATED_CERT)
        return "hybrid-9763"
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    if spki_oid in _OID_EDDSA:
        return "classical-eddsa"
    if spki_oid == _OID_EC:
        return "classical-ec"
    if spki_oid == _OID_RSA:
        return "classical-rsa"
    return "unknown"


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def summary(db, tenant_id: Optional[str] = None) -> dict:
    now = _now_iso()
    where_tenant = "AND tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    rows = db.fetchall(
        "SELECT crypto_class, COUNT(*) AS n FROM certificates "
        "WHERE revoked = 0 AND not_after > ? " + where_tenant + " GROUP BY crypto_class",
        (now,) + params,
    )

    by_class: dict = {cls: 0 for cls in CLASSES}
    for row in rows:
        cls = row[0] or "unknown"
        by_class[cls] = by_class.get(cls, 0) + int(row[1])

    total    = sum(by_class.values())
    pq_total = sum(by_class.get(c, 0) for c in PQ_CLASSES)
    pq_pct   = round(pq_total / total * 100, 1) if total > 0 else 0.0

    by_class_out: dict = {}
    for cls, n in by_class.items():
        if n > 0 or cls in ("classical-rsa", "classical-ec"):
            by_class_out[cls] = {
                "count": n,
                "pct":   round(n / total * 100, 1) if total > 0 else 0.0,
            }

    backends: dict = {}
    try:
        brows = db.fetchall("SELECT backend, COUNT(*) FROM ca_keys GROUP BY backend")
        for br in brows:
            backends[str(br[0] or "file")] = int(br[1])
    except Exception:
        pass

    return {
        "as_of":              now,
        "total_active_certs": total,
        "by_class":           by_class_out,
        "pq_capable_pct":     pq_pct,
        "ca_key_backends":    backends,
    }


def breakdown(db, by: str = "profile", tenant_id: Optional[str] = None) -> dict:
    now = _now_iso()
    where_tenant = "AND tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    if by == "month":
        cutoff = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=730)
        ).isoformat()
        rows = db.fetchall(
            "SELECT substr(not_before,1,7) AS month, crypto_class, COUNT(*) AS n "
            "FROM certificates WHERE not_before > ? " + where_tenant +
            " GROUP BY month, crypto_class ORDER BY month",
            (cutoff,) + params,
        )
        groups: dict = {}
        for row in rows:
            mo  = row[0]; cls = row[1] or "unknown"; n = int(row[2])
            groups.setdefault(mo, {})[cls] = groups.get(mo, {}).get(cls, 0) + n
        return {"groups": [
            {"key": mo, "total": sum(c.values()), "by_class": c}
            for mo, c in sorted(groups.items())
        ]}

    if by == "profile":
        rows = db.fetchall(
            "SELECT profile, crypto_class, COUNT(*) AS n FROM certificates "
            "WHERE revoked = 0 AND not_after > ? " + where_tenant +
            " GROUP BY profile, crypto_class",
            (now,) + params,
        )
        gp: dict = {}
        for row in rows:
            prof = row[0] or "default"; cls = row[1] or "unknown"; n = int(row[2])
            gp.setdefault(prof, {})[cls] = gp.get(prof, {}).get(cls, 0) + n

        def _pq_frac(c: dict) -> float:
            tot = sum(c.values())
            pq  = sum(c.get(x, 0) for x in PQ_CLASSES)
            return pq / tot if tot else 0.0

        return {"groups": [
            {"key": prof, "total": sum(c.values()), "by_class": c}
            for prof, c in sorted(gp.items(), key=lambda kv: _pq_frac(kv[1]))
        ]}

    # by == "ca" (single-CA architecture)
    rows = db.fetchall(
        "SELECT crypto_class, COUNT(*) AS n FROM certificates "
        "WHERE revoked = 0 AND not_after > ? " + where_tenant + " GROUP BY crypto_class",
        (now,) + params,
    )
    c: dict = {}
    for row in rows:
        c[row[0] or "unknown"] = int(row[1])
    return {"groups": [{"key": "root", "total": sum(c.values()), "by_class": c}]}


def csr_demand(db, window_days: int = 30, tenant_id: Optional[str] = None) -> dict:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=window_days)
    ).isoformat()
    where_tenant = "AND tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    rows = db.fetchall(
        "SELECT crypto_class, COUNT(*) AS n FROM certificates "
        "WHERE not_before > ? " + where_tenant + " GROUP BY crypto_class",
        (cutoff,) + params,
    )
    by_algo: dict = {}
    for row in rows:
        by_algo[row[0] or "unknown"] = int(row[1])

    return {
        "window":          str(window_days) + "d",
        "csrs_total":      sum(by_algo.values()),
        "by_issued_class": by_algo,
        "note": "Counts reflect issued certs only; policy-denied CSRs not separately tracked.",
    }


# ---------------------------------------------------------------------------
# Forecaster
# ---------------------------------------------------------------------------

def _least_squares(xs: list, ys: list) -> tuple:
    n = len(xs)
    if n < 2:
        return 0.0, ys[0] if ys else 0.0
    sx = sum(xs); sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return 0.0, sy / n
    slope     = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    return slope, intercept


def forecast(db, window_days: int = 180, tenant_id: Optional[str] = None) -> dict:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=window_days)
    ).isoformat()
    where_tenant = "AND tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    rows = db.fetchall(
        "SELECT substr(not_before,1,7) AS month, crypto_class, COUNT(*) AS n "
        "FROM certificates WHERE not_before > ? " + where_tenant +
        " GROUP BY month, crypto_class ORDER BY month",
        (cutoff,) + params,
    )

    monthly: dict = {}
    for row in rows:
        mo = row[0]; cls = row[1] or "unknown"; n = int(row[2])
        tot, pq = monthly.get(mo, (0, 0))
        monthly[mo] = (tot + n, pq + (n if cls in PQ_CLASSES else 0))

    months = sorted(monthly)
    if len(months) < 2:
        return {
            "model": "linear-extrapolation",
            "model_inputs": {"window_days": window_days, "data_points": len(months)},
            "milestones": [],
            "caveats": ["Insufficient data (need >= 2 months of issuance)."] + DEFAULT_CAVEATS,
        }

    xs = [float(i) for i in range(len(months))]
    ys = [
        monthly[mo][1] / monthly[mo][0] if monthly[mo][0] > 0 else 0.0
        for mo in months
    ]
    slope, intercept = _least_squares(xs, ys)

    total_issued     = sum(v[0] for v in monthly.values())
    pq_issued        = sum(v[1] for v in monthly.values())
    renewal_rate     = round(total_issued / max(window_days, 1), 1)
    pq_adoption_rate = round(pq_issued   / max(window_days, 1), 1)
    current_frac     = ys[-1]

    milestones: list = []
    for target in (50, 90, 99):
        target_frac = target / 100.0
        if target_frac <= current_frac:
            milestones.append({"target_pq_pct": target, "estimated_at": "already met"})
        elif slope <= 0:
            milestones.append({"target_pq_pct": target, "estimated_at": "no upward trend"})
        else:
            x_now       = float(len(months) - 1)
            x_target    = (target_frac - intercept) / slope
            delta_days  = (x_target - x_now) * 30.44
            eta = (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=delta_days)
            ).date()
            milestones.append({"target_pq_pct": target, "estimated_at": eta.isoformat()})

    return {
        "model": "linear-extrapolation",
        "model_inputs": {
            "window_days":              window_days,
            "renewal_rate_per_day":     renewal_rate,
            "pq_adoption_rate_per_day": pq_adoption_rate,
            "data_points":              len(months),
            "current_pq_pct":           round(current_frac * 100, 1),
        },
        "milestones": milestones,
        "caveats":    DEFAULT_CAVEATS,
    }


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

def agility_prometheus(db, prefix: str = "pypki") -> str:
    now   = _now_iso()
    lines: list = []

    try:
        rows = db.fetchall(
            "SELECT crypto_class, profile, COUNT(*) AS n FROM certificates "
            "WHERE revoked = 0 AND not_after > ? GROUP BY crypto_class, profile",
            (now,),
        )
        lines += [
            "# HELP " + prefix + "_certs_active_total Active (non-expired, non-revoked) certs.",
            "# TYPE " + prefix + "_certs_active_total gauge",
        ]
        for row in rows:
            cls  = str(row[0] or "unknown").replace('"', '\\"')
            prof = str(row[1] or "default").replace('"', '\\"')
            lines.append(prefix + '_certs_active_total{crypto_class="' + cls + '",profile="' + prof + '"} ' + str(row[2]))
    except Exception as exc:
        log.debug("agility_prometheus: active-certs failed: %s", exc)

    try:
        total_row = db.fetchone(
            "SELECT COUNT(*) FROM certificates WHERE revoked = 0 AND not_after > ?", (now,)
        )
        pq_row = db.fetchone(
            "SELECT COUNT(*) FROM certificates WHERE revoked = 0 AND not_after > ? "
            "AND crypto_class IN ('hybrid-9763','composite-mldsa','mldsa-only','slhdsa-only')",
            (now,),
        )
        total = int(total_row[0]) if total_row else 0
        pq    = int(pq_row[0])    if pq_row    else 0
        frac  = round(pq / total, 4) if total > 0 else 0.0
        lines += [
            "# HELP " + prefix + "_pq_migration_progress Fraction of active certs using PQ algorithms.",
            "# TYPE " + prefix + "_pq_migration_progress gauge",
            prefix + "_pq_migration_progress " + str(frac),
        ]
    except Exception as exc:
        log.debug("agility_prometheus: pq-progress failed: %s", exc)

    try:
        cutoff = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
        ).isoformat()
        rows = db.fetchall(
            "SELECT crypto_class, COUNT(*) AS n FROM certificates "
            "WHERE not_before > ? GROUP BY crypto_class",
            (cutoff,),
        )
        lines += [
            "# HELP " + prefix + "_certs_issued_30d Certs issued in last 30 days by crypto class.",
            "# TYPE " + prefix + "_certs_issued_30d gauge",
        ]
        for row in rows:
            cls = str(row[0] or "unknown").replace('"', '\\"')
            lines.append(prefix + '_certs_issued_30d{crypto_class="' + cls + '"} ' + str(row[1]))
    except Exception as exc:
        log.debug("agility_prometheus: 30d-issued failed: %s", exc)

    return "\n".join(lines) + ("\n" if lines else "")


# ---------------------------------------------------------------------------
# Background sweeper
# ---------------------------------------------------------------------------

class AgilitySweeper:
    """Pre-computes agility Prometheus metrics on a fixed interval."""

    def __init__(self, db, interval_seconds: int = 60, prefix: str = "pypki"):
        self._db       = db
        self._interval = interval_seconds
        self._prefix   = prefix
        self._cache    = ""
        self._lock     = threading.Lock()
        self._stop     = threading.Event()
        self._thread   = threading.Thread(
            target=self._run, daemon=True, name="agility-sweeper"
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def cached_prometheus(self) -> str:
        with self._lock:
            return self._cache

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                metrics = agility_prometheus(self._db, self._prefix)
                with self._lock:
                    self._cache = metrics
            except Exception as exc:
                log.debug("AgilitySweeper sweep failed: %s", exc)


# ---------------------------------------------------------------------------
# Backfill helper
# ---------------------------------------------------------------------------

def backfill(db, batch_size: int = 500) -> tuple:
    """
    Classify all certs with crypto_class = 'unknown' or NULL.
    Returns (updated, skipped) counts.
    """
    updated = skipped = 0
    while True:
        rows = db.fetchall(
            "SELECT serial, der FROM certificates "
            "WHERE crypto_class IS NULL OR crypto_class = 'unknown' LIMIT ?",
            (batch_size,),
        )
        if not rows:
            break
        for row in rows:
            serial = row[0]
            der    = bytes(row[1]) if row[1] else b""
            cls    = classify_der(der)
            if cls == "unknown":
                skipped += 1
            else:
                db.execute(
                    "UPDATE certificates SET crypto_class = ? WHERE serial = ?",
                    (cls, serial),
                )
                updated += 1
        if len(rows) < batch_size:
            break
    return updated, skipped
