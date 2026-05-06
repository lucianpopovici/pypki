#!/usr/bin/env python3
"""
Advanced PKI RFC Compliance Checker – Live Network & Extended Protocols
Modules:
- X.509 certificate checks (RFC 5280)
- CMPv2 & CMPv3 (RFC 4210 / RFC 8677)
- ACME (RFC 8555)
- SCEP (RFC 8894)
- EST (RFC 7030)
- OCSP (RFC 6960)
- IPSec certificates (RFC 4945 / RFC 7427)
"""

import os
import hashlib
import requests
import urllib3
from datetime import datetime, timedelta, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

CERT_FOLDER = "./ca"  # local PEM certificates
BASE_URL = "http://localhost:8080"  # single dispatcher port
# Per-service path-prefix endpoints (new single-port architecture)
LIVE_ENDPOINTS = {
    "CMP":   f"{BASE_URL}/cmp/health",
    "ACME":  f"{BASE_URL}/acme/directory",
    "EST":   f"{BASE_URL}/est",
    "SCEP":  f"{BASE_URL}/scep",
    "OCSP":  f"{BASE_URL}/ocsp",
    "IPsec": f"{BASE_URL}/ipsec/health",
}

# -----------------------------
# X.509 certificate checks
# -----------------------------
def is_cert_pem(cert_path):
    with open(cert_path, "rb") as f:
        return b"BEGIN CERTIFICATE" in f.read()

def load_cert(cert_path):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def check_cert(cert_path):
    cert = load_cert(cert_path)
    print(f"\nCertificate: {cert_path}")
    print(f"  Subject: {cert.subject.rfc4514_string()}")
    print(f"  Issuer: {cert.issuer.rfc4514_string()}")
    # BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
        print(f"  BasicConstraints: CA={bc.ca}, path_length={bc.path_length}")
    except x509.ExtensionNotFound:
        print("  WARNING: BasicConstraints missing")
    # KeyUsage
    try:
        ku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
        print(f"  KeyUsage: {ku}")
    except x509.ExtensionNotFound:
        print("  WARNING: KeyUsage missing")
    # SAN
    try:
        san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        print(f"  SAN: {san.get_values_for_type(x509.DNSName)}")
    except x509.ExtensionNotFound:
        print("  WARNING: SAN missing")
    # Validity
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        print("  WARNING: Certificate not yet valid")
    if cert.not_valid_after_utc < now:
        print("  WARNING: Certificate expired")

# -----------------------------
# OCSP checks (live)
# -----------------------------
def check_ocsp_live(cert, issuer_cert):
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [desc.access_location.value for desc in aia if desc.access_method._name == "ocsp"]
        for url in ocsp_urls:
            print(f"  Checking OCSP at {url} ...")
            # For demo: actual OCSP request requires asn1crypto or ocspbuilder
            print("  NOTE: OCSP request not implemented in this stub")
    except x509.ExtensionNotFound:
        print("  WARNING: No OCSP URLs found")

# -----------------------------
# CMP server live check
# -----------------------------
def check_cmp_live(health_url):
    """
    Check the CMP server by fetching its /health endpoint.
    Reports CA subject, serial, and whether TLS is active.
    """
    import json as _json
    print(f"\nChecking CMP server: {health_url}")
    code, eff_url = _check_url(health_url)
    if code != 200:
        return
    try:
        r = requests.get(eff_url, verify=False, timeout=5)
        data = _json.loads(r.text)
        tls = "yes" if eff_url.startswith("https://") else "no"
        print(f"  Status  : {data.get('status', '?')}")
        print(f"  CA      : {data.get('ca_subject', '?')}")
        print(f"  Serial  : {data.get('ca_serial', '?')}")
        print(f"  TLS     : {tls}")
    except Exception as e:
        print(f"  (could not parse health response: {e})")

# -----------------------------
# IPSec certificate checks
# -----------------------------
def check_ipsec_cert(cert_path):
    """
    IPSec certificate compliance (RFC 4945, RFC 7427)
    - KeyUsage: digitalSignature + keyEncipherment
    - EKU: ipsecIKE, ipsecEndSystem
    """
    cert = load_cert(cert_path)
    print(f"\nIPSec Certificate: {cert_path}")
    try:
        eku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
        print(f"  EKU: {eku}")
        ipsec_eku_oids = [
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.17"),  # ipsecIKE
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.18")   # ipsecEndSystem
        ]
        for oid in ipsec_eku_oids:
            if oid in eku:
                print(f"    Found required IPSec EKU: {oid.dotted_string}")
    except x509.ExtensionNotFound:
        print("  WARNING: EKU missing")

# -----------------------------
# Generic live endpoint check (with HTTP→HTTPS fallback)
# -----------------------------
def _check_url(url, path="", label=None, expect_200=True):
    """
    GET {url}{path}, retrying with HTTPS if a plain-HTTP connection is reset
    (which happens when the server runs in TLS mode).
    Returns (status_code_or_None, effective_url).
    """
    full = url.rstrip("/") + path
    for attempt_url in ([full, full.replace("http://", "https://", 1)]
                        if full.startswith("http://") else [full]):
        try:
            r = requests.get(attempt_url, verify=False, timeout=5)
            tag = label or attempt_url
            if r.status_code == 200:
                print(f"  OK ({attempt_url})")
            elif r.status_code == 401:
                print(f"  OK (running, requires authentication) — {attempt_url}")
            elif r.status_code == 400:
                print(f"  OK (running, requires proper request body) — {attempt_url}")
            elif r.status_code == 404:
                print(f"  NOT REGISTERED (service disabled or not started) — {attempt_url}")
            else:
                print(f"  WARNING: HTTP {r.status_code} — {attempt_url}")
            return r.status_code, attempt_url
        except requests.exceptions.ConnectionError as e:
            if "Connection reset" in str(e) or "ConnectionReset" in str(e):
                continue   # server may be TLS — retry with https
            print(f"  ERROR: {e}")
            return None, attempt_url
        except Exception as e:
            print(f"  ERROR: {e}")
            return None, attempt_url
    print(f"  ERROR: Could not connect (tried HTTP and HTTPS). Server running?")
    return None, full

# -----------------------------
# EST checks (live)
# -----------------------------
def check_est_live(url):
    """
    EST live fetch check (RFC 7030).
    url is the EST prefix (e.g. http://localhost:8080/est).
    The EST handler expects /.well-known/est/cacerts relative to the prefix.
    Auto-retries with HTTPS if a plain-HTTP connection is reset.
    """
    print(f"\nChecking EST endpoint: {url}")
    _check_url(url, "/.well-known/est/cacerts")

# -----------------------------
# Main
# -----------------------------
def main():
    # Local certificates
    for f in os.listdir(CERT_FOLDER):
        if f.endswith(".pem"):
            path = os.path.join(CERT_FOLDER, f)
            if not is_cert_pem(path):
                continue
            check_cert(path)
            check_ipsec_cert(path)
            # For OCSP demo, pass issuer certificate (placeholder)
            check_ocsp_live(load_cert(path), load_cert(path))

    # Live endpoint checks (single-port, path-prefix routing)
    check_cmp_live(LIVE_ENDPOINTS["CMP"])
    check_est_live(LIVE_ENDPOINTS["EST"])

if __name__ == "__main__":
    main()
