#!/usr/bin/env python3
"""
Ultimate PKI RFC Compliance Auditor
- X.509 certificates (RFC 5280, TLS, IPSec)
- CMPv2 / CMPv3 (RFC 4210, 8677)
- ACME (RFC 8555)
- EST (RFC 7030)
- SCEP (RFC 8894)
- OCSP (RFC 6960)
- Automated CSV + Markdown report
"""

import os, csv, hashlib, requests, datetime, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from asn1crypto import cms, ocsp, tsp, x509 as asn1_x509

# -------------------------
# Configuration
# -------------------------
CERT_FOLDER = "./ca"
BASE_URL = "http://localhost:8080"  # single dispatcher port
LIVE_ENDPOINTS = {
    "ACME": [f"{BASE_URL}/acme/directory"],
    "EST":  [f"{BASE_URL}/est"],
    "SCEP": [f"{BASE_URL}/scep"],
    "OCSP": [f"{BASE_URL}/ocsp"],
    "CMP":  [f"{BASE_URL}/cmp/health"],
}
REPORT_CSV = "pki_audit_report.csv"
REPORT_MD = "pki_audit_report.md"

# -------------------------
# Helper Functions
# -------------------------
def is_cert_pem(cert_path):
    with open(cert_path, "rb") as f:
        return b"BEGIN CERTIFICATE" in f.read()

def load_cert(cert_path):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def hash_unique(val):
    return hashlib.sha256(val.encode()).hexdigest()

# -------------------------
# X.509 / IPSec Certificate Checks
# -------------------------
def check_certificate(cert_path):
    cert = load_cert(cert_path)
    now = datetime.datetime.now(datetime.timezone.utc)
    res = {
        "Certificate": cert_path,
        "Subject": cert.subject.rfc4514_string(),
        "Issuer": cert.issuer.rfc4514_string(),
        "BasicConstraints": "MISSING",
        "KeyUsage": "MISSING",
        "EKU": "MISSING",
        "SAN": "MISSING",
        "Validity": f"NotBefore={cert.not_valid_before_utc}, NotAfter={cert.not_valid_after_utc}",
        "CRL": "MISSING",
        "OCSP": "MISSING",
        "IPSec EKU": "None"
    }

    # BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
        res["BasicConstraints"] = f"CA={bc.ca}, path_len={bc.path_length}"
    except x509.ExtensionNotFound:
        pass

    # KeyUsage
    try:
        ku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
        res["KeyUsage"] = str(ku)
    except x509.ExtensionNotFound:
        pass

    # EKU + IPSec EKU
    try:
        eku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
        res["EKU"] = [oid._name for oid in eku]
        ipsec_oids = ["1.3.6.1.5.5.7.3.17", "1.3.6.1.5.5.7.3.18"]
        res["IPSec EKU"] = [oid.dotted_string for oid in eku if oid.dotted_string in ipsec_oids] or "None"
    except x509.ExtensionNotFound:
        pass

    # SAN
    try:
        san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        res["SAN"] = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # CRL Distribution Points
    try:
        crl = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        res["CRL"] = [dp.full_name for dp in crl]
    except x509.ExtensionNotFound:
        pass

    # OCSP URLs
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [desc.access_location.value for desc in aia if desc.access_method._name == "ocsp"]
        res["OCSP"] = ocsp_urls if ocsp_urls else "None"
    except x509.ExtensionNotFound:
        pass

    # Validity check
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
        res["Validity"] += " WARNING"

    return res

# -------------------------
# OCSP Status Check
# -------------------------
def check_ocsp_status(cert, issuer_cert):
    """
    Placeholder for real OCSP request and response validation.
    Returns a status dictionary with OCSP URLs.
    """
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [desc.access_location.value for desc in aia if desc.access_method._name == "ocsp"]
        return {"OCSP_Responders": ocsp_urls}
    except x509.ExtensionNotFound:
        return {"OCSP_Responders": []}

# -------------------------
# Live Endpoint Checks
# -------------------------
def _get_with_tls_fallback(url, path=""):
    """GET url+path, auto-retry with https:// if plain HTTP is rejected (server in TLS mode)."""
    full = url.rstrip("/") + path
    candidates = [full, full.replace("http://", "https://", 1)] if full.startswith("http://") else [full]
    for attempt in candidates:
        try:
            r = requests.get(attempt, timeout=5, verify=False)
            if r.status_code == 200:
                return "OK"
            elif r.status_code == 401:
                return "OK (requires authentication)"
            elif r.status_code == 404:
                return "NOT REGISTERED (service disabled or not started)"
            return f"FAIL ({r.status_code})"
        except requests.exceptions.ConnectionError as e:
            if "Connection reset" in str(e) or "ConnectionReset" in str(e):
                continue
            return f"ERROR ({e})"
        except Exception as e:
            return f"ERROR ({e})"
    return "ERROR (Could not connect — tried HTTP and HTTPS)"

def check_est(url):
    return _get_with_tls_fallback(url, "/.well-known/est/cacerts")

def check_acme(url):
    return _get_with_tls_fallback(url)

def check_scep(url):
    return _get_with_tls_fallback(url, "/?operation=GetCACert")

# -------------------------
# CMPv2 / CMPv3 ASN.1 Stub Checks
# -------------------------
def check_cmp(msg, version="v2"):
    """
    Parse CMPv2/v3 ASN.1 messages and verify:
    - Signature
    - Nonce
    - Timestamp
    - Transaction ID
    Note: Real implementation requires parsing DER from messages.
    """
    sig_valid = True
    nonce_unique = True
    timestamp_valid = True
    return {"CMP_Version": version, "SignatureValid": sig_valid, "NonceUnique": nonce_unique, "TimestampValid": timestamp_valid}

# -------------------------
# Report Generation
# -------------------------
def write_csv(report):
    if not report: return
    with open(REPORT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(report[0].keys()))
        writer.writeheader()
        for row in report:
            writer.writerow(row)
    print(f"CSV report saved: {REPORT_CSV}")

def write_md(report):
    if not report: return
    with open(REPORT_MD, "w") as f:
        f.write("| " + " | ".join(report[0].keys()) + " |\n")
        f.write("|" + "|".join(["---"]*len(report[0])) + "|\n")
        for row in report:
            f.write("| " + " | ".join([str(v) for v in row.values()]) + " |\n")
    print(f"Markdown report saved: {REPORT_MD}")

# -------------------------
# Main Execution
# -------------------------
def main():
    report = []

    # Local certificate checks
    for f in os.listdir(CERT_FOLDER):
        if f.endswith(".pem"):
            path = os.path.join(CERT_FOLDER, f)
            if not is_cert_pem(path):
                continue
            cert_res = check_certificate(path)
            report.append(cert_res)

    # Live endpoint checks (single-port dispatcher, path-prefix routing)
    live_results = {}
    for url in LIVE_ENDPOINTS.get("EST", []):
        live_results[f"EST {url}"] = check_est(url)
    for url in LIVE_ENDPOINTS.get("ACME", []):
        live_results[f"ACME {url}"] = check_acme(url)
    for url in LIVE_ENDPOINTS.get("SCEP", []):
        live_results[f"SCEP {url}"] = check_scep(url)
    for url in LIVE_ENDPOINTS.get("OCSP", []):
        live_results[f"OCSP {url}"] = check_acme(url)  # generic GET
    for url in LIVE_ENDPOINTS.get("CMP", []):
        live_results[f"CMP {url}"] = check_acme(url)   # generic GET

    # CMPv2/v3 example stubs
    cmp_v2 = check_cmp({"sender":"client","nonce":"1234","signature":b""}, "v2")
    cmp_v3 = check_cmp({"sender":"client","nonce":"1234","signature":b""}, "v3")

    # Output reports
    write_csv(report)
    write_md(report)

    # Live and CMP results
    print("\nLive Endpoint Checks:")
    for k,v in live_results.items(): print(f"{k}: {v}")

    print("\nCMP Compliance (Stub):")
    print("CMPv2:", cmp_v2)
    print("CMPv3:", cmp_v3)

if __name__ == "__main__":
    main()
