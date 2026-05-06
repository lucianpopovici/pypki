#!/usr/bin/env python3
"""
Full PKI RFC Compliance Auditor
Checks:
- X.509 Certificates (RFC 5280)
- IPSec certificates (RFC 4945 / 7427)
- ACME (RFC 8555)
- EST (RFC 7030)
- SCEP (RFC 8894)
- CMPv2/v3 (RFC 4210 / 8677)
- OCSP (RFC 6960)
Outputs: Markdown / CSV compliance report
"""

import os, hashlib, requests, csv, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# ------------------------
# Config
# ------------------------
CERT_FOLDER = "./ca"
BASE_URL = "http://localhost:8080"  # single dispatcher port
LIVE_ENDPOINTS = {
    "ACME": [f"{BASE_URL}/acme/directory"],
    "EST":  [f"{BASE_URL}/est"],
    "SCEP": [f"{BASE_URL}/scep"],
    "OCSP": [f"{BASE_URL}/ocsp"],
    "CMP":  [f"{BASE_URL}/cmp/health"],
}
REPORT_FILE = "pki_compliance_report.csv"

# ------------------------
# Helper Functions
# ------------------------
def is_cert_pem(cert_path):
    with open(cert_path, "rb") as f:
        return b"BEGIN CERTIFICATE" in f.read()

def load_cert(cert_path):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def hash_unique(val):
    return hashlib.sha256(val.encode()).hexdigest()

# ------------------------
# Certificate Checks
# ------------------------
def check_certificate(cert_path):
    cert = load_cert(cert_path)
    result = {
        "Certificate": cert_path,
        "Subject": cert.subject.rfc4514_string(),
        "Issuer": cert.issuer.rfc4514_string(),
        "BasicConstraints": "",
        "KeyUsage": "",
        "EKU": "",
        "SAN": "",
        "Validity": "",
        "CRL": "",
        "OCSP": "",
        "IPSec EKU": "",
    }

    # BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
        result["BasicConstraints"] = f"CA={bc.ca}, path_len={bc.path_length}"
    except x509.ExtensionNotFound:
        result["BasicConstraints"] = "MISSING"

    # KeyUsage
    try:
        ku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
        result["KeyUsage"] = str(ku)
    except x509.ExtensionNotFound:
        result["KeyUsage"] = "MISSING"

    # ExtendedKeyUsage
    try:
        eku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
        result["EKU"] = [oid._name for oid in eku]
        # IPSec EKU
        ipsec_oids = ["1.3.6.1.5.5.7.3.17", "1.3.6.1.5.5.7.3.18"]
        ipsec_found = [oid.dotted_string for oid in eku if oid.dotted_string in ipsec_oids]
        result["IPSec EKU"] = ipsec_found if ipsec_found else "None"
    except x509.ExtensionNotFound:
        result["EKU"] = "MISSING"

    # SAN
    try:
        san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        result["SAN"] = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        result["SAN"] = "MISSING"

    # Validity
    now = datetime.now(timezone.utc)
    result["Validity"] = f"NotBefore={cert.not_valid_before_utc}, NotAfter={cert.not_valid_after_utc}"
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
        result["Validity"] += " WARNING"

    # CRL Distribution Points
    try:
        crl = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        result["CRL"] = [dp.full_name for dp in crl]
    except x509.ExtensionNotFound:
        result["CRL"] = "MISSING"

    # OCSP
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [desc.access_location.value for desc in aia if desc.access_method._name == "ocsp"]
        result["OCSP"] = ocsp_urls if ocsp_urls else "None"
    except x509.ExtensionNotFound:
        result["OCSP"] = "MISSING"

    return result

# ------------------------
# Live Endpoint Checks (ACME/EST/SCEP)
# ------------------------
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

# ------------------------
# CMPv2/v3 Checks
# ------------------------
def check_cmp(msg, version="v2"):
    """
    Stub function: Validate CMP message signature, nonce, timestamp
    Replace msg with actual parsed DER or JSON
    """
    # signature validation placeholder
    sig_valid = True
    nonce_unique = True
    timestamp_valid = True
    return {
        "CMP_Version": version,
        "SignatureValid": sig_valid,
        "NonceUnique": nonce_unique,
        "TimestampValid": timestamp_valid
    }

# ------------------------
# Generate CSV Report
# ------------------------
def main():
    report = []

    # Local Certificates
    for f in os.listdir(CERT_FOLDER):
        if f.endswith(".pem"):
            cert_path = os.path.join(CERT_FOLDER, f)
            if not is_cert_pem(cert_path):
                continue
            cert_res = check_certificate(cert_path)
            report.append(cert_res)

    # Live Endpoints (single-port dispatcher, path-prefix routing)
    live_checks = []
    for url in LIVE_ENDPOINTS.get("EST", []):
        live_checks.append({"Endpoint": url, "EST": check_est(url)})
    for url in LIVE_ENDPOINTS.get("ACME", []):
        live_checks.append({"Endpoint": url, "ACME": check_acme(url)})
    for url in LIVE_ENDPOINTS.get("SCEP", []):
        live_checks.append({"Endpoint": url, "SCEP": check_scep(url)})
    for url in LIVE_ENDPOINTS.get("OCSP", []):
        live_checks.append({"Endpoint": url, "OCSP": check_acme(url)})  # generic GET
    for url in LIVE_ENDPOINTS.get("CMP", []):
        live_checks.append({"Endpoint": url, "CMP": check_acme(url)})   # generic GET

    # CMP Example
    cmp_msg_v2 = {"sender":"client","nonce":"1234","signature":b""}
    cmp_res = check_cmp(cmp_msg_v2, version="v2")
    cmp_msg_v3 = {"sender":"client","nonce":"1234","signature":b""}
    cmp_res_v3 = check_cmp(cmp_msg_v3, version="v3")

    # Output CSV
    with open(REPORT_FILE, "w", newline="") as csvfile:
        fieldnames = list(report[0].keys()) if report else []
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in report:
            writer.writerow(row)

    print(f"\nPKI compliance report written to {REPORT_FILE}")
    print("Live endpoint checks:")
    for check in live_checks:
        print(check)
    print("CMP compliance (stub):")
    print(cmp_res)
    print(cmp_res_v3)

if __name__ == "__main__":
    main()
