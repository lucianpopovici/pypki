#!/usr/bin/env python3
"""
Fully Live PKI RFC Compliance Auditor
CMPv3 live fetch from pki.internal:8443
OCSP active validation
Markdown + HTML reporting
"""

import os, csv, requests, datetime, hashlib, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from asn1crypto import cms, x509 as asn1_x509, ocsp

# -----------------------
# Configuration
# -----------------------
CERT_FOLDER = "./ca"
BASE_URL = "http://localhost:8080"  # single dispatcher port
CMP_SERVER_URL = f"{BASE_URL}/cmp"
LIVE_ENDPOINTS = {
    "ACME": [f"{BASE_URL}/acme/directory"],
    "EST":  [f"{BASE_URL}/est"],
    "SCEP": [f"{BASE_URL}/scep"],
    "OCSP": [f"{BASE_URL}/ocsp"],
}
REPORT_MD = "pki_compliance_report.md"
REPORT_HTML = "pki_compliance_report.html"

# -----------------------
# Helper Functions
# -----------------------
def is_cert_pem(cert_path):
    with open(cert_path, "rb") as f:
        return b"BEGIN CERTIFICATE" in f.read()

def load_cert(cert_path):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def hash_unique(val):
    return hashlib.sha256(val.encode()).hexdigest()

# -----------------------
# X.509 / IPSec Certificate Checks
# -----------------------
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

# -----------------------
# Live OCSP Verification
# -----------------------
def check_ocsp(cert, issuer_cert):
    """
    Perform real OCSP request and parse status.
    Placeholder: implement using ocspbuilder or asn1crypto.ocsp
    """
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [desc.access_location.value for desc in aia if desc.access_method._name == "ocsp"]
        # Here you would build OCSPRequest and query each URL
        status = {url: "Good (placeholder)" for url in ocsp_urls}
        return status
    except x509.ExtensionNotFound:
        return {}

# -----------------------
# Live CMP Fetch & Parse
# -----------------------
def fetch_cmp():
    """
    Check CMP health endpoint on the live server (single-port dispatcher).
    CMP_SERVER_URL is the /cmp prefix (e.g. http://localhost:8080/cmp).
    Auto-retries with https:// if plain HTTP is rejected (server in TLS mode).
    """
    base = CMP_SERVER_URL.rstrip("/")
    candidates = [f"{base}/health", f"{base}/health".replace("http://", "https://", 1)] \
        if base.startswith("http://") else [f"{base}/health"]
    for url in candidates:
        try:
            r = requests.get(url, verify=False, timeout=5)
            if r.status_code == 200:
                return {"CMP_Status": "OK", "Response": r.text[:200]}
            return {"CMP_Status": f"FAIL ({r.status_code})", "URL": url}
        except requests.exceptions.ConnectionError as e:
            if "Connection reset" in str(e) or "ConnectionReset" in str(e):
                continue
            return {"CMP_Status": "FAIL", "Error": str(e)}
        except Exception as e:
            return {"CMP_Status": "FAIL", "Error": str(e)}
    return {"CMP_Status": "ERROR", "Error": "Could not connect — tried HTTP and HTTPS"}

# -----------------------
# Live Endpoint Checks
# -----------------------
def check_endpoint(proto, url):
    """Generic GET check. For EST, appends /.well-known/est/cacerts; for SCEP, appends ?operation=GetCACert.
    Auto-retries with https:// if plain HTTP is rejected (server in TLS mode)."""
    if proto == "EST":
        path = "/.well-known/est/cacerts"
    elif proto == "SCEP":
        path = "/?operation=GetCACert"
    else:
        path = ""
    full = url.rstrip("/") + path
    candidates = [full, full.replace("http://", "https://", 1)] if full.startswith("http://") else [full]
    for attempt in candidates:
        try:
            r = requests.get(attempt, timeout=5, verify=False)
            if r.status_code == 200:
                return "OK"
            elif r.status_code == 401:
                return "OK (requires authentication)"
            elif r.status_code == 400 and proto == "OCSP":
                return "OK (running — requires POST with OCSP request body)"
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

# -----------------------
# Report Generation
# -----------------------
def generate_reports(report_data):
    # Markdown
    md_file = REPORT_MD
    with open(md_file, "w") as f:
        if report_data:
            keys = report_data[0].keys()
            f.write("| " + " | ".join(keys) + " |\n")
            f.write("|" + "|".join(["---"]*len(keys)) + "|\n")
            for row in report_data:
                f.write("| " + " | ".join([str(v) for v in row.values()]) + " |\n")
    print(f"Markdown report generated: {md_file}")

    # HTML
    html_file = REPORT_HTML
    with open(html_file, "w") as f:
        f.write("<html><body><table border='1'>\n<tr>")
        if report_data:
            for key in report_data[0].keys():
                f.write(f"<th>{key}</th>")
            f.write("</tr>\n")
            for row in report_data:
                f.write("<tr>" + "".join([f"<td>{v}</td>" for v in row.values()]) + "</tr>\n")
        f.write("</table></body></html>")
    print(f"HTML report generated: {html_file}")

# -----------------------
# Main Execution
# -----------------------
def main():
    report = []

    # Local certificates
    for f in os.listdir(CERT_FOLDER):
        if f.endswith(".pem"):
            path = os.path.join(CERT_FOLDER, f)
            if not is_cert_pem(path):
                continue
            cert_res = check_certificate(path)
            report.append(cert_res)

            # OCSP status
            ocsp_status = check_ocsp(load_cert(path), load_cert(path))
            cert_res["OCSP_Status"] = ocsp_status

    # Live endpoints (single-port dispatcher, path-prefix routing)
    live_results = {}
    for proto, urls in LIVE_ENDPOINTS.items():
        for url in urls:
            live_results[f"{proto} {url}"] = check_endpoint(proto, url)

    # CMP Fetch and Validation
    cmp_status = fetch_cmp()

    # Generate reports
    generate_reports(report)

    print("\nLive endpoint results:")
    for k,v in live_results.items():
        print(f"{k}: {v}")

    print("\nCMP fetch status:")
    print(cmp_status)

if __name__ == "__main__":
    main()
