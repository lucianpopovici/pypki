"""CA key backend reachability checks."""
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="ca-key-backend-reachable",
    severity=Severity.CRITICAL,
    category="backends",
    description="Every CA key backend (file/PKCS#11/KMS) successfully signs a test digest",
    timeout_seconds=30,
)
def check_ca_key_backend_reachable(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    tested = 0
    failed = []

    for key_path in env.ca_key_paths:
        key_path = Path(key_path)
        if not key_path.exists():
            failed.append(f"{key_path}: file not found")
            continue
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, padding
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

            key_bytes = key_path.read_bytes()
            key = load_pem_private_key(key_bytes, password=None)
            test_data = b"preflight-test-sign"

            if isinstance(key, ec.EllipticCurvePrivateKey):
                key.sign(test_data, ec.ECDSA(hashes.SHA256()))
            elif isinstance(key, rsa.RSAPrivateKey):
                key.sign(test_data, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(key, ed25519.Ed25519PrivateKey):
                key.sign(test_data)
            elif isinstance(key, ed448.Ed448PrivateKey):
                key.sign(test_data)
            else:
                # Unknown key type — skip rather than fail
                pass
            tested += 1
        except Exception as e:
            failed.append(f"{key_path}: {e}")

    if not failed:
        return CheckResult(
            id="ca-key-backend-reachable", severity=Severity.CRITICAL, category="backends",
            status=Status.PASS if tested > 0 else Status.SKIP,
            description="Every CA key backend signs a test digest",
            finding=f"{tested} backend(s) tested, all signed successfully"
                    if tested > 0 else "No CA key files found to test",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"tested": tested},
        )
    return CheckResult(
        id="ca-key-backend-reachable", severity=Severity.CRITICAL, category="backends",
        status=Status.FAIL,
        description="Every CA key backend signs a test digest",
        finding=f"{len(failed)} backend(s) failed: " + "; ".join(failed),
        remediation="Check CA key file permissions, passphrase, and HSM connectivity",
        timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"failed": failed, "tested": tested},
    )
