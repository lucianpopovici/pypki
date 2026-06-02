# PyPKI Integrations

<!-- Last reviewed: 2026-06-02 -->

## Terraform

A Terraform provider (`terraform-provider-pypki`) wraps the PyPKI REST API
so infrastructure-as-code teams can manage certificates, sub-CAs, and ACME
accounts declaratively.

### Provider setup

```hcl
terraform {
  required_providers {
    pypki = {
      source  = "lucianpopovici/pypki"
      version = "~> 0.1"
    }
  }
}

provider "pypki" {
  endpoint  = "https://pki.example.com"
  api_token = var.pypki_token      # or env PYPKI_API_TOKEN
  ca_bundle = file("./ca-bundle.pem")
}
```

Create a long-lived service-account token:

```bash
pypki_admin token-create --identity terraform-ci --role pki:operator --ttl 365
```

### Key resources

```hcl
# End-entity certificate (CSR mode — private key never leaves Terraform)
resource "tls_private_key" "web" {
  algorithm = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "web" {
  private_key_pem = tls_private_key.web.private_key_pem
  subject { common_name = "web01.example.com" }
  dns_names = ["web01.example.com"]
}

resource "pypki_certificate" "web" {
  profile  = "tls_server"
  csr_pem  = tls_cert_request.web.cert_request_pem
  early_renewal_hours = 720
}

output "cert_pem" { value = pypki_certificate.web.cert_pem }
```

```hcl
# Sub-CA for a team
resource "pypki_sub_ca" "team_a" {
  parent_ca    = "root-2026"
  common_name  = "Team A Intermediate"
  validity_days = 3650
  path_length  = 0
  permitted_dns_domains = ["a.internal.example.com"]
}
```

```hcl
# ACME account + cert-manager ClusterIssuer bootstrap
resource "pypki_acme_account" "ci" {
  contact_email = "ci@example.com"
  external_account_binding {
    key_id   = var.eab_key_id
    hmac_key = var.eab_hmac_key
  }
}
```

### REST API contract

The provider consumes the versioned REST API at `/api/v1/`. All endpoints are
documented in `docs/openapi.json` (served at `GET /api/openapi.json`).

```bash
# Export current spec
pypki_admin openapi-export --pretty > openapi.json

# Check for handler/spec drift
pypki_admin openapi-export --check-drift
```

Key endpoints the provider depends on:

| Endpoint | Operation |
|---|---|
| `GET /api/v1/health` | Connectivity check |
| `GET /api/v1/version` | Version negotiation |
| `GET /api/v1/certs/{serial}` | Read cert state |
| `POST /api/v1/issue` | Create cert (CSR or subject string) |
| `POST /api/v1/revoke` | Delete cert (cessation_of_operation) |
| `POST /api/v1/issue-sub-ca` | Create sub-CA |
| `GET /api/v1/openapi.json` | Provider regenerates client from this |

The `/api/` prefix (without `v1/`) is an alias for backward compatibility.

---

## cert-manager (Kubernetes)

PyPKI exposes ACME, EST, and CMP endpoints that cert-manager can consume:

**ACME (recommended)**:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: pypki-acme
spec:
  acme:
    server: https://pki.example.com/acme/directory
    email: admin@example.com
    externalAccountBinding:
      keyID: <from pypki_admin acme-eab-mint>
      keySecretRef:
        name: pypki-eab-secret
        key: hmac
    privateKeySecretRef:
      name: pypki-acme-key
    solvers:
    - http01:
        ingress:
          class: nginx
```

**EST (for mTLS-heavy clusters)**:
EST endpoints at `https://pki.example.com/est/.well-known/est/`. Use an
`external-cert-manager-issuer` that speaks EST.

---

## HashiCorp Vault PKI secrets engine

If your team already runs Vault, you can use PyPKI as an upstream CA and
have Vault issue short-lived leaf certs using the Vault PKI engine. Import
PyPKI's intermediate CA cert into Vault's intermediate CA slot.

```bash
# Generate a Vault-bound intermediate using PyPKI
curl -X POST https://pki.example.com/api/issue-sub-ca \
  -H "Authorization: Bearer $PYPKI_TOKEN" \
  -d '{"cn": "Vault Intermediate", "validity_days": 3650}' \
  | jq -r '.cert_pem' > vault-intermediate.pem

# Set the signed certificate in Vault
vault write pki/intermediate/set-signed certificate=@vault-intermediate.pem
```

---

## Prometheus + Grafana

Scrape `GET /api/metrics` (Prometheus exposition format). Import the bundled
dashboard from `dashboards/pypki-agility.json`.

Alerting rules are documented in `docs/HOWTO/README.md`.

---

## WireGuard (pull-mode sync)

Use `tools/pypki-wg-sync/sync.py` on each WireGuard server. See `docs/WIREGUARD.md`.

---

## Matter manufacturing

REST API at `/api/matter/dac`, `/api/matter/dac/bulk`. Admin CLI:
`pypki_admin matter-dac-bulk-issue`. See `docs/MATTER.md`.
