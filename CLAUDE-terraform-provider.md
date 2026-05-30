# CLAUDE-terraform-provider.md — Terraform Provider for PyPKI

Companion to `CLAUDE.md`. This spec is **a separate repo, written in Go**
(`terraform-provider-pypki`), not part of the Python codebase. Including
the spec here so future Claude instances understand the shape and can
keep the REST API surface stable enough for Terraform to consume.

Provider lifecycle is decoupled from PyPKI releases; the API contract
between them is the only thing that needs joint review.

---

## What this is

Infrastructure-as-code is table stakes for enterprise PKI adoption.
`cert-manager` covers Kubernetes. Terraform covers everything else:
VMs, load balancers (F5, NetScaler), bare-metal hosts, network devices,
non-K8s container hosts. Without a provider, ops teams write bespoke
glue against the REST API — exactly the work a provider exists to
eliminate.

The provider is a thin idempotent wrapper over PyPKI's REST API. It
doesn't implement business logic; it tracks state in Terraform's
state file and reconciles to match declared resources.

---

## Repository layout

Separate repo: `github.com/lucianpopovici/terraform-provider-pypki`.
Following the modern Terraform Plugin Framework (not the legacy SDK
v2 — Plugin Framework is the only supported path for new providers
as of HashiCorp's roadmap from 2023 onwards).

```
terraform-provider-pypki/
├── go.mod
├── main.go                                  # provider entrypoint
├── internal/
│   ├── provider/
│   │   ├── provider.go                      # provider config
│   │   ├── certificate_resource.go
│   │   ├── sub_ca_resource.go
│   │   ├── acme_account_resource.go
│   │   ├── policy_data_source.go
│   │   ├── ca_chain_data_source.go
│   │   └── client.go                        # PyPKI REST client
│   └── client/
│       └── pypki/                           # generated from OpenAPI spec
├── examples/
│   ├── homelab/
│   ├── enterprise-mtls/
│   └── kubernetes-bootstrap/
├── docs/                                    # markdown docs published to registry
└── .github/workflows/                       # build, test, release
```

Releases go to the Terraform Registry under the Hashicorp signing
process (GPG key managed in this org's keybase or 1Password vault).

---

## Provider configuration

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
  endpoint    = "https://pki.example.com"
  api_token   = var.pypki_token       # or PYPKI_API_TOKEN env
  ca_bundle   = file("./pypki-ca-bundle.pem")  # trust PyPKI's TLS cert
  default_ca  = "intermediate-internal"
}
```

`api_token` is the long-lived service-account token from
`pypki_admin.py token-create --role pki:operator`. The provider
authenticates exclusively with bearer tokens — never reuses an
operator's OIDC session.

---

## Resources

### `pypki_certificate`

```hcl
resource "pypki_certificate" "web_internal" {
  profile         = "tls_server"
  common_name     = "web01.internal.example.com"
  subject_alternative_names = [
    "web01.internal.example.com",
    "web01",
  ]
  key_algorithm   = "ecdsa"
  key_curve       = "P-256"
  validity_days   = 90
  ca              = "intermediate-internal"

  early_renewal_hours = 720      # renew 30d before expiry
}
```

Lifecycle:

- **Create**: POST to `/api/issue`, store the returned serial + DER in
  state.
- **Read**: GET `/api/certs/<serial>`; reconcile profile, validity,
  revocation state. If revoked externally, mark for replacement.
- **Update**: any change to subject, SANs, key algorithm, or profile
  triggers `ForceNew` (re-issue). Validity changes alone re-issue too;
  PyPKI doesn't support mutating issued certs.
- **Delete**: POST `/api/revoke` with reason `cessation_of_operation`.

The `early_renewal_hours` field hooks into Terraform's
`time_offset`-style rotation: when current time + offset > `not_after`,
the resource plans a replacement on next `terraform apply`. Same
pattern as the official `tls_self_signed_cert` resource.

Exports:

- `cert_pem` — leaf certificate in PEM
- `chain_pem` — issuer chain (intermediate + root)
- `fullchain_pem` — `cert_pem || chain_pem`
- `private_key_pem` — only if `pypki_certificate.generate_key = true`;
  otherwise the user provides a CSR via `csr_pem`
- `not_before`, `not_after`, `serial`, `sha256_fingerprint`

Private key handling has to be careful: Terraform state contains the
private key in plaintext when `generate_key = true`. Document this
loudly and recommend `csr_pem` for production use (CSR-based,
private key never leaves the requester).

### `pypki_sub_ca`

```hcl
resource "pypki_sub_ca" "team_a" {
  parent_ca       = "root-2026"
  common_name     = "Team A Intermediate"
  validity_days   = 3650
  path_length     = 0
  name_constraints {
    permitted_dns_domains = ["a.internal.example.com"]
  }
  key_algorithm   = "ecdsa"
  key_curve       = "P-384"
}
```

Operationally heavy: creating a sub-CA in production is a deliberate
human action. The Terraform resource exists for repeatable lab/dev
setup; require a `--auto-approve` plus an explicit `confirm_intent`
field set to a documented string to actually run in production
deployments.

### `pypki_acme_account`

```hcl
resource "pypki_acme_account" "ci" {
  contact_email   = "ci@example.com"
  external_account_binding {
    key_id    = var.eab_key_id
    hmac_key  = var.eab_hmac_key
  }
}
```

Useful for bootstrapping cert-manager `ClusterIssuer` resources whose
EAB credentials this resource creates. The output `account_url` plus
the input EAB values fully configures a cert-manager Issuer.

### `pypki_policy_attachment` (if policy engine ships)

```hcl
resource "pypki_policy_attachment" "main" {
  policy_file = file("${path.module}/policy.yaml")
}
```

Lifecycle: any change to the file's hash triggers an upload + reload.
Uses the `policy-validate` endpoint server-side to reject invalid
policies before they take effect. Pairs with `CLAUDE-policy-engine.md`.

---

## Data sources

```hcl
data "pypki_ca_chain" "internal" {
  ca = "intermediate-internal"
}

data "pypki_certificate" "existing" {
  serial = "0x1234..."
}

data "pypki_acme_directory" "endpoint" {}
```

Data sources are read-only and side-effect-free. Heavily used in
modules that just want the trust chain to drop into a TLS config.

---

## Required API surface from PyPKI

The provider depends on these REST endpoints being stable. Any breaking
change must rev the provider major version and be called out in
PyPKI's CHANGELOG.

| Endpoint                                  | Status   |
| ----------------------------------------- | -------- |
| `POST /api/issue`                         | Existing |
| `GET /api/certs/<serial>`                 | Existing |
| `POST /api/revoke`                        | Existing |
| `GET /api/ca-chain/<ca-name>`             | Existing |
| `POST /api/issue-sub-ca`                  | Existing |
| `GET /api/sub-cas`                        | Existing |
| `POST /api/acme-accounts` (with EAB)      | Existing |
| `GET /api/acme-accounts/<id>`             | Existing |
| `POST /api/policy/validate`               | New (paired with policy engine) |
| `PUT  /api/policy/current`                | New (paired with policy engine) |
| `GET /api/health` + `GET /api/version`    | Existing |
| `GET /api/openapi.json`                   | New — generated OpenAPI 3 spec  |

The `openapi.json` endpoint is the contract: the provider regenerates
its Go client from it on every release. PyPKI must produce this spec
in CI (`pypki_admin.py openapi-export`); drift between actual handlers
and the spec is a release blocker.

---

## Testing strategy

### Unit (in Go)

Mock the PyPKI HTTP client. Standard provider unit-test patterns:
ResourceData hydration, schema validation, diff suppression.

### Acceptance (in Go, against a real PyPKI)

Spin up PyPKI in a container (`pypki-test` image, SQLite, ephemeral
CA). Run the full Terraform plan/apply/destroy cycle for each resource.
Tests live in `internal/provider/*_acc_test.go` and run on every PR.

```go
func TestAccCertificateResource_basic(t *testing.T) {
    resource.Test(t, resource.TestCase{
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{{
            Config: testAccCertConfigBasic(),
            Check: resource.ComposeTestCheckFunc(
                resource.TestCheckResourceAttrSet("pypki_certificate.test", "cert_pem"),
                resource.TestCheckResourceAttrSet("pypki_certificate.test", "serial"),
            ),
        }},
    })
}
```

### Compatibility matrix

Test against the most recent two PyPKI minor releases; declare
older versions unsupported. PyPKI's REST API is versioned via the
`/api/v1/` prefix once the provider exists — adding `/api/v2/` later
without breaking v1 is the upgrade path.

---

## On the PyPKI side

These are the changes PyPKI must make so the provider can exist:

| Change                                              | File                            |
| --------------------------------------------------- | ------------------------------- |
| Generate and publish `/api/openapi.json`            | `pki_server.py`, `openapi.py` (new) |
| Move all current endpoints under `/api/v1/` (back-compat alias from `/api/`) | `pki_server.py` |
| `pypki_admin.py openapi-export` subcommand          | `pypki_admin.py`                |
| CI step: spec lint + ensure no drift                | `.github/workflows/openapi.yml` |
| Service-account tokens with role-based authz        | already exists per `CLAUDE-sso.md` |
| `docs/INTEGRATIONS.md` section: Terraform           | `docs/`                         |

OpenAPI generation: hand-write the spec at `docs/openapi.yaml`,
validate at startup against the registered handlers (every handler
must have a spec entry; every spec entry must have a handler). Cheaper
than auto-generation and forces docs to stay current. ~600 LoC of YAML
for the current handler set.

---

## Per-change checklist (PyPKI side)

- [ ] `openapi.py` — load `docs/openapi.yaml`, validate against handlers
- [ ] `pki_server.py` — `/api/v1/` mount, `/api/openapi.json` route
- [ ] `pypki_admin.py` — `openapi-export`
- [ ] `docs/openapi.yaml` — initial spec covering all current endpoints
- [ ] `.github/workflows/openapi.yml` — drift check in CI
- [ ] `test_pki_server.py` — `TestOpenAPISpec` (every handler in spec)
- [ ] `README.md` — Terraform integration link
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/INTEGRATIONS.md` — section on Terraform

## Per-repo checklist (provider repo)

- [ ] `main.go`, `internal/provider/provider.go`
- [ ] Resources: `pypki_certificate`, `pypki_sub_ca`, `pypki_acme_account`,
      `pypki_policy_attachment`
- [ ] Data sources: `pypki_ca_chain`, `pypki_certificate`,
      `pypki_acme_directory`
- [ ] `internal/client/pypki/` — generated from OpenAPI
- [ ] `examples/` — homelab, enterprise-mtls, kubernetes-bootstrap
- [ ] `docs/` — markdown for Terraform Registry
- [ ] Acceptance test job in CI against PyPKI container
- [ ] Release workflow with GPG-signed binaries for the Terraform Registry
- [ ] `README.md` with quickstart

---

## Open questions

1. **Pulumi and Crossplane**: once OpenAPI exists, both come almost for
   free via codegen. Crossplane especially closes the K8s loop with
   `cert-manager` for users who want everything declarative in
   Kubernetes manifests. Defer until Terraform is stable, then revisit
   based on user demand.

2. **State file sensitivity**: certs in Terraform state are sensitive
   (revealing serial numbers and SANs to anyone with state-file read
   access). Document the standard "use a remote backend with
   encryption" advice; consider marking `cert_pem` as `Sensitive` in
   the schema even though it's not technically secret (it discourages
   accidental display in CI logs).

3. **Diff stability**: re-issuing a cert produces a new serial and
   `not_before`, so naive equality checks would force perpetual diff.
   The provider must suppress diffs on these fields unless one of the
   user-controlled inputs (subject, SANs, profile, key params) actually
   changed. Standard `customdiff` pattern; non-trivial to get right.

4. **Race with ACME**: if the same hostname is managed by both
   `pypki_certificate` and an in-cluster ACME client, they'll fight.
   Document the rule of thumb: ACME owns leaf certs in K8s,
   Terraform owns root/intermediate/sub-CA and non-K8s leaves. Add an
   example showing the boundary.

5. **Long-term provider ownership**: HashiCorp Verified vs Community
   tier on the Registry has different requirements (HashiCorp Verified
   requires a partnership). Start as Community; revisit if/when PyPKI
   has commercial backing.
