# CLAUDE-deployment-topologies.md — Reference Deployment Topologies

Companion to `CLAUDE.md`. Follow all conventions there. Documents four
reference deployments end-to-end. Each is paired with working IaC
(Terraform / Ansible / Helm) in `examples/topologies/<name>/` and a
runbook in `docs/topologies/<name>.md`. Becomes the canonical answer
to "how should I deploy this?"

---

## What this is

PyPKI's current docs imply Docker Compose with nginx. That's one
topology among many; new operators end up reinventing the others by
trial and error. This spec defines four canonical deployments, each
with explicit threat model, IaC, and runbook. The init wizard
(`CLAUDE-bootstrap-cli.md`) asks which topology and produces matching
configs.

The four:

1. **Homelab Pi** — single box, SQLite, file-backed keys, nginx, ports
   80/443. Optimized for "running in 30 minutes."
2. **Single-VM Enterprise** — one VM, Postgres on same VM, PKCS#11 HSM
   or cloud KMS, two-NIC isolation. Optimized for "small org, real
   security."
3. **HA Enterprise** — multiple PyPKI instances behind HAProxy,
   streaming-replicated Postgres, shared cloud KMS, observability
   stack. Optimized for "no single point of failure."
4. **Kubernetes-native** — Helm chart, Postgres operator, cert-manager
   integration, NetworkPolicy isolation. Optimized for "ops team
   already operates K8s."

---

## Topology A: Homelab Pi

### Diagram

```
                     ┌─────────────────────────┐
                     │   Raspberry Pi 4/5      │
                     │   or NAS / mini-PC      │
                     │                         │
   LAN traffic ───►  │  nginx :80 :443         │
                     │    │                    │
                     │    ▼                    │
                     │  PyPKI :8443 (loopback) │
                     │    │                    │
                     │    ▼                    │
                     │  SQLite WAL             │
                     │  /var/lib/pypki/db/     │
                     │                         │
                     │  Backup → USB / NAS NFS │
                     └─────────────────────────┘
```

### Specs

- **Hardware**: Raspberry Pi 4 (4GB+), Pi 5, ODROID, mini-PC. 2 GB
  RAM minimum; 8 GB+ if running the Web UI heavily.
- **OS**: Raspberry Pi OS Bookworm, Ubuntu Server LTS, or Debian
  stable.
- **TLS**: pattern A (self-signed by own CA) or pattern B (Let's
  Encrypt) — operator's choice.
- **Auth**: PAM, one admin user.
- **Backup**: weekly cron to local USB or NFS mount on the home NAS.
- **Observability**: Prometheus on the same host, optional Grafana.

### Threat model

- **In scope**: physical theft of the device, family-member
  accidental misuse, ISP-level network observers, malicious LAN
  device.
- **Out of scope**: nation-state adversaries, supply-chain attacks
  on the Pi firmware, sophisticated targeted physical attacks.

Mitigations: full-disk encryption (LUKS) recommended, SSH key-only
access, fail2ban on SSH, ufw with default-deny.

### IaC

`examples/topologies/homelab-pi/`:

```
homelab-pi/
├── README.md                          # 5-minute getting started
├── ansible/
│   ├── playbook.yml                   # idempotent, run on the Pi
│   ├── inventory.yml.example
│   └── roles/
│       ├── base/                      # ufw, fail2ban, unattended-upgrades
│       ├── nginx/
│       └── pypki/
├── scripts/
│   ├── flash-sd-card.sh               # writes Pi OS + cloud-init
│   └── post-install.sh                # runs `pypki init --homelab`
└── cloud-init/
    └── user-data.yaml                 # SSH keys, hostname, packages
```

`ansible-playbook playbook.yml -i inventory.yml` from a workstation
takes a freshly-flashed Pi to a fully-running PyPKI in ~10 minutes.

### Runbook (`docs/topologies/homelab-pi.md`)

Covers: initial setup, adding ACME clients (acme.sh on OpenWrt, lego
on a NAS, certbot on a Raspberry Pi), browser trust installation
across major OSes, common troubleshooting (clock skew, DNS issues),
upgrade procedure, and what to do if the SD card dies.

---

## Topology B: Single-VM Enterprise

### Diagram

```
       Internet                              Internal admin VLAN
          │                                        │
          ▼                                        ▼
   ┌──────────────┐                         ┌────────────┐
   │ Public NIC   │                         │ Admin NIC  │
   │ ens0:443/80  │                         │ ens1:8443  │
   └──────┬───────┘                         └─────┬──────┘
          │                                       │
   ┌──────┴───────────────────────────────────────┴──────┐
   │                                                     │
   │  VM (8 vCPU, 16 GB RAM)                             │
   │                                                     │
   │  nginx :443 :80         PyPKI admin :8443           │
   │      │                     │                        │
   │      ▼                     ▼                        │
   │  PyPKI public :8080 (loopback)                      │
   │      │                                              │
   │      ▼                                              │
   │  Postgres 16 (local, listening on loopback)         │
   │                                                     │
   │  HSM: PKCS#11 (YubiHSM2 / nShield / Luna) or KMS    │
   │                                                     │
   │  Backup → S3 / Azure Blob / NFS (cron 0 2 * * *)    │
   └─────────────────────────────────────────────────────┘
```

### Specs

- **VM**: 8 vCPU, 16 GB RAM, 200 GB SSD. Typical bare metal or
  hypervisor VM.
- **OS**: Ubuntu LTS, RHEL/Rocky/Alma 9, Debian stable.
- **DB**: Postgres 16 on the same VM (latency win; backups need
  per-DB strategy).
- **Keys**: PKCS#11 HSM via local USB / PCIe card (YubiHSM2, nShield
  Solo, Luna PCIe) or cloud KMS over the public-cloud network.
- **Network isolation**: public NIC for ACME / OCSP / CRL, admin NIC
  for Web UI and REST API. Strict firewall rules per-NIC.
- **TLS**: pattern B (LE on public) + pattern A or C (admin).
- **Auth**: OIDC (Keycloak/Okta/Entra ID) for admins, PAM as fallback.
- **Observability**: Prometheus + Grafana on the same VM or external.

### Threat model

- **In scope**: external attackers, lateral movement from a
  compromised user workstation on the admin VLAN, insider with
  read-only DB access.
- **Out of scope**: hypervisor escape, hardware tampering with the
  HSM.

Mitigations: SELinux/AppArmor enforced (see
`CLAUDE-os-hardening-firewall.md`), per-NIC firewall (no admin
endpoints on public NIC), HSM PIN held in environment variable from
a secret manager (Vault / AWS Secrets Manager / Azure Key Vault).

### IaC

`examples/topologies/single-vm-enterprise/`:

```
single-vm-enterprise/
├── README.md
├── terraform/
│   ├── aws/                            # EC2 + ENIs + SG + IAM
│   ├── gcp/                            # Compute Engine + VPC
│   ├── azure/                          # VM + NSGs + identity
│   └── proxmox/                        # for on-prem hypervisor
├── ansible/
│   ├── playbook.yml
│   └── roles/
│       ├── postgres/
│       ├── nginx/
│       ├── apparmor/
│       ├── nftables/
│       ├── pypki/
│       └── observability/
└── runbooks/
    ├── deploy.sh                       # tf apply + ansible-playbook
    └── disaster-recovery.sh
```

### Runbook

Covers: initial deployment (terraform → ansible → init), HSM
provisioning, OIDC integration, network policy validation,
upgrade procedure, DR walk-through.

---

## Topology C: HA Enterprise

### Diagram

```
                      Load balancer (anycast or active-passive)
                      ┌──────────────┐
                      │  HAProxy /   │
                      │  AWS NLB /   │
                      │  GCP TCP LB  │
                      └──────┬───────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   ┌─────────┐         ┌─────────┐         ┌─────────┐
   │ PyPKI A │         │ PyPKI B │         │ PyPKI C │
   │ stateless│         │stateless│         │stateless│
   └────┬────┘         └────┬────┘         └────┬────┘
        │                   │                   │
        └─────────┬─────────┴─────────┬─────────┘
                  │                   │
           ┌──────▼───┐         ┌─────▼──────┐
           │ Postgres │ stream  │ Postgres   │
           │ primary  │◄────────┤ replicas   │
           └──────────┘  WAL    └────────────┘
                  │
                  ▼
            Cloud KMS (shared)
                  │
                  ▼
         Backup: S3/GCS, signed seals
         Anchored externally (git repo, public log)

      Observability: Prometheus → Mimir, Loki, Tempo
```

### Specs

- **PyPKI nodes**: 3+, stateless except for in-memory caches. Behind
  L4 load balancer; round-robin or least-connections.
- **DB**: Postgres primary + 2 streaming replicas. Failover via
  Patroni, pg_auto_failover, or cloud-managed (RDS Multi-AZ,
  Cloud SQL HA, Azure Database for Postgres flexible-server HA).
- **PgBouncer**: in front of Postgres in transaction mode (see
  `CLAUDE-db-bootstrap.md`).
- **Keys**: cloud KMS, single key referenced by all nodes.
- **Locks**: Postgres advisory locks (already used). Verified to
  serialize correctly across nodes for serial allocation and the
  audit-chain append.
- **Backup**: every node can trigger a backup; coordination via
  Postgres advisory lock. Seals anchored to an external location.
- **Observability**: full stack (Prometheus + remote write, Loki,
  Tempo or Jaeger), per-node and aggregated dashboards.

### Threat model

- Single node failure → load balancer routes around.
- Postgres primary failure → automated failover within seconds.
- Region failure → operator restore from cross-region backup (manual).
- KMS failure → emergency mode: existing certs keep working, no
  new issuance until KMS recovers. Document the playbook.

### IaC

`examples/topologies/ha-enterprise/`:

```
ha-enterprise/
├── README.md
├── terraform/
│   ├── aws/                            # ALB / NLB, ASG, RDS, KMS
│   ├── gcp/                            # GLB, MIG, Cloud SQL, KMS
│   ├── azure/                          # LB, VMSS, Flex Server, KV
│   └── on-prem/                        # HAProxy, Patroni cluster
├── helm/                               # if hybrid K8s + VM
├── ansible/
│   ├── playbook-pypki-node.yml
│   ├── playbook-postgres-cluster.yml
│   └── playbook-observability.yml
└── runbooks/
    ├── node-replacement.md
    ├── postgres-failover.md
    ├── kms-incident.md
    └── region-failover.md
```

### Runbook

Covers: node addition / removal, rolling upgrades (drain → upgrade →
verify → next), Postgres failover drill, KMS outage handling,
cross-region DR drill (yearly).

---

## Topology D: Kubernetes-native

### Diagram

```
                  Ingress controller (nginx-ingress / Traefik)
                      │
                      ▼
                ┌────────────┐
                │  PyPKI svc │  (3 replicas, anti-affinity)
                └────┬───────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    Pod A        Pod B        Pod C       (stateless workers)
        │            │            │
        └────────────┴────────────┘
                     │
                     ▼
          Postgres operator (CNPG / Zalando)
          PVC-backed, automated backups to S3
                     │
                     ▼
          External Secrets → cloud KMS, OIDC creds

   PyPKI integrates with:
   - cert-manager (via own ACME server)
   - Prometheus Operator (ServiceMonitor)
   - NetworkPolicy (default-deny, explicit allowlist)
```

### Specs

- **Distribution**: any conformant K8s 1.30+ (EKS, GKE, AKS, on-prem
  k3s, OpenShift).
- **Storage**: Postgres on PVC backed by SSD-tier StorageClass.
- **Secrets**: External Secrets Operator pulls from vault / cloud
  secret manager into K8s Secrets.
- **Ingress**: nginx-ingress or Traefik; cert-manager **uses PyPKI**
  for the cluster's own certs (closed loop).
- **Image**: distroless, non-root, read-only rootfs, SBOM attached.
- **Observability**: Prometheus Operator (ServiceMonitor), OTel
  collector DaemonSet.
- **HA**: 3 PyPKI replicas with anti-affinity, PodDisruptionBudget
  `minAvailable: 2`.

### Threat model

- Hostile pod on same node → restricted by Pod Security Standards
  (`restricted` profile) and NetworkPolicy.
- Stolen ServiceAccount token → bound to specific role with minimal
  Kubernetes RBAC; PyPKI's own admin is OIDC, not K8s SA.
- Container escape → Pod Security Standards + restricted SCC
  (OpenShift) or PodSecurityPolicy admission.

### Helm chart

`examples/topologies/kubernetes/helm/pypki/`:

```
pypki/
├── Chart.yaml
├── values.yaml                         # full config surface
├── values-homelab.yaml                 # minimal example
├── values-enterprise.yaml              # full HA example
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   ├── networkpolicy.yaml
│   ├── poddisruptionbudget.yaml
│   ├── servicemonitor.yaml
│   ├── pdb.yaml
│   ├── secret-external.yaml            # External Secrets
│   └── postgres-cluster.yaml           # CNPG Cluster CR
└── README.md
```

`values.yaml` exposes the full set of init-answers fields so a deployed
Helm release is the K8s-native equivalent of running `pypki init`.

### cert-manager integration

The clinching K8s feature. The cluster's nginx-ingress wants TLS
certs; cert-manager provisions them; cert-manager's ACME client points
at PyPKI's own ACME endpoint. Self-bootstrap:

1. Helm install PyPKI with an external-bootstrap cert from `init`.
2. Apply a `ClusterIssuer` pointing at PyPKI's ACME URL.
3. cert-manager requests TLS certs from PyPKI for the cluster's
   Ingress resources.
4. PyPKI eventually rotates its own admin cert to one issued via
   ACME-via-cert-manager (full closed loop).

Document this in `docs/topologies/kubernetes.md` with the YAML.

---

## Selection guide

The init wizard asks the topology question with this guide:

| If you...                                         | Pick   |
| ------------------------------------------------- | ------ |
| Want a CA for your home network in <30 min        | A      |
| Run one or two VPSes, need a real CA for internal services | B |
| Operate enterprise infra with HA SLAs             | C      |
| Already operate Kubernetes and want IaC-native    | D      |

Cross-topology migration is supported only A→B and B→C; not D
(K8s deployments stay in K8s). Document the migration paths in
`docs/topologies/migration.md`.

---

## Implementation

Topologies are mostly documentation + IaC, not code. Code changes are
limited to enabling each topology cleanly:

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `docs/topologies/` | New subdir, one file per topology + selection guide + migration |
| `examples/topologies/<name>/` | IaC for each                                     |
| `pki_server.py`   | `--topology-hint A|B|C|D` sets reasonable defaults for         |
|                   | thread counts, log verbosity, metrics scrape interval        |
| `wizard.py`       | Topology question, document the implications                 |
| `Helm chart`      | Lives in `examples/topologies/kubernetes/helm/pypki/`        |
| `README.md`       | New "Deployment topologies" section                          |
| `CHANGELOG.md`    | `### Added`                                                  |

### Topology test matrix in CI

```yaml
# .github/workflows/topology-smoke.yml
jobs:
  homelab-pi:
    runs-on: ubuntu-latest
    steps:
      # cloud-init in a VM, run ansible, run pypki init --homelab,
      # issue one cert, assert chain validates
  single-vm:
    # terraform local-exec + ansible + smoke test
  ha-enterprise:
    # docker-compose mimicking 3 PyPKI + Patroni Postgres,
    # rolling-upgrade test
  kubernetes:
    # kind cluster, helm install, cert-manager integration test
```

Each topology is smoke-tested nightly; a broken topology blocks the
next release.

---

## Per-change checklist

- [ ] `docs/topologies/` — four pages + selection guide + migration
- [ ] `examples/topologies/homelab-pi/` — Ansible, cloud-init
- [ ] `examples/topologies/single-vm-enterprise/` — Terraform per cloud, Ansible
- [ ] `examples/topologies/ha-enterprise/` — Terraform, Ansible, runbooks
- [ ] `examples/topologies/kubernetes/helm/pypki/` — Helm chart
- [ ] `pki_server.py` — `--topology-hint` flag
- [ ] `wizard.py` — topology question
- [ ] `.github/workflows/topology-smoke.yml` — nightly smoke tests
- [ ] `README.md` — Deployment topologies section
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `pypki-flows.html` — diagram per topology

Run `./run_tests.sh` plus the topology workflows.

---

## Open questions

1. **Cloud-marketplace images**: pre-baked AMIs / GCP images / Azure
   marketplace listings, one per cloud, that boot to a working
   single-VM deployment. Operator picks the image, fills in a form,
   gets a running PyPKI. Significant ops work to maintain. Defer
   until topology B has steady-state demand.

2. **HA without Postgres**: a CRDT-based or Raft-based replication
   layer would let PyPKI be HA without Postgres. Tantalizing
   simplification but a multi-year project; Postgres is the
   pragmatic answer. Document why.

3. **Edge / IoT deployments**: PyPKI as a tiny CA on a constrained
   device serving Matter or Thread enrollment. Topology E? The
   Matter spec from `CLAUDE-embedded-enrollment.md` suggests this
   user exists; add as a fifth topology when concrete.

4. **Government / classified deployments**: air-gapped + Common
   Criteria certified components. Out of scope for the open-source
   project but the offline-root + Shamir + air-gapped-ceremony
   pieces are the building blocks. Document the gap rather than
   pretending to fill it.

5. **Topology auto-detection**: an introspection command that looks
   at the environment (K8s? systemd? Docker? Pi?) and recommends a
   topology. Friendly for new operators, but the wizard already
   asks. Skip.
