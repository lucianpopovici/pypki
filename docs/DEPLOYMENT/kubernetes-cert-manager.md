# Deployment: Kubernetes with cert-manager + PyPKI sub-CA

> Last reviewed: 2026-06-01 (commit 453e7ba)

This guide deploys PyPKI as a Certificate Authority for a Kubernetes cluster, with **cert-manager** as the in-cluster issuer. PyPKI runs outside the cluster (typically on a dedicated host or VM); cert-manager runs inside the cluster as a `CA` ClusterIssuer using a sub-CA bootstrapped from PyPKI.

This is the topology PyPKI is designed for in cloud-native environments.

## Why this design (and what PyPKI deliberately doesn't do)

We considered three topologies before settling on this one:

| Topology | Verdict |
|---|---|
| **PyPKI as the in-cluster issuer directly** (cert-manager `Issuer` pointing at PyPKI's REST/CMP API) | **Rejected.** Adds a network dependency on every cert renewal in the cluster. Slow, fragile under partition. cert-manager's external-issuer model isn't standardized — every external integration is bespoke. |
| **EST + cert-manager** | **Rejected.** cert-manager doesn't speak EST natively; would require a custom external issuer. EST adds nothing over the chosen design here for k8s use cases. |
| **PyPKI issues a sub-CA → cert-manager runs a `CA` ClusterIssuer with that sub-CA's key + cert** | **Chosen.** cert-manager's built-in `CA` issuer just signs locally with the provided key + cert. No external dependency at issuance time. PyPKI is consulted only at sub-CA bootstrap (rare) and revocation (rare). Sub-CA naming constraints bound what cert-manager can issue. |

The cluster control plane (kubeadm-managed `kube-apiserver`, etcd, kubelet, etc.) keeps its self-signed CA. The operational pain of `kubeadm init --external-ca` and managing an offline CA workflow for the control plane far outweighs the benefit. PyPKI handles the **workload identity** layer, not the control plane. If you need a unified PKI for both, that's a different deployment topology and a much bigger project.

## Topology

```
                      ┌───────────────────────────────┐
                      │   PyPKI (outside cluster)     │
                      │   - root CA private key       │
                      │   - issues sub-CAs            │
                      │   - serves CRL + OCSP         │
                      │   - serves CPS document       │
                      └─────────────┬─────────────────┘
                                    │  /api/issue-sub-ca   (bootstrap-time only)
                                    ▼
                      ┌───────────────────────────────┐
                      │   k8s Secret: cluster-ca       │
                      │   tls.crt + tls.key            │
                      │   (the sub-CA, in cluster)     │
                      └─────────────┬─────────────────┘
                                    │  referenced by
                                    ▼
                      ┌───────────────────────────────┐
                      │   cert-manager ClusterIssuer  │
                      │   spec.ca.secretName=cluster-ca│
                      └─────────────┬─────────────────┘
                                    │  signs
                                    ▼
                      ┌───────────────────────────────┐
                      │   workload Certificate CRs    │
                      │   (Ingress TLS, mTLS, ...)    │
                      └───────────────────────────────┘
```

## Prerequisites

- A running PyPKI deployment with HTTP(S) API access (REST API key configured)
- kubectl access to the target cluster
- cert-manager v1.13+ installed (`kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml`)
- A registered Private Enterprise Number (PEN) for your CPS policy OID — see [CPS.md §1.2](../CPS.md#12-document-identification)

## Step 1 — Decide the sub-CA's name and constraints

The sub-CA you're about to issue will sign certificates **only** for resources in this cluster. Bound it tightly with `nameConstraints` to limit blast radius if the sub-CA key is compromised:

| Constraint | Example | Reason |
|---|---|---|
| `permittedDNSNames` | `*.cluster1.example.internal`, `cluster1.example.internal` | Workload DNS names |
| `permittedDNSNames` (for service mesh) | `*.svc.cluster.local`, `*.svc` | mTLS between Pods if Istio/Linkerd uses this CA |
| `excludedDNSNames` | `*.example.com` (your real public domain) | Belt-and-braces: even if compromised, the sub-CA can't issue for your real domain |
| `permittedIPRanges` | `10.0.0.0/8` (your pod/node CIDR) | Bound IP-SAN issuance to RFC1918 |
| `pathLength` | `0` | Sub-CA cannot issue further sub-CAs |

Document these in your CPS Appendix A — relying parties need to know what your sub-CA is allowed to do.

## Step 2 — Bootstrap the sub-CA from PyPKI

Use the REST API to issue the sub-CA. PyPKI returns the sub-CA cert and private key as PEM. **The key never leaves this single API call** — store it directly into a Kubernetes Secret.

```bash
# On a host with kubectl + curl, with PYPKI_API_KEY exported:
SUBCA_NAME="cluster1-issuer"
SUBCA_VALIDITY_DAYS=1825   # 5 years; shorter is safer if you're set up for renewal

curl -sS -X POST "https://pki.example.internal/api/issue-sub-ca" \
  -H "X-API-Key: $PYPKI_API_KEY" \
  -H "Content-Type: application/json" \
  -d @- <<EOF > /tmp/subca-response.json
{
  "subject": "CN=$SUBCA_NAME, O=Example Org, OU=Cluster 1",
  "validity_days": $SUBCA_VALIDITY_DAYS,
  "path_length": 0,
  "permitted_dns": [
    "*.cluster1.example.internal",
    "cluster1.example.internal",
    "*.svc.cluster.local",
    "*.svc"
  ],
  "excluded_dns": [
    "example.com",
    "*.example.com"
  ],
  "permitted_ips": [
    "10.0.0.0/8"
  ]
}
EOF

# Extract the cert and key. PyPKI emits PKCS#8 keys as of RFC 5958 fix.
jq -r '.cert_pem'  /tmp/subca-response.json > /tmp/subca.crt
jq -r '.key_pem'   /tmp/subca-response.json > /tmp/subca.key
jq -r '.chain_pem' /tmp/subca-response.json > /tmp/subca-chain.crt
```

The `path_length: 0` is enforced (it was being silently ignored before the sub-CA ergonomics fix). The `permitted_dns` / `excluded_dns` / `permitted_ips` fields actually appear in the issued sub-CA's `nameConstraints` extension as critical (also a recent fix — they used to be silently dropped).

Verify the sub-CA has the constraints you expect:

```bash
openssl x509 -in /tmp/subca.crt -noout -text | sed -n '/X509v3 Name Constraints/,/X509v3/p'
```

You should see:
```
X509v3 Name Constraints: critical
    Permitted:
      DNS:*.cluster1.example.internal
      DNS:cluster1.example.internal
      DNS:*.svc.cluster.local
      DNS:*.svc
      IP:10.0.0.0/255.0.0.0
    Excluded:
      DNS:example.com
      DNS:*.example.com
```

## Step 3 — Create the cert-manager Secret

```bash
kubectl create namespace cert-manager-issuer 2>/dev/null

kubectl -n cert-manager-issuer create secret tls cluster1-ca \
  --cert=/tmp/subca.crt \
  --key=/tmp/subca.key

# Securely delete the local copy. The Secret is now the only copy in cluster.
shred -u /tmp/subca.key /tmp/subca-response.json
```

Some operators add the chain into the Secret too. cert-manager's `CA` issuer doesn't strictly need the chain on the issuer side (it's added to leaf certs at sign time), but having it available is convenient:

```bash
kubectl -n cert-manager-issuer create configmap cluster1-ca-chain \
  --from-file=ca-chain.pem=/tmp/subca-chain.crt
```

## Step 4 — Define the ClusterIssuer

```yaml
# cluster1-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: pypki-cluster1
spec:
  ca:
    secretName: cluster1-ca
    # secretName must reference a kubernetes.io/tls secret in the
    # cert-manager namespace (or wherever cert-manager looks).
    # If you put the secret in a different namespace, use an Issuer
    # (namespaced) instead of ClusterIssuer.
```

```bash
kubectl apply -f cluster1-issuer.yaml
kubectl describe clusterissuer pypki-cluster1
```

You should see `Status.Conditions[*].Status: "True"` and `Type: "Ready"`. If not, check `kubectl -n cert-manager logs deploy/cert-manager`.

## Step 5 — Issue your first workload Certificate

```yaml
# example-app-cert.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-app-tls
  namespace: default
spec:
  secretName: example-app-tls
  duration: 720h           # 30 days
  renewBefore: 240h        # renew 10 days early
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: pypki-cluster1
    kind: ClusterIssuer
  dnsNames:
    - example-app.cluster1.example.internal
```

```bash
kubectl apply -f example-app-cert.yaml
kubectl describe certificate example-app-tls
```

cert-manager will create the Secret `example-app-tls` containing `tls.crt` and `tls.key`. Mount it into your Pod or use it via Ingress.

## Step 6 — Verify revocation works

This is what makes a real PKI different from a glorified self-signed bundle. Issue a test cert, revoke it via PyPKI, observe relying parties detecting the revocation.

```bash
# 1. Issue a test cert
kubectl apply -f example-app-cert.yaml

# 2. Find its serial number
SERIAL=$(kubectl get secret example-app-tls -o jsonpath='{.data.tls\.crt}' | \
         base64 -d | openssl x509 -noout -serial | cut -d= -f2)

# 3. Revoke via PyPKI's REST API
curl -sS -X POST "https://pki.example.internal/api/revoke" \
  -H "X-API-Key: $PYPKI_API_KEY" \
  -d "serial=0x$SERIAL&reason=4"   # reason 4 = superseded

# 4. Wait for OCSP cache to expire (default 300s) then check
sleep 310
openssl ocsp -issuer /tmp/subca-chain.crt \
             -cert <(kubectl get secret example-app-tls -o jsonpath='{.data.tls\.crt}' | base64 -d) \
             -url https://pki.example.internal/ocsp \
             -resp_text -noverify

# Expect: "Cert Status: revoked"
```

**Caveat:** cert-manager itself does not check OCSP / CRL when handing certs to workloads. Revocation is a runtime concern enforced by:
- The mTLS server on the receiving side (which should validate via OCSP / CRL)
- Service mesh policy (Istio's `PeerAuthentication`, Linkerd's mTLS)
- Application-level cert validation

If your workloads aren't checking revocation status, revocation alone won't stop a compromised cert from being accepted in the cluster. **Pair short cert lifetimes (24-72h for sensitive workloads) with revocation as defense-in-depth.**

## Step 7 — Sub-CA renewal

The sub-CA you bootstrapped expires per `validity_days` (5 years in the example above). Renewal is currently a manual operation. **Plan it well before expiry.**

Procedure:

1. ~6 months before sub-CA expiry, issue a fresh sub-CA from PyPKI (Step 2 again, optionally with a different name to disambiguate)
2. Update the cert-manager Secret to point at the new sub-CA cert + key
3. Trigger renewal of all workload certs: `cert-manager.io/issue-temporary-certificate` annotation on each Certificate, or simply wait for natural renewal (cert-manager uses `renewBefore`)
4. After the last workload cert is re-issued from the new sub-CA, retire the old sub-CA's private key
5. Continue serving CRL + OCSP for the old sub-CA until the last workload cert under it expires
6. After that point, the old sub-CA can be fully retired

For deployments where 5-year sub-CA validity is too long, set `validity_days: 365` and run this renewal yearly. **Yearly drills make the procedure muscle memory rather than a once-in-five-years adventure.**

## Step 8 — CPS pointer in issued certs

Set `--cps-uri` and `--cps-policy-oid` on the PyPKI server so every cert (including the sub-CA you just bootstrapped, and every workload cert it signs) carries the CertificatePolicies extension pointing at your hosted CPS document. See [CPS.md](../CPS.md) for the template and [pki_server.py argparse](../../pki_server.py) for the flags.

## Service mesh integration (Istio / Linkerd)

Both meshes can consume a cert-manager-managed CA. You have two choices:

### Option A — Mesh issues its own intermediate, cert-manager-istio-csr

**Best for: Istio-only deployments where you want the standard Istio control plane to remain in charge.**

Install cert-manager-istio-csr in the istio-system namespace, point it at your `pypki-cluster1` ClusterIssuer. Istio's `istiod` requests an intermediate from your cert-manager issuer, then uses that intermediate to sign workload certs. Two layers of CA chained from your sub-CA chained from your PyPKI root. Verify with `istioctl pc s <pod> -o json | jq '.dynamicActiveSecrets[] | select(.name | contains("default"))'`.

### Option B — Mesh consumes cert-manager certs directly via SPIRE or trust-manager

**Best for: SPIFFE-based identity, multi-mesh, or Linkerd.**

Use `trust-manager` (also from cert-manager.io) to distribute the CA chain into mesh namespaces. Use SPIFFE Federation if you have multiple meshes that need to trust each other.

Either way, the chain back to PyPKI is preserved, and revocation done at PyPKI propagates outward.

## What this deployment doesn't do

To set expectations:

- **Does not** automatically distrust the cluster control plane's self-signed kubeadm CA. Workload certs from PyPKI's sub-CA, control plane uses its own. If you need a unified PKI, that's `kubeadm init --external-ca` territory and significantly more operational work.
- **Does not** rotate the sub-CA private key automatically. Step 7 is manual until Tier 5.6 cross-signing tooling ships.
- **Does not** replace `cert-manager`. cert-manager is the in-cluster issuer; PyPKI is the upstream root and revocation source.
- **Does not** enforce revocation at workloads. That's the application's / mesh's job.

## Troubleshooting

**`ClusterIssuer status not Ready, error: tls: failed to find any PEM data in certificate input`**
The Secret is malformed. Re-run Step 3 ensuring the files are valid PEM (start with `-----BEGIN CERTIFICATE-----` and `-----BEGIN PRIVATE KEY-----`). If you see `BEGIN RSA PRIVATE KEY` instead of `BEGIN PRIVATE KEY`, your PyPKI build is from before the RFC 5958 fix — upgrade.

**`Certificate stuck in CertificateRequest pending state`**
Check `kubectl describe certificaterequest <name>`. Common causes: requested DNS name violates the sub-CA's `nameConstraints` (Step 1); the namespace's ServiceAccount lacks RBAC permissions on cert-manager CRDs.

**Revoked cert still being accepted by workloads**
Workloads must be configured to check OCSP or CRL. cert-manager doesn't do it for them.

## References

- [CPS.md](../CPS.md) — Certification Practice Statement
- [THREAT_MODEL.md](../THREAT_MODEL.md) — adversary model and per-component compromise scenarios
- cert-manager docs: <https://cert-manager.io/docs/>
- cert-manager `CA` issuer: <https://cert-manager.io/docs/configuration/ca/>
- Istio cert-manager-istio-csr: <https://cert-manager.io/docs/usage/istio-csr/>
