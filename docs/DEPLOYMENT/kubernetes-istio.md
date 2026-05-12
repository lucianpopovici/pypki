# Deployment: PyPKI as Istio Mesh CA

This guide chains PyPKI into an [Istio](https://istio.io) service mesh as the trust root for mTLS between meshed workloads. It builds on `docs/DEPLOYMENT/kubernetes-cert-manager.md` — read that first if you haven't, because the same sub-CA pattern underlies both. The difference is that Istio's `istiod` control plane is the issuer of leaf workload certs, and we wire it to a PyPKI-rooted intermediate.

> **The big picture.** Istio's default behavior is to generate its own self-signed root and use it as the mesh CA. That's fine for a demo, terrible for any environment where workloads outside the mesh need to verify mesh-issued certs (and vice versa). Wiring Istio to a PyPKI-rooted intermediate means **everything in your environment chains to one trust root**: meshed workloads, non-meshed workloads, ingress endpoints, internal HTTPS, IoT, the lot.

> **Two options inside this pattern.** Either (a) hand Istio a static intermediate cert + key (the "[plug-in CA certs](https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/)" pattern) or (b) run [`cert-manager-istio-csr`](https://github.com/cert-manager/istio-csr) so Istio's CSR requests are forwarded to cert-manager (and from there to PyPKI's sub-CA). Option (b) is the right answer for production because the intermediate key is held by cert-manager, not handed to istiod. This guide covers both.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Decision: Plug-in CA vs istio-csr](#2-decision-plug-in-ca-vs-istio-csr)
3. [Prerequisites](#3-prerequisites)
4. [Option A — Plug-in CA Certs](#4-option-a--plug-in-ca-certs)
5. [Option B — cert-manager-istio-csr](#5-option-b--cert-manager-istio-csr)
6. [Verifying the Trust Chain](#6-verifying-the-trust-chain)
7. [Rotation](#7-rotation)
8. [Cross-Cluster mTLS](#8-cross-cluster-mtls)
9. [Operational Notes](#9-operational-notes)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Architecture

```
PyPKI Root
  │
  └── Mesh Sub-CA  (issued via /api/issue-sub-ca, name-constrained)
        │
        ├── Option A: handed directly to istiod as cacerts Secret
        │             → istiod uses its private key to sign workload certs
        │
        └── Option B: handed to cert-manager-istio-csr,
                      which forwards Istio CSRs to a cert-manager Issuer
                      backed by the same sub-CA → leaves issued via cert-manager.
```

Either way, **every workload-to-workload mTLS handshake inside the mesh chains back to the PyPKI root**, and a workload outside the mesh that has the PyPKI root in its trust store can verify mesh certs and be verified by them.

---

## 2. Decision: Plug-in CA vs istio-csr

| Aspect | Plug-in CA (Option A) | istio-csr (Option B) |
|---|---|---|
| **Where the sub-CA private key lives** | In a Kubernetes `Secret` mounted into istiod | In a cert-manager-issued cert; CSRs go to cert-manager and back |
| **Issuance throughput** | Higher — istiod signs locally | Lower — every CSR is a round-trip to cert-manager |
| **Operational simplicity** | Simpler — fewer moving parts | More moving parts but better separation |
| **Audit visibility on workload cert issuance** | Only via istio's own logs | Full cert-manager + PyPKI audit trail |
| **Rotation of the sub-CA** | Restart istiod; brief mesh disruption | Cert-manager handles rotation; transparent |
| **HSM integration** | Not directly — istiod doesn't speak PKCS#11 | Possible — cert-manager's CA Issuer can chain into a Vault Issuer that uses an HSM |
| **Recommended for** | Smaller meshes (< 100 workloads), simpler ops | Larger meshes, regulated environments, HSM-backed roots |

**Default to Option B for production.** Pick Option A if the mesh is small and you specifically don't want the extra dependency.

---

## 3. Prerequisites

- **PyPKI** running with admin API enabled and a valid `--admin-key`.
- **Kubernetes** cluster with admin access. Tested on 1.27+; older versions likely work but are untested.
- **Istio** not yet installed (this guide installs it). If you already run Istio, you'll need to migrate the trust root — see §7.
- **cert-manager** installed for Option B (see `docs/DEPLOYMENT/kubernetes-cert-manager.md` §4).
- **Decision made on Option A vs B.** Don't switch mid-deployment; pick one.

---

## 4. Option A — Plug-in CA Certs

This is the simpler path. We issue a sub-CA from PyPKI, hand the cert + key to istiod via the magic Secret name `cacerts`, and let istiod do the rest.

### Step 1 — Issue the mesh sub-CA from PyPKI

```bash
export PYPKI_URL="https://pki.example.com"
export PYPKI_ADMIN_KEY="..."

curl -X POST "$PYPKI_URL/api/issue-sub-ca" \
    -H "Authorization: Bearer $PYPKI_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d @- <<EOF
{
  "subject": "CN=istio-mesh-sub-ca, O=Example Corp, OU=Mesh",
  "validity_days": 1095,
  "path_length": 0,
  "permitted_dns": [
    "svc.cluster.local",
    "svc",
    "cluster.local"
  ]
}
EOF
```

The response gives you `cert_pem`, `key_pem`, and the chain. Save them:

```bash
mkdir -p mesh-ca && cd mesh-ca
jq -r .cert_pem  ../response.json > ca-cert.pem
jq -r .key_pem   ../response.json > ca-key.pem
jq -r .chain_pem ../response.json > cert-chain.pem      # full chain (root + intermediate)
# The root by itself is needed too:
curl "$PYPKI_URL/api/ca-cert" -o root-cert.pem
chmod 0600 ca-key.pem
```

Istio's expected layout for the plug-in pattern is **four files** in a Secret named `cacerts`:

| File | What goes in it |
|---|---|
| `ca-cert.pem` | The intermediate (mesh sub-CA) cert |
| `ca-key.pem` | The intermediate's private key, PKCS#8 |
| `root-cert.pem` | The PyPKI root cert |
| `cert-chain.pem` | Intermediate + root concatenated (full chain) |

### Step 2 — Create the `cacerts` Secret in `istio-system`

```bash
kubectl create namespace istio-system
kubectl create secret generic cacerts -n istio-system \
    --from-file=ca-cert.pem=mesh-ca/ca-cert.pem \
    --from-file=ca-key.pem=mesh-ca/ca-key.pem \
    --from-file=root-cert.pem=mesh-ca/root-cert.pem \
    --from-file=cert-chain.pem=mesh-ca/cert-chain.pem
```

**The Secret name MUST be exactly `cacerts`** and **the file names MUST be exactly the four above**. istiod looks for these by literal string match — typos here are why this step fails most often.

### Step 3 — Install Istio

```bash
istioctl install --set profile=default -y
```

`istioctl` notices the `cacerts` Secret on startup and uses it instead of generating self-signed roots. Confirm with `istioctl x verify-install` after the pods are running.

### Step 4 — Verify

See [§6 below](#6-verifying-the-trust-chain).

---

## 5. Option B — cert-manager-istio-csr

This pattern keeps the sub-CA private key inside cert-manager (or, optionally, an external KMS via cert-manager's Vault Issuer). istiod's CSRs go to a cert-manager-istio-csr sidecar, which translates them into cert-manager `CertificateRequest` resources and returns the signed leaves.

### Step 1 — Set up the cert-manager `CA` Issuer

This is the same pattern as `docs/DEPLOYMENT/kubernetes-cert-manager.md` §§3-5. Issue a sub-CA from PyPKI, plant it in a Secret in `cert-manager`'s namespace, create a `ClusterIssuer`. The only difference is the name-constraint policy — for Istio, restrict it to `*.svc.cluster.local`:

```bash
curl -X POST "$PYPKI_URL/api/issue-sub-ca" \
    -H "Authorization: Bearer $PYPKI_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "subject": "CN=istio-csr-sub-ca, O=Example Corp",
      "validity_days": 1095,
      "path_length": 0,
      "permitted_dns": ["svc.cluster.local", "cluster.local"]
    }' > response.json

kubectl create secret tls istio-csr-sub-ca \
    -n cert-manager \
    --cert=<(jq -r .cert_pem response.json) \
    --key=<(jq -r .key_pem response.json)
```

```yaml
# istio-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: pypki-istio-issuer
spec:
  ca:
    secretName: istio-csr-sub-ca
```

```bash
kubectl apply -f istio-issuer.yaml
```

### Step 2 — Install cert-manager-istio-csr

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update

helm install cert-manager-istio-csr jetstack/cert-manager-istio-csr \
    --namespace cert-manager \
    --set "app.tls.rootCAFile=/var/run/secrets/istio-csr/ca.crt" \
    --set "app.certmanager.issuer.name=pypki-istio-issuer" \
    --set "app.certmanager.issuer.kind=ClusterIssuer" \
    --set "app.certmanager.issuer.group=cert-manager.io" \
    --set "app.server.serving.address=0.0.0.0" \
    --set "app.server.serving.port=6443"
```

The `cert-manager-istio-csr` Pod now runs and answers Istio's CSR requests by translating them into cert-manager `CertificateRequest` resources against `pypki-istio-issuer`.

### Step 3 — Install Istio with `istio-csr` integration

```bash
cat > istio-config.yaml <<EOF
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  profile: default
  values:
    pilot:
      env:
        # Disable istiod's built-in CA — istio-csr replaces it.
        ENABLE_CA_SERVER: "false"
    global:
      caAddress: cert-manager-istio-csr.cert-manager.svc:6443
EOF

istioctl install -f istio-config.yaml -y
```

### Step 4 — Verify

See [§6 below](#6-verifying-the-trust-chain).

---

## 6. Verifying the Trust Chain

Regardless of Option A or B, verify the result the same way. Deploy two test workloads, capture a leaf cert, walk the chain to PyPKI's root.

```bash
kubectl create namespace mesh-test
kubectl label namespace mesh-test istio-injection=enabled
kubectl run testpod --image=curlimages/curl -n mesh-test --command -- sleep 3600
kubectl wait --for=condition=Ready pod/testpod -n mesh-test --timeout=60s
```

Now extract the workload's mTLS cert from inside the sidecar:

```bash
kubectl exec -n mesh-test testpod -c istio-proxy -- \
    openssl s_client -connect localhost:15000 -showcerts < /dev/null 2>&1 \
    | openssl crl2pkcs7 -nocrl -certfile /dev/stdin \
    | openssl pkcs7 -print_certs -text \
    | grep -E "Subject:|Issuer:" \
    | head -20
```

You should see **three certs** chaining up:

```
Subject: ...spiffe://cluster.local/ns/mesh-test/sa/default
Issuer:  CN=istio-mesh-sub-ca, O=Example Corp           ← workload leaf

Subject: CN=istio-mesh-sub-ca, O=Example Corp
Issuer:  CN=Example Corp Root CA                        ← mesh sub-CA

Subject: CN=Example Corp Root CA
Issuer:  CN=Example Corp Root CA                        ← PyPKI root (self-signed)
```

If you see only two certs (workload + a self-signed root with `CN=Istio CA` or similar), the plug-in didn't take effect — istiod fell back to its built-in CA. Re-check the Secret name and file names.

---

## 7. Rotation

The mesh sub-CA expires (3 years in our examples). Plan rotation around 6 months before expiry.

### Option A rotation

1. Issue new mesh sub-CA from PyPKI, valid for another 3 years.
2. **Append** the new cert to `cert-chain.pem` and `root-cert.pem` (don't replace — both old and new must be trusted during the transition).
3. Update the `cacerts` Secret in `istio-system` with the new files.
4. Restart istiod: `kubectl rollout restart -n istio-system deploy/istiod`.
5. Workloads pick up new certs on their next renewal cycle (default ~12h in Istio).
6. After all workloads have rotated (verify by sampling), shrink the `cert-chain.pem` and `root-cert.pem` to contain only the new sub-CA.

### Option B rotation

cert-manager handles it. Issue a new sub-CA from PyPKI, update the `istio-csr-sub-ca` Secret, and cert-manager re-issues all leaves on their existing renewal schedule. No restart needed.

This is one of the operational reasons Option B is preferred: rotation is a planned database update rather than a control-plane restart.

---

## 8. Cross-Cluster mTLS

If you run multiple clusters and want **mesh-wide mTLS that works across cluster boundaries**, the trick is that all clusters' mesh sub-CAs must chain to the same PyPKI root. Issue one sub-CA per cluster from the same PyPKI:

```bash
for cluster in prod-us-east prod-eu-west prod-ap-south; do
    curl -X POST "$PYPKI_URL/api/issue-sub-ca" \
         -H "Authorization: Bearer $PYPKI_ADMIN_KEY" \
         -d "{\"subject\": \"CN=istio-$cluster, ...\", ...}" \
         > "${cluster}-subca.json"
done
```

Each cluster gets its own sub-CA but they all share the PyPKI root. Workloads in `prod-us-east` verify workloads in `prod-eu-west` because both their leaf certs chain back to the same root. Configure Istio multicluster as usual; the trust topology Just Works.

This is the single biggest operational win of having a real PKI behind your mesh: cross-cluster mTLS becomes a configuration question, not a "how do we federate trust" question.

---

## 9. Operational Notes

### istio-csr is a security boundary

In Option B, anyone with `update` on `CertificateRequest` resources in the namespaces istio-csr watches can theoretically request mesh-leaf certs. Lock RBAC down. The default Helm chart values are reasonable but worth reviewing in any production install.

### Don't roll your own CA per environment

Common anti-pattern: each cluster runs its own self-signed Istio root, plus PyPKI as the "real" CA, and the operator wires the two together with `DestinationRule` and `Secret`-juggling. **Don't.** Either let Istio be its own CA (and accept that mesh certs are mesh-only) or chain it to PyPKI from day one. The middle ground is operationally awful.

### Service mesh vs cert-manager — which protects what?

The mesh sub-CA in this guide is **specifically for workload-to-workload mTLS inside the mesh**. For ingress (cert-manager + Let's Encrypt or PyPKI ACME), workload-to-external (cert-manager `CA` Issuer per `docs/DEPLOYMENT/kubernetes-cert-manager.md`), and webhook certs (cert-manager `cainjector`), you'll have separate cert-manager `Certificate` flows. **All of them can share the PyPKI root** and that's the goal — one trust root, multiple issuance paths.

### Audit visibility

Option A: istiod logs only. PyPKI audit log shows the one sub-CA issuance event. Workload cert events are not in PyPKI's audit log.

Option B: Every `CertificateRequest` is a Kubernetes object with full audit trail. PyPKI audit log still only shows the sub-CA issuance, but cert-manager + the cluster API audit log together give per-leaf visibility. This is the regulated-environment-compatible answer.

### When to skip the mesh entirely

If your workload count is small (< a dozen), going straight to cert-manager + per-workload `Certificate` resources is simpler than running a mesh. Mesh is the right answer when (a) workload count makes per-workload config tedious, or (b) you actually need the L7 features (traffic policy, observability, fault injection) the mesh provides. mTLS alone isn't sufficient justification for the operational cost of a mesh; PyPKI + cert-manager handle that without one.

---

## 10. Troubleshooting

**`istioctl x verify-install` says CA root mismatch.**
The `cacerts` Secret was applied, but istiod was already running with self-signed roots from a previous install. Delete the istiod pods (`kubectl delete pod -n istio-system -l app=istiod`) so they restart and pick up the Secret.

**Workload certs still chain to `istiod` self-signed root.**
The `cacerts` Secret name or file names are wrong. They're case-sensitive and exact: `cacerts`, `ca-cert.pem`, `ca-key.pem`, `root-cert.pem`, `cert-chain.pem`. No variations.

**Option B: `cert-manager-istio-csr` Pod CrashLoopBackoff.**
Usually the `--issuer-name` / `--issuer-kind` Helm values don't match an actual Issuer/ClusterIssuer in the cluster. Check `kubectl get clusterissuer pypki-istio-issuer -o yaml` exists and `Ready: True`.

**Mesh-to-non-mesh mTLS fails with "x509: certificate signed by unknown authority".**
The non-mesh side doesn't have the PyPKI root in its trust store. This is the trust-distribution piece — see `docs/DEPLOYMENT/kubernetes-cert-manager.md` §8.

**SPIFFE IDs in workload certs are missing.**
Istio's CSR includes a `URI:spiffe://...` SAN. PyPKI passes `DNS`, `IPAddress`, and `RFC822Name` SANs through to issued certs; URI SAN pass-through requires the `san_uris` parameter on `issue_certificate`, which is tracked as follow-up work. Until that lands, Option B is preferred for Istio (cert-manager-istio-csr handles the URI SAN injection differently and works around this gap).

**`istioctl proxy-status` shows STALE for some Pods.**
Probably unrelated to PKI. Check the Pod's istio-proxy logs. If the only error is cert-related, look for cert-manager issuance failures in `kubectl describe certificaterequest -A`.

**Cross-cluster mTLS fails after adding a third cluster.**
Each cluster needs its own sub-CA chained to the shared PyPKI root, and each cluster's istiod (or istio-csr) needs to know about the **shared root cert** as a trust anchor. The intermediate certs are cluster-specific; only the root is shared. Misconfiguring this — distributing all sub-CA certs to all clusters — usually works but is unnecessary complexity.

---

## See also

- `docs/DEPLOYMENT/kubernetes-cert-manager.md` — the cert-manager basics this guide builds on.
- `docs/CPS.md` §7.1 — what the mesh sub-CA cert actually contains.
- `docs/THREAT_MODEL.md` §4 — what an attacker who steals the mesh sub-CA private key can and cannot do.
- Istio docs: https://istio.io/latest/docs/tasks/security/cert-management/
- cert-manager-istio-csr: https://github.com/cert-manager/istio-csr
- SPIFFE: https://spiffe.io — the workload-identity spec Istio implements.
