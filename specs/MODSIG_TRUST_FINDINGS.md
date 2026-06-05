# MODSIG_TRUST_FINDINGS.md — Module-Signing Trust Model

## 1. Verdict

**Per-CA module trust IS achievable** on Linux 6.19.10 when the signer certificate is
embedded in the PKCS#7 by dropping the `CMS_NOCERTS` flag from `sign-file`.

| Gate | Condition | Result | dmesg |
|------|-----------|--------|-------|
| E0 (control) | Stock `sign-file` (`CMS_NOCERTS`), leaf NOT in keyring | **FAIL** exit=1 | `Loading of module with unavailable key is rejected` |
| E1 (test) | Patched `sign-file` (cert embedded), leaf NOT in keyring | **PASS** exit=0 | `hello: loaded (ima-evm-harness test module)` |

Kernel tested: `Linux version 6.19.10-300.fc44.x86_64` (custom Fedora build).
PyPKI Root CA in `.builtin_trusted_keys` (key id `3882c9169ffab6a7a23ef495eededdec16bb3552`).
Leaf cert verified absent from all trusted keyrings before E1 (`keyctl list` count = 0 for both
`.builtin_trusted_keys` and `.secondary_trusted_keys`).

---

## 2. Strand 1 — Kernel source basis

### 2.1 `scripts/sign-file.c` — flag expression

Anchor: `CMS_NOCERTS` (lines 320, 325, 329 in `linux-6.19.10/scripts/sign-file.c`):

```c
cms = CMS_sign(NULL, NULL, NULL, NULL,
               CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY |
               CMS_DETACHED | CMS_STREAM);
ERR(!cms, "CMS_sign");

ERR(!CMS_add1_signer(cms, x509, private_key, digest_algo,
                     CMS_NOCERTS | CMS_BINARY |
                     CMS_NOSMIMECAP | use_keyid |
                     use_signed_attrs),
    "CMS_add1_signer");
ERR(CMS_final(cms, bm, NULL, CMS_NOCERTS | CMS_BINARY) != 1,
    "CMS_final");
```

`CMS_NOCERTS` on `CMS_add1_signer()` is the operative flag: it prevents the signer
certificate from being embedded in the SignedData certificates field. With this flag the
PKCS#7 carries only the signature and a `signerIdentifier` (IssuerAndSerialNumber or SKID);
there is no cert chain to walk.

### 2.2 `crypto/asymmetric_keys/pkcs7_verify.c:pkcs7_find_key` — signer linkage

Anchor: `sinfo->signer = x509` (line 177):

```c
static int pkcs7_find_key(struct pkcs7_message *pkcs7,
                          struct pkcs7_signed_info *sinfo)
{
    struct x509_certificate *x509;
    for (x509 = pkcs7->certs; x509; x509 = x509->next, certix++) {
        if (!asymmetric_key_id_same(x509->id, sinfo->sig->auth_ids[0]))
            continue;
        sinfo->signer = x509;   /* ← only set if cert is embedded */
        return 0;
    }
    /* If not found, sinfo->signer stays NULL */
    return 0;
}
```

With `CMS_NOCERTS`: `pkcs7->certs` is empty → `sinfo->signer = NULL`.
Without `CMS_NOCERTS`: embedded cert is matched → `sinfo->signer` = leaf cert object.

### 2.3 `crypto/asymmetric_keys/pkcs7_trust.c:pkcs7_validate_trust_one` — trust walk

Anchor: `pkcs7_validate_trust` (function):

The function walks `sinfo->signer` through the embedded cert chain, then attempts a
root-match using the last cert's AKI fields (`last->sig->auth_ids[0/1]`):

```c
/* Walk embedded chain */
for (x509 = sinfo->signer; x509; x509 = x509->signer) {
    key = find_asymmetric_key(trust_keyring, x509->id, x509->skid, NULL, false);
    if (!IS_ERR(key)) goto matched;          /* cert itself is trusted */
    if (x509->signer == x509) return -ENOKEY; /* self-signed root, not trusted */
    last = x509;
    sig = last->sig;
}

/* After loop: check if the issuer (root) is trusted via the last cert's AKI */
if (last && (last->sig->auth_ids[0] || last->sig->auth_ids[1])) {
    key = find_asymmetric_key(trust_keyring,
                              last->sig->auth_ids[0],
                              last->sig->auth_ids[1], NULL, false);
    if (!IS_ERR(key)) { x509 = last; goto matched; }  /* root found */
}
```

With `CMS_NOCERTS` (`sinfo->signer = NULL`): loop never runs; `last = NULL`; falls to
final `find_asymmetric_key(trust_keyring, sinfo->sig->auth_ids[0], NULL, NULL, false)`
which matches only if the leaf cert itself is in the keyring → per-leaf required.

With embedded cert (`sinfo->signer = leaf`): loop runs once (leaf not in keyring, not
self-signed); `last = leaf`; AKI match looks up root → root found in builtin keyring →
`verify_signature(root_key, leaf_sig)` → chain verified → module loads.

The `auth_ids[1]` slot is populated by `x509_akid_note_kid()` in
`crypto/asymmetric_keys/x509_cert_parser.c:772` from the AKI `keyIdentifier` field.
`find_asymmetric_key` checks both `auth_ids[0]` (IssuerAndSerial) and
`auth_ids[1]` (keyIdentifier/SKID) — a match on either is sufficient.

### 2.4 `kernel/module/signing.c:mod_verify_sig` — keyring selection

Anchor: `verify_pkcs7_signature` (line 64):

```c
return verify_pkcs7_signature(mod, modlen, mod + modlen, sig_len,
                              VERIFY_USE_SECONDARY_KEYRING,
                              VERIFYING_MODULE_SIGNATURE,
                              NULL, NULL);
```

`VERIFY_USE_SECONDARY_KEYRING` resolves to `.secondary_trusted_keys` in
`certs/system_keyring.c`. That keyring links to `.builtin_trusted_keys` on init
(`key_link(secondary_trusted_keys, builtin_trusted_keys)`), so keys compiled into the
kernel (from `CONFIG_SYSTEM_TRUSTED_KEYS`) are reachable.

---

## 3. Strand 2 — PyPKI AKI status

Anchor: `pki_server.py:2486`

```python
.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
    critical=False,
)
```

This line is in `issue_certificate()` and executes unconditionally for all profiles,
including `code_signing`. The `from_issuer_public_key()` builder adds the AKI
`keyIdentifier` field derived from the CA's public key. This is the value the kernel
reads as `auth_ids[1]` when parsing the leaf cert's AKI extension.

**AKI match confirmed** (experiment signing cert):
- Leaf AKI keyIdentifier: `38:82:C9:16:9F:FA:B6:A7:A2:3E:F4:95:EE:DE:DD:EC:16:BB:35:52`
- Root SKID: `38:82:C9:16:9F:FA:B6:A7:A2:3E:F4:95:EE:DE:DD:EC:16:BB:35:52` ✓

**Status**: AKI is present on `code_signing` leaves. No PyPKI gap.

---

## 4. Recipes

### 4A — Per-CA recipe (patched `sign-file`, cert embedded)

Patch `scripts/sign-file.c` — remove `CMS_NOCERTS` from the three CMS calls:

```diff
- cms = CMS_sign(NULL, NULL, NULL, NULL,
-                CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY |
-                CMS_DETACHED | CMS_STREAM);
+ cms = CMS_sign(NULL, NULL, NULL, NULL,
+                CMS_PARTIAL | CMS_BINARY |
+                CMS_DETACHED | CMS_STREAM);

- ERR(!CMS_add1_signer(cms, x509, private_key, digest_algo,
-                      CMS_NOCERTS | CMS_BINARY |
-                      CMS_NOSMIMECAP | use_keyid |
-                      use_signed_attrs),
+ ERR(!CMS_add1_signer(cms, x509, private_key, digest_algo,
+                      CMS_BINARY |
+                      CMS_NOSMIMECAP | use_keyid |
+                      use_signed_attrs),

- ERR(CMS_final(cms, bm, NULL, CMS_NOCERTS | CMS_BINARY) != 1,
+ ERR(CMS_final(cms, bm, NULL, CMS_BINARY) != 1,
```

Rebuild: `make scripts/sign-file` in the kernel source tree.

Sign a module:
```bash
scripts/sign-file sha512 leaf_key.pem leaf_cert.der my_module.ko
```

**Trust setup**: enroll the CA root cert once into the kernel's builtin trusted keys
(`CONFIG_SYSTEM_TRUSTED_KEYS="ca_root.pem"`) or into `.secondary_trusted_keys` via
`keyctl padd`. No per-leaf enrollment needed.

**Verify cert is embedded** (sanity check):
```bash
python3 - <<'EOF'
import struct, subprocess, sys, tempfile, os
data = open(sys.argv[1], 'rb').read()
marker = b'~Module signature appended~\n'
body = data[:-len(marker)]
sig_len = struct.unpack('>I', body[-12:][8:12])[0]
pkcs7 = body[-(12 + sig_len):-12]
with tempfile.NamedTemporaryFile(suffix='.p7b', delete=False) as f:
    f.write(pkcs7); name = f.name
r = subprocess.run(['openssl','pkcs7','-inform','DER','-print_certs','-noout','-in',name],
                   capture_output=True, text=True)
print(r.stdout or "(no certs embedded)")
os.unlink(name)
EOF
my_module.ko
```

### 4B — Per-leaf recipe (stock `sign-file`, leaf enrolled)

Stock `sign-file` with `CMS_NOCERTS` (unmodified kernel tool):

```bash
scripts/sign-file sha512 leaf_key.pem leaf_cert.der my_module.ko
```

**Trust setup**: enroll the signing leaf certificate at runtime:
```bash
keyctl padd asymmetric "" %:.secondary_trusted_keys < leaf_cert.der
```
Or persistently via `update-ca-trust` / mokutil (Secure Boot Mok path) depending
on the deployment model.

The leaf must be enrolled on every machine that loads the module. Rotation requires
re-enrolling the new leaf everywhere.

---

## 5. Security tradeoff

**This is a documented choice, not a clear recommendation.**

| Dimension | Per-CA (embed cert, root trusted) | Per-leaf (stock sign-file, leaf enrolled) |
|-----------|-----------------------------------|-------------------------------------------|
| Blast radius | Any `code_signing` leaf the CA ever issues can load modules — bound only to the CA trust decision | Exactly the enrolled leaves — narrow and explicit |
| Operational cost | Enroll CA root once (build-time or boot-time); no per-module-signer enrollment | Enroll each signing leaf on each machine; rotation requires re-enrollment |
| Revocation | CA-level revocation (compromise of root = revoke everything) | Leaf-level (remove one leaf from keyring without disturbing others) |
| Why distros ship `CMS_NOCERTS` | Per-leaf pinning is almost certainly the deliberate security choice: the blast radius of CA trust for module loading is very broad | The default |

**Recommendation framing**: per-CA is appropriate for closed environments where the CA
issuing `code_signing` certs is tightly controlled (e.g., internal PyPKI deployment,
one CA = one organizational trust domain). Per-leaf is appropriate where multiple teams
or tenants share the same CA and should not implicitly trust each other's signed modules.
PyPKI can support both modes; the choice is a deployment policy decision.

---

## 6. Product implication

Leaf-enrollment tooling is **required regardless**: IMA appraisal (per the F2-BUILTIN
run, established fact) is inherently per-leaf — IMA sig v2 carries the leaf SKID and
the kernel matches it against a key that must be present in `.ima`. There is no chain
appraisal for IMA. The enrollment distribution tooling must therefore support
leaf-cert delivery to target systems for IMA in all cases.

For module signing, the E1 result establishes that CA-root enrollment **can** eliminate
the per-leaf enrollment burden for modules specifically, provided operators accept the
broader trust scope. A practical offering would ship both:

- **`--modsig-trust-mode ca`**: patched `sign-file` + one-time root enrollment in EFI/MoK.
- **`--modsig-trust-mode leaf`** (default): stock `sign-file` + per-leaf enrollment
  automation using the same tooling already required for IMA.

---

## 7. Metadata

| Item | Value |
|------|-------|
| Kernel tested | `6.19.10-300.fc44.x86_64` |
| Kernel build | `linux-6.19.10/arch/x86/boot/bzImage` |
| `CONFIG_MODULE_SIG` | `y` |
| `CONFIG_MODULE_SIG_FORCE` | not set (enforced via `module.sig_enforce=1` cmdline) |
| `CONFIG_SYSTEM_TRUSTED_KEYS` | `certs/combined_trusted_keys.pem` (contains PyPKI Root CA) |
| Trusted root key id | `3882c9169ffab6a7a23ef495eededdec16bb3552` |
| Signing leaf serial | `4e:aa:47:0a:5a:de:ea:d0:89:bb:e0:75:58:69:58:12:5e:0f:26:6a` |
| sign-file E1 patch | `CMS_NOCERTS` removed from `CMS_sign()`, `CMS_add1_signer()`, `CMS_final()` |
| E0 result | exit=1 — `insmod: ERROR: Key was rejected by service` |
| E1 result | exit=0 — `hello: loaded (ima-evm-harness test module)` |
| E1 leaf in keyring before test | 0 (confirmed via `keyctl list`) |
| Experiment date | 2026-06-05 |
