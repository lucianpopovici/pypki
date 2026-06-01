# PyPKI Offline Root CA Ceremony Script

> Last reviewed: 2026-06-01 (commit 453e7ba)

This document is the operator script for:

1. **Initial root export**: packaging the offline root CA key + cert into an encrypted
   bundle, optionally with Shamir M-of-N share splitting.
2. **Shamir share ceremony**: distributing shares to share-holders in a controlled setting.
3. **Recovery**: reconstituting the bundle passphrase from shares to perform a
   high-value operation (issue a new intermediate, revoke the old one).

Read this document end-to-end before the ceremony. Assign roles before you start.

---

## Roles

| Role | Responsibility |
|---|---|
| **Ceremony Officer** | Runs the ceremony host machine; types commands |
| **Share-holder 1..N** | Receives and safeguards one Shamir share each |
| **Witness** | Observes and countersigns the ceremony log |
| **Security Officer** | Approves the operation and verifies the outcome |

Minimum for a 3-of-5 ceremony: Ceremony Officer + 5 share-holders + 1 Witness.

---

## Prerequisites

- Air-gapped (or network-isolated) machine with PyPKI installed
- USB drive for share-holder cards (printed QR + word mnemonic)
- PyPKI running on the online intermediate host (to export the CSR and import the cert)
- Ceremony log: a signed paper log for the Witness

---

## Part 1: Initial root export

### 1.1 Verify the CA directory

```bash
ls -la /var/lib/pypki/ca/
# Must contain: ca.key, ca.crt, certificates.db
```

### 1.2 Export with Shamir splitting

```bash
python pypki_admin.py ca-init \
    --ca-dir /var/lib/pypki/ca \
    --out /media/usb-secure/root-bundle-$(date +%Y%m%d).tar.gz.enc \
    --shamir 3-of-5
```

The tool prints 5 share strings, e.g.:

```
Shamir 3-of-5 shares (distribute securely):
  Share 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  Share 2: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
  Share 3: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
  Share 4: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
  Share 5: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=

Bundle: /media/usb-secure/root-bundle-20260525.tar.gz.enc (1234 bytes)
```

**Each share is a base64-encoded string.** Ceremony Officer reads each share aloud;
the corresponding share-holder writes it down on their card (or scans it from the
screen as a QR code if you have a QR printer).

**Critical:** The share strings are never written to disk on the ceremony host.
The tool prints them to the terminal only. Once the terminal is cleared, they are gone.
Verify each share-holder has their share before proceeding.

### 1.3 Convert shares to mnemonic words (recommended for paper backup)

```python
# Run on the ceremony host immediately after share generation
import shamir, mnemonic, base64

share_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # replace with actual share
x, y = shamir.decode_share(share_str)
words = mnemonic.encode(y)
print(f"Share {x}: {' '.join(words)}")
# Example: "abandon ability able about above absent absorb abstract ..."
# 34 words for a 32-byte share (32 data + 2 checksum)
```

Print the word list on the share-holder card. Include:
- Share index (1 of 5, etc.)
- Ceremony date
- Threshold required (e.g. "3 of 5 shares needed")
- The word list
- Witness signature line

### 1.4 Verify the bundle can be opened

```bash
# Collect M=3 shares from 3 of the 5 share-holders
python pypki_admin.py ca-recover \
    --bundle /media/usb-secure/root-bundle-20260525.tar.gz.enc \
    --csr-in /tmp/test.csr \
    --cert-out /tmp/test.crt \
    --shares 3
# Enter 3 share strings when prompted.
# If this succeeds, the shares are valid and the bundle is intact.
```

If the test issuance succeeds, shred `/tmp/test.crt` and clear the terminal.

### 1.5 Store the bundle

The encrypted bundle (`root-bundle-*.tar.gz.enc`) should be stored in at least two
physically separate locations:

- Primary: offline USB drive in a locked safe (on-premises)
- Secondary: encrypted USB drive at a second location (off-site)

The bundle is only useful if someone also has ≥ M shares. Without M shares, the
bundle's passphrase cannot be reconstructed.

### 1.6 Ceremony log entry

```
Date: 2026-05-25
Operation: Initial root export + Shamir 3-of-5 split
Bundle location: [REDACTED — logged separately]
Share holders: Alice (1), Bob (2), Carol (3), Dave (4), Eve (5)
Witness: Frank
Security Officer: Grace
Hash of bundle: sha256:<hex>
```

---

## Part 2: Signing a new sub-CA certificate (recovery ceremony)

### Trigger

The online intermediate CA key has been compromised (see Scenario 3 in `docs/DR.md`),
or the intermediate certificate is expiring and needs renewal.

### 2.1 Convene the share-holders

Contact M share-holders (minimum 3 in a 3-of-5 scheme). They must be present
in person or on a verified video call (not via email — share strings must not
be transmitted electronically except over an encrypted channel the share-holder
controls).

### 2.2 Prepare the new intermediate CSR

On the PyPKI host (online):

```bash
# Generate new CA key
openssl ecparam -name prime256v1 -genkey -noout \
    -out /var/lib/pypki/ca/ca-new.key
chmod 600 /var/lib/pypki/ca/ca-new.key

# Generate CSR
openssl req -new \
    -key /var/lib/pypki/ca/ca-new.key \
    -subj "/CN=PyPKI Intermediate CA 2026/O=Example Corp/C=US" \
    -out /tmp/intermediate-2026.csr.pem
```

Transfer `intermediate-2026.csr.pem` to the ceremony host via a read-only USB drive.

### 2.3 Run the recovery ceremony

On the ceremony host:

```bash
python pypki_admin.py ca-recover \
    --bundle /media/usb-secure/root-bundle-20260525.tar.gz.enc \
    --csr-in /media/usb-transfer/intermediate-2026.csr.pem \
    --cert-out /media/usb-transfer/intermediate-2026.crt.pem \
    --shares 3

# Prompts:
# Share 1/3: <Alice reads her share aloud; Ceremony Officer types it>
# Share 2/3: <Bob reads his share>
# Share 3/3: <Carol reads hers>
```

If ≥ 3 valid shares are provided, the tool reconstructs the passphrase in memory,
decrypts the bundle, and signs the CSR. No share string is written to disk.

### 2.4 Verify the issued certificate

```bash
openssl x509 -in /media/usb-transfer/intermediate-2026.crt.pem -text -noout
# Check:
#   Issuer: CN=PyPKI Root CA (should match the offline root)
#   Subject: CN=PyPKI Intermediate CA 2026
#   CA:TRUE
#   Path Length Constraint: 0
#   Not Before / Not After: correct dates
```

### 2.5 Import the certificate into the online CA

Transfer `intermediate-2026.crt.pem` to the PyPKI host and import it:

```bash
python pypki_admin.py import-cert \
    --ca-dir /var/lib/pypki/ca \
    --cert-in /tmp/intermediate-2026.crt.pem
```

Then rename the new key to the active CA key:

```bash
mv /var/lib/pypki/ca/ca.key /var/lib/pypki/ca/ca.key.revoked-$(date +%Y%m%d)
mv /var/lib/pypki/ca/ca-new.key /var/lib/pypki/ca/ca.key
systemctl restart pypki
```

### 2.6 Clear ceremony artifacts

On the ceremony host:

```bash
# Clear the terminal (removes share strings from scrollback)
clear; history -c

# Shred any temp files
shred -u /tmp/intermediate-2026.csr.pem 2>/dev/null || true
```

### 2.7 Ceremony log entry

```
Date: 2026-06-01
Operation: Recovery ceremony — new intermediate CA issuance
Share holders present: Alice (1), Bob (2), Carol (3)
Shares used: 3 of 5
New cert serial: <hex>
New cert SHA-256: <hex>
Witness: Frank
Security Officer: Grace
```

---

## Mnemonic share recovery

If a share-holder has lost their original base64 string but still has the paper
word list, they can reconstruct the share:

```python
import mnemonic, shamir

words = "abandon ability able about ...".split()  # their 34-word list
y = mnemonic.decode(words)  # validates CRC-16 checksum
x = 1  # their share index (printed on the card)
encoded = shamir.encode_share(x, y)
print("Reconstructed share:", encoded)
```

If `mnemonic.decode()` raises `ValueError`, the word list has a transcription error.
The share-holder must check each word carefully against the BIP-39 wordlist.

---

## Security properties

- **M-of-N information-theoretic security:** Any M−1 shares reveal nothing about the
  passphrase. An attacker who compromises M−1 share-holders gains zero information.
- **CRC-16 checksum in mnemonic encoding:** Detects single-word transcription errors
  with very high probability (65535/65536 detection rate per corrupted word).
- **Shares never written to disk:** The `ca-init` command prints shares to stdout only.
  Terminal history should be cleared after the ceremony.
- **Bundle encryption:** The bundle itself is AES-256-GCM encrypted with a 32-byte
  random passphrase derived from the Shamir shares. Without M shares, the bundle is
  computationally opaque.
