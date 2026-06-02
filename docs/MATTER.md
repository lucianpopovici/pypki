# PyPKI Matter Device Attestation

<!-- Last reviewed: 2026-06-02 -->

PyPKI acts as a Matter Product Attestation Authority (PAA) / Intermediate
(PAI) and issues Device Attestation Certificates (DACs) per the Matter Core
Specification §6.2.2.

**Thread credentials** (commissioning tokens) are out of scope — they are
short-lived setup tokens distinct from manufacturing DACs.

---

## Certificate hierarchy

```
PAA (self-signed, registered in CSA DCL)
 └─ PAI (per vendor/product line)
     └─ DAC (per device, burned at manufacturing)
```

| Role | BC       | Path len | Key usage        | EKU | CRL/OCSP |
|------|----------|----------|------------------|-----|----------|
| PAA  | CA=true  | 1        | keyCertSign+crlSign | none | none |
| PAI  | CA=true  | 0        | digitalSig+keyCertSign+crlSign | none | none |
| DAC  | CA=false | —        | digitalSignature | none | none |

All keys must be **ECDSA P-256**. No SANs on any level.

---

## Matter-specific OIDs in Subject DN

| OID                        | Name      | Value format    |
|----------------------------|-----------|-----------------|
| `1.3.6.1.4.1.37244.2.1`   | VendorID  | 4-hex chars, e.g. `FFF1` |
| `1.3.6.1.4.1.37244.2.2`   | ProductID | 4-hex chars, e.g. `8000` |

---

## Issuing a DAC

```bash
curl -X POST https://pki.example.com/api/matter/dac \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_id":      "0xFFF1",
    "product_id":     "0x8000",
    "subject_serial": "ABCD1234EFGH5678",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "valid_years":    10
  }'
```

Response: `{ "cert_serial": "...", "pem": "<DAC PEM>" }`

---

## Issuing a PAI

```bash
curl -X POST https://pki.example.com/api/matter/pai \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name":        "Acme Lightbulbs Q3 2026",
    "vendor_id":   "0xFFF1",
    "product_ids": ["0x8000", "0x8001"],
    "valid_years": 20
  }'
```

Response includes `cert_pem` and `private_key_pem` (PAI key, returned once).

---

## Bulk DAC issuance (manufacturing line)

POST a JSON object with `vendor_id`, `product_id`, and an `items` array:

```bash
curl -X POST https://pki.example.com/api/matter/dac/bulk \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_id":  "0xFFF1",
    "product_id": "0x8000",
    "items": [
      {"subject_serial": "S001", "public_key_pem": "..."},
      {"subject_serial": "S002", "public_key_pem": "..."}
    ]
  }'
```

Response is NDJSON (one JSON object per line), streamed as issuance proceeds.

CLI bulk tool:

```bash
pypki_admin matter-dac-bulk-issue \
  --vendor-id FFF1 --product-id 8000 \
  --input-file devices.json \
  --output-file dacs.ndjson \
  --valid-years 10
```

Input file format: JSON array of `{subject_serial, public_key_pem}`.

---

## CSA DCL registration

v1 does not submit to the CSA Distributed Compliance Ledger automatically.
Submit your PAA out-of-band following the CSA's onboarding process. Include
the PAA's `cert_serial` and PEM in your DCL submission.

---

## Admin CLI

```bash
# List registered PAA/PAI authorities
pypki_admin matter-paa-list
```
