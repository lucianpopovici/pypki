# Fuzz Corpus

Each subdirectory holds seed inputs for one fuzz target.

## Populating the corpus

Run once before the first fuzz session:

```bash
python3 fuzz/setup_corpus.py
```

This generates minimal valid DER inputs from der_codec primitives. Existing
files are not overwritten (use `--overwrite` to force).

## Seeding from real clients (recommended)

After the interop suite runs (Tier 6.2), copy captured request bodies into
the relevant corpus directory:

```bash
# After an sscep enroll:
cp interop/scep/_captures/enroll_request.der fuzz/corpus/scep_envelope/
# After openssl cmp ir:
cp interop/cmp/_captures/ir_request.der fuzz/corpus/cmp_pkimessage/
```

Real client inputs make the corpus far more effective than hand-crafted seeds.

## Regression inputs

`regressions/` holds inputs that triggered crashes in past fuzz runs.
**Never delete files from this directory.** They are permanent regression
guards: each one has a corresponding test in `test_pki_server.py` under
`TestTier6Fuzz<area>`.

## Corpus size limits

Each seed file must be ≤ 4 KiB. Larger inputs slow fuzzer throughput
significantly. The stdlib runner's mutation engine works best on inputs
between 16 and 512 bytes.

## Subdirectories

| Directory        | Harness                        | Target parser                   |
| ---------------- | ------------------------------ | ------------------------------- |
| `tlv_primitive/` | `harness_tlv.py`               | `der_codec.decode_tlv`          |
| `scep_envelope/` | `harness_scep_envelope.py`     | `CMSParser.parse_signed_data`   |
| `cmp_pkimessage/`| `harness_cmp_pkimessage.py`    | `CMPv2ASN1.parse_pki_message`   |
| `crmf_popo/`     | `harness_crmf_popo.py`         | `CMPv2ASN1.parse_crmf` + POPO   |
| `est_csr/`       | `harness_est_csr.py`           | `ESTHandler._decode_csr`        |
| `ocsp_request/`  | `harness_ocsp_request.py`      | `OCSPRequestParser.parse`       |
| `tsa_request/`   | `harness_tsa_request.py`       | `TSARequestParser.parse`        |
| `mldsa_roundtrip/`| `harness_mldsa_roundtrip.py`  | ML-DSA TBSCertificate builder   |
| `regressions/`   | (all)                          | Crash reproducers — never delete|
