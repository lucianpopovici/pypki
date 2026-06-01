# Manual Interop Runbook

Some interop tests can't be automated cheaply. This runbook documents the
manual procedure for each. Re-run at least once per minor release.

## SCEP + Microsoft NDES

**Status**: Known gap — no automated test planned.

**Setup**:
1. Windows Server 2019+ with AD CS and NDES role installed.
2. Configure NDES to point at a PyPKI CA (export CA cert from PyPKI,
   import into NDES as the CA certificate).
3. A Windows 10/11 test client with MDM enrollment enabled.

**Test procedure**:
1. From the test client, trigger SCEP enrollment via MDM profile.
2. Verify the cert appears in `certmgr.msc` with correct CN and SAN.
3. Check PyPKI audit log for the enrollment event.

**Expected behavior**: Cert issued successfully, chain verifies.

**Known quirks**: None documented yet.

**Last tested**: Not yet run.

---

## S/MIME — Thunderbird

**Setup**:
1. Thunderbird 115+.
2. PyPKI configured with an `email_signing` profile.
3. Issue an S/MIME cert for `alice@example.com` from PyPKI.
4. Import the cert + private key (PKCS#12) into Thunderbird's cert store.
5. Import the PyPKI CA cert into Thunderbird as a trusted CA.

**Test procedure**:
1. Compose a signed email in Thunderbird, send to self.
2. Open the received email; verify signature badge shows "Valid".
3. Compose an encrypted email (to alice@example.com) using the cert.
4. Verify decryption works.

**Expected behavior**: Signed email shows "Digitally Signed Message" with
green checkmark. Encrypted email decrypts cleanly.

**Screenshots**: (paste screenshots of successful run here)

**Last tested**: Not yet run.

---

## S/MIME — Outlook (Microsoft 365)

**Setup**:
1. Outlook 365 (Windows or web).
2. S/MIME control installed in Outlook desktop.
3. PyPKI CA cert trusted in Windows Certificate Store.
4. `email_signing` cert for the test user's email address.

**Test procedure**:
1. Send a signed email; verify recipient sees "Signed by" indication.
2. Send an encrypted email; verify recipient can decrypt.

**Last tested**: Not yet run.

---

## CMP + EJBCA

**Setup**:
1. EJBCA Community 8.x Docker image.
2. Configure EJBCA as a CMP client pointing to PyPKI.

**Test procedure**: TBD.

**Last tested**: Not yet run.

---

## EST + Cisco IOS XE

**Setup**: Cisco IOS XE lab device (requires hardware or VIRL).

**Test procedure**: TBD.

**Last tested**: Not yet run.
