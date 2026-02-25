# PU-CP-ABE: IoT-Cloud Hybrid Access Control System

> **Based on:** "IoT-Cloud Data Sharing and Access Control System with Efficient Policy Updating."
> 
>
> This is a **real-world proof-of-concept** of the paper's scheme, adapted for AWS deployment.
> The paper's pure-ABE construction is restructured as a **hybrid encryption system**:
> AES-GCM encrypts the actual data; the custom PU-CP-ABE scheme encrypts only the 32-byte DEK.

---

## Why Hybrid Encryption?

ABE schemes based on bilinear pairings operate on group elements, not arbitrary byte strings. In practice:

```
Paper (theoretical):   ABE.Enc(M,  mpk, T)  ← encrypts message directly
This project:          AES-GCM.Enc(M,  DEK) ← encrypts message (fast, any size)
                       ABE.Enc(DEK, mpk, T) ← encrypts only the 32-byte key
```

This is the standard pattern for all real-world ABE deployments. Breaking confidentiality of M still requires breaking the ABE ciphertext to recover DEK — the security guarantee is unchanged.

---

## Why Docker on AWS Lambda?

AWS Lambda's standard Python runtime cannot install C extensions at deploy time. The PBC pairing library (and its GMP dependency) must be compiled for `x86_64 Linux` and bundled with the code. A Docker container image is the cleanest solution and is natively supported by Lambda Container Image support.

**Cold-start note:** The first invocation after a period of inactivity takes ~5–6 s (container load from ECR). Subsequent warm invocations run in ~130 ms. Enable **Provisioned Concurrency** to eliminate cold starts in production.

---

## Technical Stack
 
| Layer | Technology | Notes |
|---|---|---|
| ABE scheme | Custom PU-CP-ABE (this paper) | Policy-update capability |
| Pairing library | **PBC** (C, compiled in Docker) | Python has no native pairing |
| Python bindings | **charm-crypto** | Wraps PBC for Python |
| Big integers | **GMP** (C, compiled in Docker) | Required by PBC |
| Symmetric encryption | **AES-256-GCM** (`cryptography` lib) | Encrypts actual data M |
| Runtime | **Docker on AWS Lambda** | PBC must be pre-compiled |
| Storage | **AWS S3** | Ciphertexts; triggers Lambda |

---

## File Reference

| File | Lines | Role |
|---|---|---|
| `ta_local.py` | 1195 | **Core**: ThresholdABE, UPKeyGen, CTUpdate, serialize helpers, CLI |
| `lambda_encrypt.py` | ~150 | Cloud encrypt: full ABE+AES-GCM hybrid, local CLI entry |
| `client_decrypt.py` | ~170 | Client decrypt: ABE→KDF→AES-GCM, local CLI entry |
| `cloud_update.py` | ~200 | Policy update: UPKeyGen+CTUpdate, writes new version |
| `app.py` | ~40 | **Lambda entry point** (deployed): S3→AES-GCM only demo |
| `object_store.py` | ~50 | FileObjectStore: versioned JSON files, PoC for S3 |
| `crypto_core.py` | ~100 | Test helper: subprocess wrappers for encrypt/decrypt |
| `bench_local.py` | ~40 | Benchmark skeleton (imports `ade_abe`, needs wiring) |
| `Dockerfile` | ~65 | Container: Python 3.10 + GMP + PBC + charm-crypto |
| `event.json` | 1 | Test S3 event payload for local Lambda testing |
| `requirements.txt` | 3 | `boto3`, `cryptography<41`, `pyparsing` |
| `requirements-dev.txt` | 2 | `pytest==8.3.3`, `pytest-cov==5.0.0` |

```
keys/                 ← local key storage (never commit to git)
  ta_setup.json       {curve, ell, mpk, msk}
  user_sk.json        {curve, ell, attrs, policy, sk}
  store/<uuid>/
    v1.json           initial encrypt result
    v2.json           after policy update
    latest.json       {"latest_version": N}

tests/
  conftest.py
  test_encrypt_basic.py
  test_client_decrypt_e2e.py
  test_crypto_core.py
```

---


## Cryptographic Workflow 

### 1. TA Setup

```bash
python ta_local.py setup --curve SS512 --ell 10 --out keys/ta_setup.json
# writes: keys/ta_setup.json  →  {curve, ell, mpk, msk}
# ⚠ contains msk — never upload to S3 or include in Docker image
```

### 2. Issue User Key

```bash
python ta_local.py keygen \
    --inp    keys/ta_setup.json \
    --attrs  "attA,attB" \
    --policy "(attA OR attB)" \
    --out    keys/user_sk.json
# delivers to user out-of-band (not via S3)
```

### 3. Cloud Encrypt (local CLI — full ABE path)

```bash
python lambda_encrypt.py \
    --setup     keys/ta_setup.json \
    --policy    "(attA OR attB)" \
    --plaintext "EHR record content here" \
    --store-dir keys/store
# output: keys/store/<uuid>/v1.json
# {object_id, version:1, policy, c_aes, ct_abe, ts}
# ⚠ note the printed object_id
```

### 4. Client Decrypt

```bash
python client_decrypt.py \
    --object_id <uuid-from-step-3> \
    --attrs     "attA,attB" \
    --setup     keys/ta_setup.json \
    --sk        keys/user_sk.json \
    --store_dir keys/store
# → prints decrypted plaintext
```

### 5. Policy Update (cloud-side, no re-encryption)

```bash
python cloud_update.py \
    --setup          keys/ta_setup.json \
    --store-dir      keys/store \
    --object-id      <uuid> \
    --new-policy     "(attA OR (2, attB, attC, attD))" \
    --target-subtree T1 \
    --mode           Attributes2Existing
# writes: keys/store/<uuid>/v2.json
# c_aes is identical to v1.json — only ct_abe changes
```

### 6. Decrypt under updated policy

```bash
python client_decrypt.py \
    --object_id <uuid> \
    --version   2 \
    --attrs     "attA" \
    --setup     keys/ta_setup.json \
    --sk        keys/user_sk.json \
    --store_dir keys/store
```

---

## Running Tests

```bash
# Dev deps
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v --cov=. --cov-report=term-missing

# Run inside Docker (no local PBC needed)
docker run --rm <ECR_URI>:latest \
    python -m pytest /var/task/tests/ -v
```

`crypto_core.py` provides `encrypt_bytes()` and `decrypt_bytes()` as subprocess wrappers used by the test suite. These call `lambda_encrypt.py` and `client_decrypt.py` as subprocesses, allowing tests to run without importing charm-crypto directly.


---

## CloudWatch Log

```
{"operation": "encrypt", "input_bucket": "your-demo-bucket",
 "input_key": "test.txt", "output_bucket": "your-demo-bucket-output"}
Duration: 126.57 ms    Billed Duration: 5525 ms    Memory Size: 1024 MB
```

| Field | Meaning |
|---|---|
| `operation: encrypt` | S3 trigger correctly routed to Flow A |
| `126.57 ms` actual | The DEK generation + ABE.Enc + AES-GCM.Enc computation |
| `5525 ms` billed | ~5.4 s Docker container cold start (Lambda pulling image from ECR) |
| `1024 MB` memory | Sufficient for PBC pairing arithmetic; can profile and reduce |

On warm invocations, billed time drops to ~130–200 ms. Use **Provisioned Concurrency** to eliminate cold starts for production workloads.




