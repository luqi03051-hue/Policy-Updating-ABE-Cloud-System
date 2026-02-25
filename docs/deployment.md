
# Deployment Guide — PU-CP-ABE on AWS Lambda (Docker)

This document describes how the research PU-CP-ABE scheme is deployed as a practical cloud data-sharing system on AWS.

The goal of this deployment is not to build a full production service, but to demonstrate how a pairing-based cryptographic scheme can operate inside a realistic cloud environment.

---

## 1. System Deployment Philosophy

The original paper defines cryptographic algorithms:

- Setup
- KeyGen
- Encrypt
- Decrypt
- UPKeyGen
- CTUpdate

Real-world systems additionally require:

- large file encryption
- runtime dependency management
- cloud execution isolation
- reproducibility

Therefore this project adopts:

- Hybrid Encryption
- Containerised Runtime
- Serverless Execution

---

## 2. Hybrid Encryption Architecture

Direct ABE encryption of large files is inefficient.

Instead, the deployment uses a KEM‑DEM (Hybrid Encryption) design.

### Encryption (Cloud)

1. Generate random Data Encryption Key (DEK)
2. Encrypt file using AES‑GCM
3. Encrypt DEK using PU‑CP‑ABE

Stored objects:

- file.ct — AES encrypted payload  
- file.dek.abe — ABE ciphertext of DEK  
- file.meta.json — policy and metadata  

### Decryption (Client)

DEK = ABE.Dec(dek.abe.ct, SK_user)  
file = AES‑GCM.Dec(file.ct, DEK)

This preserves the access‑control semantics of the ABE scheme while enabling efficient file encryption.

---

## 3. Why Docker Deployment is Required

The ABE implementation is pairing‑based and depends on native cryptographic libraries:

- Charm‑Crypto
- PBC library
- GMP
- OpenSSL

AWS Lambda standard Python runtimes cannot reliably execute these dependencies.

Therefore the entire cryptographic runtime is packaged as a Docker container image.

Benefits:

- deterministic runtime
- identical local/cloud execution
- stable native library linkage
- portable research artifact

---

## 4. AWS Architecture Overview

User Upload → S3 (Input Bucket) → Lambda Container → S3 (Encrypted Storage)

Components:

| Component | Role |
|---|---|
| S3 | Object storage |
| Lambda Container | Cryptographic executor |
| ECR | Docker image registry |
| CloudWatch | Execution logging |

---

## 5. Role Separation (Security Model)

### Trusted Authority (Local Machine)

Runs:

- Setup()
- KeyGen()

Responsibilities:

- generate mpk and msk
- issue user secret keys

msk never leaves the local environment.

### Cloud Server (AWS Lambda)

The cloud is honest‑but‑curious.

Allowed operations:

- AES encryption
- ABE encryption
- ciphertext updating

Forbidden operations:

- KeyGen
- Decrypt
- access plaintext keys

The cloud stores ciphertext only.

### Data User (Client)

Client performs:

ABE.Dec → recover DEK  
AES.Dec → recover file

Decryption always occurs locally.

---

## 6. Deployment Steps

### Step 1 — Build Docker Image

docker build -t abe-lambda:poc .

The image includes:

- Python runtime
- Charm‑Crypto
- PBC
- project algorithms

### Step 2 — Push Image to AWS ECR

aws ecr create-repository --repository-name abe-lambda  
docker tag abe-lambda:poc <account>.dkr.ecr.<region>.amazonaws.com/abe-lambda:poc  
docker push <ECR_URL>

### Step 3 — Create Lambda Function

Create Lambda using Container Image.

Configuration:

- Memory ≥ 1024 MB
- Timeout ≥ 60s

### Step 4 — Configure S3 Trigger

Input bucket:

s3://inbox/

Event:

ObjectCreated

Trigger target:

Lambda Encrypt Function

### Step 5 — Upload Public Parameters

Upload:

mpk → s3://config/params.json

Keep locally:

msk  
user secret keys

### Step 6 — Encrypt via Upload

User uploads file:

hello.txt → inbox/

Lambda automatically:

- generates DEK
- AES encrypts file
- ABE encrypts DEK
- writes encrypted outputs

### Step 7 — Observe Execution

CloudWatch Logs show:

START RequestId  
operation: encrypt  
END RequestId  
REPORT Duration...

Logs provide an auditable record that only ciphertext operations occur in the cloud.

---

## 7. Policy Updating Deployment

Policy updates do not require re‑encrypting data.

Workflow:

1. Data owner submits new policy
2. Cloud generates update key

UK = UPKeyGen(...)

3. Cloud updates ciphertext

CT' = CTUpdate(CT, UK)

Only the ABE component changes; encrypted payload remains unchanged.

---

## 8. PoC Design Choice

For simplicity and reproducibility, the Proof‑of‑Concept executes the full cryptographic workflow within a single Lambda invocation.

In production deployments, the workflow can be separated into:

- Encrypt Service
- Policy Update Service
- Access Gateway

---

## 9. Deployment Outcome

This deployment demonstrates:

- transformation of academic cryptography into cloud systems
- secure key isolation
- serverless cryptographic execution
- practical ABE‑based access control

The cloud never gains access to plaintext or master secrets.
