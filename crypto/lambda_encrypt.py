# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from charm.toolbox.pairinggroup import GT
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from object_store import FileObjectStore
from ta_local import build_abe, serialize_any, deserialize_any


# ------------------------
# Utils
# ------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def kdf_from_gt(group: Any, K_gt: Any) -> bytes:
   
    raw = group.serialize(K_gt)
    return hashlib.sha256(raw).digest()


def aes_gcm_encrypt(plaintext: bytes, key32: bytes, aad: bytes) -> Dict[str, str]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key32)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {"nonce_b64": b64e(nonce), "ct_b64": b64e(ct)}


# ------------------------
# Context
# ------------------------
@dataclass
class CloudContext:
    curve: str
    ell: int
    group: Any
    abe: Any
    mpk: Any  


def load_cloud_context(setup_json_path: str = "keys/ta_setup.json") -> CloudContext:
   
    setup_path = Path(setup_json_path)
    if not setup_path.exists():
        raise FileNotFoundError(f"setup file not found: {setup_path}")

    blob = json.loads(setup_path.read_text(encoding="utf-8"))

    curve = blob["curve"]
    ell = int(blob.get("ell", 0))


    group, abe = build_abe(curve, ell)

  
    if "mpk" not in blob:
        raise KeyError("setup json missing key: mpk")
    mpk = deserialize_any(group, blob["mpk"])

    return CloudContext(curve=curve, ell=ell, group=group, abe=abe, mpk=mpk)


# ------------------------
# Core: encrypt + persist
# ------------------------
def cloud_encrypt_upload(
    ctx: CloudContext,
    store: FileObjectStore,
    M_plain: bytes,
    policy: str,
) -> Dict[str, Any]:
   
    t0 = time.time()

  
    K_gt = ctx.group.random(GT)

  
    dek32 = kdf_from_gt(ctx.group, K_gt)

   
    object_id = str(uuid.uuid4())

  
    aad = object_id.encode("utf-8")
    c_aes = aes_gcm_encrypt(M_plain, dek32, aad=aad)

   
    ct_abe_raw = ctx.abe.encrypt(K_gt, ctx.mpk, policy)
    if ct_abe_raw is None:
        raise ValueError("ABE encryption failed. Please check your policy syntax or ABE implementation.")

   
    ct_abe_ser = serialize_any(ctx.group, ct_abe_raw)

  
    record = {
        "object_id": object_id,
        "version": 1,
        "policy": policy,
        "c_aes": c_aes,        
        "ct_abe": ct_abe_ser,  
        "ts": int(t0),
    }
    store.put(object_id, record)

    return {
        "object_id": object_id,
        "version": 1,
        "ms": int((time.time() - t0) * 1000),
    }


# ------------------------
# CLI entry (container test)
# ------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", default="keys/ta_setup.json")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--plaintext", required=True)
    parser.add_argument("--store-dir", default="/var/task/keys/store")
    args = parser.parse_args()

    store = FileObjectStore(args.store_dir)
    ctx = load_cloud_context(args.setup)
    res = cloud_encrypt_upload(ctx, store, args.plaintext.encode("utf-8"), args.policy)
    print(json.dumps(res, ensure_ascii=False, indent=2))
