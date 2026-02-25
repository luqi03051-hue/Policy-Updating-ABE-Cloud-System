# -*- coding: utf-8 -*-
"""
lambda_encrypt.py (Persistent Version - FIXED)

功能：
1) Cloud 端接收明文 M + policy
2) 生成随机会话密钥 K_gt（GT 元素），并通过 KDF 派生 AES-256 key
3) 使用 AES-GCM 加密明文（AAD 绑定 object_id）
4) 使用你自己的 ABE 加密 K_gt（用 TA 生成的 mpk）
5) 将结果持久化保存到本地磁盘（PoC：模拟 S3 持久化）

存储结构（与 client_decrypt.py 兼容）：
  keys/store/<object_id>/v<version>.json
  keys/store/<object_id>/latest.json

依赖：ta_local.py 里应提供：
- build_abe(curve, ell) -> (group, abe)
- serialize_any(group, obj)
- deserialize_any(group, obj)
"""

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
    """
    从 GT 元素派生 AES-256 key：SHA-256(group.serialize(K_gt)) -> 32 bytes
    client 端只要解出同一份 K_gt，就能得到同一份 AES key。
    """
    raw = group.serialize(K_gt)
    return hashlib.sha256(raw).digest()


def aes_gcm_encrypt(plaintext: bytes, key32: bytes, aad: bytes) -> Dict[str, str]:
    """AES-GCM 加密（AAD 绑定 object_id），返回 JSON 可序列化结构。"""
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
    mpk: Any  # mpk 的具体结构由你的 ABE 实现决定


def load_cloud_context(setup_json_path: str = "keys/ta_setup.json") -> CloudContext:
    """
    读取 TA 的 setup 文件（PoC：本地文件；真实 AWS：S3/SSM/镜像内置）。
    注意：Cloud 端只需要 mpk（不应持有 msk）。
    """
    setup_path = Path(setup_json_path)
    if not setup_path.exists():
        raise FileNotFoundError(f"setup file not found: {setup_path}")

    blob = json.loads(setup_path.read_text(encoding="utf-8"))

    curve = blob["curve"]
    ell = int(blob.get("ell", 0))

    # 与 TA 使用同一份 build_abe 初始化（保证算法一致）
    group, abe = build_abe(curve, ell)

    # 关键：用 deserialize_any 反序列化 mpk
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
    """
    Cloud: receive {M, policy}, produce {c_aes, ct_abe}, store to disk.
    保持你的 ABE encrypt 算法：ctx.abe.encrypt(K_gt, ctx.mpk, policy)
    """
    t0 = time.time()

    # 1) 生成随机会话密钥（GT 元素）
    K_gt = ctx.group.random(GT)

    # 2) 派生 AES key（32 bytes）
    dek32 = kdf_from_gt(ctx.group, K_gt)

    # 3) 生成 object_id（用于存储 & 作为 AES-GCM AAD 绑定）
    object_id = str(uuid.uuid4())

    # 4) AES-GCM 加密明文（AAD 绑定 object_id）
    aad = object_id.encode("utf-8")
    c_aes = aes_gcm_encrypt(M_plain, dek32, aad=aad)

    # 4) ABE 加密 GT 元素（保持你的调用方式；若签名不同只改这一行）
    ct_abe_raw = ctx.abe.encrypt(K_gt, ctx.mpk, policy)
    if ct_abe_raw is None:
        raise ValueError("ABE encryption failed. Please check your policy syntax or ABE implementation.")

    # 5) 序列化 ABE 密文（用 serialize_any，避免未来格式不兼容）
    ct_abe_ser = serialize_any(ctx.group, ct_abe_raw)

    # 6) 记录 + 持久化
    record = {
        "object_id": object_id,
        "version": 1,
        "policy": policy,
        "c_aes": c_aes,        # 与 client_decrypt 兼容（小写）
        "ct_abe": ct_abe_ser,  # 与 client_decrypt 兼容（小写）
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