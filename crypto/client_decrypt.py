# -*- coding: utf-8 -*-
"""
client_decrypt.py

Client-side decryption for the PoC:
- Loads mpk (setup) and sk (user key)
- Reads record from keys/store/<object_id>/...
- ABE decrypts K_gt using YOUR PAPER algorithms in ta_local.py (Decrypt + attrs)
- Derives AES-256 key via SHA-256(serialize(K_gt))
- AES-GCM decrypts plaintext with AAD=policy

Decrypt call order tries to match your paper signature:
    abe.decrypt(ct, sk, mpk, attrs)
and includes fallbacks for alternative signatures.

"""


from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ta_local import build_abe, deserialize_any


# ------------------------
# helpers
# ------------------------
def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_version_file(store_dir: Path, object_id: str, version: Optional[int]) -> Path:
    obj_dir = store_dir / object_id
    if not obj_dir.exists():
        raise FileNotFoundError(f"object_id not found in store: {obj_dir}")

    if version is None:
        latest_path = obj_dir / "latest.json"
        if latest_path.exists():
            latest = _read_json(latest_path)
            version = int(latest["latest_version"])
        else:
            vers = []
            for p in obj_dir.glob("v*.json"):
                try:
                    vers.append(int(p.stem[1:]))
                except Exception:
                    pass
            if not vers:
                raise FileNotFoundError(f"No version files found in {obj_dir}")
            version = max(vers)

    ver_path = obj_dir / f"v{int(version)}.json"
    if not ver_path.exists():
        raise FileNotFoundError(f"Version file not found: {ver_path}")
    return ver_path


def kdf_from_gt(group: Any, K_gt: Any) -> bytes:
    raw = group.serialize(K_gt)
    return hashlib.sha256(raw).digest()


def _abe_decrypt_flexible(abe: Any, mpk: Any, sk: Any, ct: Any, attrs: Any) -> Any:
    """Try multiple common decrypt signatures to match your own ABE implementation."""
    # 1) decrypt(ct, sk)
    if attrs:
        try:
            return abe.decrypt(ct, sk, mpk, attrs)
        except TypeError:
            pass
    try:
        return abe.decrypt(ct, sk)
    except TypeError:
        pass
    # 2) decrypt(ct, sk, mpk)
    try:
        return abe.decrypt(ct, sk, mpk)
    except TypeError:
        pass
    # 3) decrypt(mpk, sk, ct)
    try:
        return abe.decrypt(mpk, sk, ct)
    except TypeError:
        pass
    # 4) decrypt(sk, ct)
    try:
        return abe.decrypt(sk, ct)
    except TypeError as e:
        raise TypeError(
            "No compatible abe.decrypt signature matched. "            "Tried: decrypt(ct,sk), decrypt(ct,sk,mpk), decrypt(mpk,sk,ct), decrypt(sk,ct)."
        ) from e


def load_setup_and_sk(setup_path: str, sk_path: str):
    setup_blob = _read_json(Path(setup_path))
    sk_blob = _read_json(Path(sk_path))

    curve = setup_blob.get("curve")
    ell = int(setup_blob.get("ell", 0))
    if not curve:
        raise KeyError("setup json missing key: curve")

    group, abe = build_abe(curve, ell)

    if "mpk" not in setup_blob:
        raise KeyError("setup json missing key: mpk")
    mpk = deserialize_any(group, setup_blob["mpk"])

    # user_sk.json 可能是 {"sk": ...} 或直接就是 sk
    sk_raw = sk_blob.get("sk", sk_blob)
    sk = deserialize_any(group, sk_raw)

    return group, abe, mpk, sk


def client_download_and_decrypt(
    object_id: str,
    setup_path: str,
    sk_path: str,
    store_dir: str = "keys/store",
    version: Optional[int] = None,
    attrs: Optional[set] = None,
) -> bytes:
    store_dir_p = Path(store_dir)
    ver_path = _resolve_version_file(store_dir_p, object_id, version)
    rec = _read_json(ver_path)

    group, abe, mpk, sk = load_setup_and_sk(setup_path, sk_path)

    policy = rec["policy"]

    ct_abe_ser = rec.get("ct_abe") or rec.get("CT_ABE")
    if ct_abe_ser is None:
        raise KeyError("record missing ct_abe/CT_ABE")

    # 先反序列化 ABE 密文回 charm 对象
    ct_abe_raw = deserialize_any(group, ct_abe_ser)

    # ABE 解密得到 K_gt（应为 GT 元素）
    K_gt = _abe_decrypt_flexible(abe, mpk, sk, ct_abe_raw, attrs)

    # 兜底：如果你的 decrypt 返回的是序列化结构，再反序列化一次
    if isinstance(K_gt, (dict, list, str, bytes, int, float, bool)) or K_gt is None:
        K_gt = deserialize_any(group, K_gt)

    # 派生 AES-256 key
    dek32 = kdf_from_gt(group, K_gt)

    c_aes = rec.get("c_aes") or rec.get("C_AES")
    if c_aes is None:
        raise KeyError("record missing c_aes/C_AES")

    nonce = base64.b64decode(c_aes["nonce_b64"])
    ct = base64.b64decode(c_aes["ct_b64"])

    aesgcm = AESGCM(dek32)
    pt = aesgcm.decrypt(nonce, ct, object_id.encode("utf-8"))
    return pt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--object_id", required=True)
    ap.add_argument("--version", type=int, default=None)
    ap.add_argument("--setup", default="keys/ta_setup.json")
    ap.add_argument("--sk", default="keys/user_sk.json")
    ap.add_argument("--store_dir", default="keys/store")
    ap.add_argument("--attrs", default="", help="comma-separated attributes, e.g., A,B or C")
    args = ap.parse_args()
    attrs = {a.strip() for a in args.attrs.split(",") if a.strip()}

    pt = client_download_and_decrypt(
        object_id=args.object_id,
        setup_path=args.setup,
        sk_path=args.sk,
        store_dir=args.store_dir,
        version=args.version,
        attrs=attrs,
    )
    try:
        print(pt.decode("utf-8"))
    except Exception:
        print(base64.b64encode(pt).decode("ascii"))


if __name__ == "__main__":
    main()
