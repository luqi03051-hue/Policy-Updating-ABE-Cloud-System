# -*- coding: utf-8 -*-
"""
cloud_update.py

Cloud-side *policy update* for the PoC (simulating "cloud runs UPKeyGen + CTUpdate").

What it does
- Loads mpk (TA setup) to initialise the SAME ABE scheme as encrypt/decrypt
- Loads an existing stored object record (vK.json) from the local persistent store (PoC for S3)
- Generates an update token tk via your paper algorithm UPKeyGen
- Updates the ABE ciphertext via CTUpdate (no need to touch AES-GCM ciphertext)
- Writes a NEW version v(K+1).json and updates latest.json

This script is intended to be run inside your Docker/Lambda container *as the cloud*.

Store format (compatible with client_decrypt.py):
  <store_dir>/<object_id>/v1.json, v2.json, ...
  <store_dir>/<object_id>/latest.json  -> {"object_id": "...", "latest_version": N}

Record keys (compatible with lambda_encrypt.py + client_decrypt.py):
  - policy (string)
  - c_aes (AES-GCM blob dict)
  - ct_abe (serialized ABE ciphertext dict)
  - version (int), object_id (string), ts (int)

Usage examples
  # Update subtree T1 (existing attributes only)
  python cloud_update.py \
    --setup keys/ta_setup.json \
    --store-dir /var/task/keys/store \
    --object-id <ID> \
    --new-policy "(attA OR attB)" \
    --target-subtree T1 \
    --mode Attributes2Existing

  # Update with Attributes2New (add a NEW subtree ciphertext)
  python cloud_update.py \
    --setup keys/ta_setup.json \
    --store-dir /var/task/keys/store \
    --object-id <ID> \
    --new-policy "(attA OR (2, attB, attC, attD))" \
    --target-subtree T1 \
    --mode Attributes2New \
    --new-subtree T3 \
    --pos-new-gate 2
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ta_local import build_abe, deserialize_any, serialize_any, UPKeyGen, CTUpdate


# ------------------------
# Store helpers (no dependency on object_store.py)
# ------------------------
def _read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _write_json(p: Path, obj: Dict[str, Any]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _resolve_version_file(store_dir: Path, object_id: str, version: Optional[int]) -> Tuple[Path, int]:
    """
    Match the resolution logic in client_decrypt.py:
    - If version is None: use latest.json if present, else scan v*.json and take max.
    """
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

    ver = int(version)
    ver_path = obj_dir / f"v{ver}.json"
    if not ver_path.exists():
        raise FileNotFoundError(f"Version file not found: {ver_path}")
    return ver_path, ver


def _write_new_version(store_dir: Path, object_id: str, version: int, record: Dict[str, Any]) -> Path:
    obj_dir = store_dir / object_id
    obj_dir.mkdir(parents=True, exist_ok=True)

    ver_path = obj_dir / f"v{version}.json"
    _write_json(ver_path, record)

    latest_path = obj_dir / "latest.json"
    _write_json(latest_path, {"object_id": object_id, "latest_version": version, "ts": int(time.time())})
    return ver_path


# ------------------------
# Load cloud context (mpk only)
# ------------------------
def load_cloud_context(setup_json_path: str) -> Tuple[Any, Any, Dict[str, Any], int]:
    """
    Returns (group, abe, mpk, ell).
    setup json must contain: curve, ell, mpk
    """
    setup_path = Path(setup_json_path)
    if not setup_path.exists():
        raise FileNotFoundError(f"setup file not found: {setup_path}")

    blob = json.loads(setup_path.read_text(encoding="utf-8"))
    curve = blob["curve"]
    ell = int(blob.get("ell", 0))

    group, abe = build_abe(curve, ell)
    mpk = deserialize_any(group, blob["mpk"])
    return group, abe, mpk, ell


# ------------------------
# Main update routine
# ------------------------
def update_policy(
    *,
    setup_path: str,
    store_dir: str,
    object_id: str,
    new_policy: str,
    target_subtree: str,
    mode: str,
    version: Optional[int] = None,
    new_subtree: Optional[str] = None,
    pos_new_gate: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Returns a summary dict with new version info.
    """
    group, _abe, mpk, ell = load_cloud_context(setup_path)

    store_path = Path(store_dir)
    ver_path, ver = _resolve_version_file(store_path, object_id, version)
    record = _read_json(ver_path)

    if "policy" not in record:
        raise KeyError("record missing 'policy'")
    old_policy = record["policy"]

    if "ct_abe" not in record:
        raise KeyError("record missing 'ct_abe'")
    ct_old = deserialize_any(group, record["ct_abe"])

    # E_T are the random numbers used in ct_T; stored in CT['_debug']['s_map'] by your Encrypt
    try:
        E_T = ct_old["_debug"]["s_map"]
    except Exception as e:
        raise KeyError(
            "ct_abe missing CT['_debug']['s_map']. "
            "Make sure you used the paper-version Encrypt that stores _debug.s_map."
        ) from e

    tk = UPKeyGen(
        group=group,
        params=mpk,
        ell=ell,
        E_T=E_T,
        old_policy=old_policy,
        new_policy=new_policy,
        target_subtree=target_subtree,
        mode=mode,
        new_subtree=new_subtree,
        pos_new_gate=pos_new_gate,
    )

    ct_new = CTUpdate(ct_old, tk)

    # Persist: only policy + ct_abe change; AES ciphertext remains (same session key encapsulated)
    record_new = dict(record)
    record_new["policy"] = new_policy
    record_new["ct_abe"] = serialize_any(group, ct_new)
    record_new["version"] = ver + 1
    record_new["ts"] = int(time.time())

    out_path = _write_new_version(store_path, object_id, ver + 1, record_new)

    return {
        "object_id": object_id,
        "old_version": ver,
        "new_version": ver + 1,
        "old_policy": old_policy,
        "new_policy": new_policy,
        "written": str(out_path),
        "mode": mode,
        "target_subtree": target_subtree,
    }


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Cloud-side policy update: UPKeyGen + CTUpdate")
    p.add_argument("--setup", default="keys/ta_setup.json", help="TA setup json containing mpk (cloud only needs mpk)")
    p.add_argument("--store-dir", default="/var/task/keys/store", help="Persistent store dir (PoC for S3)")
    p.add_argument("--object-id", required=True, help="Object ID (folder name in store)")
    p.add_argument("--version", type=int, default=None, help="Which version to update; default=latest")
    p.add_argument("--new-policy", required=True, help="New access policy string")

    p.add_argument("--target-subtree", required=True, help="Subtree label in OLD policy to update, e.g., T1")
    p.add_argument("--mode", required=True, choices=["Attributes2Existing", "Attributes2New"],
                   help="Update mode per your paper")

    # Only for Attributes2New
    p.add_argument("--new-subtree", default=None, help="Subtree label in NEW policy (e.g., T3) (Attributes2New only)")
    p.add_argument("--pos-new-gate", type=int, default=None,
                   help="1-based position among gate-children of target gate in NEW policy (Attributes2New only)")

    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    if args.mode == "Attributes2New":
        if not args.new_subtree or args.pos_new_gate is None:
            raise SystemExit("Attributes2New requires --new-subtree and --pos-new-gate")
    else:
        # ignore extras if provided
        args.new_subtree = None
        args.pos_new_gate = None

    summary = update_policy(
        setup_path=args.setup,
        store_dir=args.store_dir,
        object_id=args.object_id,
        version=args.version,
        new_policy=args.new_policy,
        target_subtree=args.target_subtree,
        mode=args.mode,
        new_subtree=args.new_subtree,
        pos_new_gate=args.pos_new_gate,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
