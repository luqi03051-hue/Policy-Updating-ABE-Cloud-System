# crypto_core.py
from __future__ import annotations

import os
import re
import subprocess
import uuid
from typing import Any, Dict, List, Optional
import sys

def _run(cmd: List[str], cwd: Optional[str] = None) -> str:
    """Run a command and return stdout. Raise RuntimeError with stderr on failure."""
    p = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  rc: {p.returncode}\n"
            f"  stdout:\n{p.stdout}\n"
            f"  stderr:\n{p.stderr}\n"
        )
    return p.stdout.strip()


import os
import json
import re
from typing import Dict, Any

def _extract_oid(output: str) -> str:
    s = (output or "").strip()
    l = s.find("{")
    r = s.rfind("}")
    if l != -1 and r != -1 and r > l:
        json_str = s[l:r+1]
        json_str = re.sub(r"\x1b\[[0-9;]*m", "", json_str)
        try:
            data = json.loads(json_str)
            if isinstance(data, dict) and "object_id" in data:
                return str(data["object_id"])
        except Exception:
            pass
    # fallback：正则抓 object_id
    m = re.search(r'"object_id"\s*:\s*"([^"]+)"', s)
    if m:
        return m.group(1)
    raise ValueError(f"Cannot extract object_id from encrypt output:\n{s}")

def encrypt_bytes(plaintext: bytes, policy: str, keys_dir: str = "keys") -> Dict[str, Any]:
    if plaintext is None:
        raise ValueError("plaintext is None")
    if policy is None or not str(policy).strip():
        raise ValueError("policy is empty")

    keys_dir = os.path.abspath(keys_dir)
    setup_path = os.path.join(keys_dir, "ta_setup.json")
    store_dir = os.path.join(keys_dir, "store")
    os.makedirs(store_dir, exist_ok=True)

    before = set(os.listdir(store_dir))

    cmd = [
        sys.executable, "lambda_encrypt.py",
        "--setup", setup_path,
        "--policy", policy,
        "--plaintext", plaintext.decode("utf-8", errors="ignore"),
        "--store-dir", store_dir,
    ]

    out = _run(cmd)

    oid = _extract_oid(out)

    after = set(os.listdir(store_dir))
    new_files = sorted(list(after - before))

    store_file = None
    if new_files:
        store_file = os.path.join(store_dir, new_files[-1])

    return {
        "object_id": oid,
        "policy": policy,
        "keys_dir": keys_dir,
        "setup_path": setup_path,
        "store_dir": store_dir,
        "store_file": store_file,   
        "encrypt_stdout": out,
    }

def decrypt_bytes(
    bundle: Dict[str, Any],
    attrs: str,
    sk_path: str,
) -> bytes:
    object_id = bundle["object_id"]
    store_dir = bundle["store_dir"]
    setup_path = bundle["setup_path"]

    sk_path = os.path.abspath(sk_path)

    cmd = [
        sys.executable,
        "client_decrypt.py",
        "--object_id",
        str(object_id),
        "--attrs",
        attrs,
        "--store_dir",
        store_dir,
        "--setup",
        setup_path,
        "--sk",
        sk_path,
    ]
    out = _run(cmd)

    lines = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("[DEBUG]") or s.startswith("[INFO]") or s.startswith("[WARN]") or s.startswith("[ERROR]"):
            continue
        lines.append(s)

    if not lines:
        return b""


    return lines[-1].encode("utf-8")

