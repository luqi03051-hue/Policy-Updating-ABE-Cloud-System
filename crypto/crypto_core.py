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
    # 尝试截取 JSON
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

    # ✅ 核心：encrypt 前后差分，定位本次生成的新文件
    before = set(os.listdir(store_dir))

    # 你项目里原来怎么调用 lambda_encrypt.py，就保持一致
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
        # 如果一次产生多个文件，取最后一个（通常最新）
        store_file = os.path.join(store_dir, new_files[-1])

    return {
        "object_id": oid,
        "policy": policy,
        "keys_dir": keys_dir,
        "setup_path": setup_path,
        "store_dir": store_dir,
        "store_file": store_file,   # ✅ 这里必须非 None 才能过 tamper test
        "encrypt_stdout": out,
    }

def decrypt_bytes(
    bundle: Dict[str, Any],
    attrs: str,
    sk_path: str,
) -> bytes:
    """
    使用你现有的 client_decrypt.py 做一次解密。
    attrs: "attA,attB,attC" 这种
    sk_path: 私钥文件路径（例如 keys/user_sk.json）
    """
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

    # 只取最后一个非空行作为明文（前面可能有 [DEBUG] 或其他日志）
    lines = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s:
            continue
        # 过滤常见日志前缀
        if s.startswith("[DEBUG]") or s.startswith("[INFO]") or s.startswith("[WARN]") or s.startswith("[ERROR]"):
            continue
        lines.append(s)

    # 如果没有任何“明文行”，说明明文就是空（或脚本只打了日志）
    if not lines:
        return b""

    # 最后一行视为明文
    return lines[-1].encode("utf-8")
