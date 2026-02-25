import subprocess
from pathlib import Path
import pytest
import sys
import json

# tests/conftest.py

ROOT = Path(__file__).resolve().parents[1]  
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def has_charm() -> bool:
    p = subprocess.run(
        [sys.executable, "-c", "import charm; print('ok')"],
        capture_output=True,
        text=True,
    )
    return p.returncode == 0

def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"cmd failed:\n{p.stdout}\n{p.stderr}")
    return p.stdout.strip()


@pytest.fixture(scope="session")
def keys_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    return Path(d)


@pytest.fixture(scope="session")
def ta_setup(keys_dir):
    setup_path = keys_dir / "ta_setup.json"
    _run([sys.executable, "ta_local.py", "setup", "--out", str(setup_path)])
    return setup_path


@pytest.fixture(scope="session")
def user_sk_A(keys_dir, ta_setup):
    sk_path = keys_dir / "user_sk_A.json"
    _run([
        "python", "ta_local.py", "keygen",
        "--inp", str(ta_setup),
        "--attrs", "A",
        "--policy", "A",
        "--out", str(sk_path),
    ])
    return sk_path

@pytest.fixture(scope="session")
def abe_materials(keys_dir, ta_setup, user_sk_A):
    setup_obj = json.loads(Path(ta_setup).read_text())

    return {
        "keys_dir": keys_dir,
        "setup_path": ta_setup,
        "sk_path": user_sk_A,
        "mpk": setup_obj["mpk"],
    }


