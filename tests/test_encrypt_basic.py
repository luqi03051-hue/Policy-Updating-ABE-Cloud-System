import pytest
import os
from crypto_core import encrypt_bytes
from conftest import has_charm

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_CHARM_TESTS") != "1",
    reason="Set RUN_CHARM_TESTS=1 to enable Charm-Crypto integration tests."
)

def test_encrypt_success(keys_dir):
    bundle = encrypt_bytes(
        plaintext=b"hello",
        policy="A or C",
        keys_dir=str(keys_dir),
    )

    assert bundle["object_id"]
    assert bundle["store_file"] is not None


def test_encrypt_reject_empty_policy(keys_dir):
    with pytest.raises(ValueError):
        encrypt_bytes(
            plaintext=b"hello",
            policy="",
            keys_dir=str(keys_dir),
        )


def test_encrypt_reject_none_plaintext(keys_dir):
    with pytest.raises(ValueError):
        encrypt_bytes(
            plaintext=None,
            policy="A or C",
            keys_dir=str(keys_dir),
        )
