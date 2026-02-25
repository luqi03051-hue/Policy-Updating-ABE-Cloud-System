import os
import pytest
from crypto_core import encrypt_bytes, decrypt_bytes

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_CHARM_TESTS") != "1",
    reason="Set RUN_CHARM_TESTS=1 to enable Charm-Crypto integration tests."
)

def test_encrypt_decrypt_roundtrip(abe_materials):
    bundle = encrypt_bytes(
        plaintext=b"hello",
        policy="A or C",
        keys_dir=str(abe_materials["keys_dir"]),
    )
    pt = decrypt_bytes(
        bundle=bundle,
        attrs="A",
        sk_path=str(abe_materials["sk_path"]),
    )
    assert pt == b"hello"

def test_policy_not_satisfied_should_fail(abe_materials):
    bundle = encrypt_bytes(
        plaintext=b"secret",
        policy="A and B",
        keys_dir=str(abe_materials["keys_dir"]),
    )
    with pytest.raises(Exception):
        decrypt_bytes(
            bundle=bundle,
            attrs="A",
            sk_path=str(abe_materials["sk_path"]),
        )

def test_empty_plaintext_ok(abe_materials):
    bundle = encrypt_bytes(
        plaintext=b"",
        policy="A or C",
        keys_dir=str(abe_materials["keys_dir"]),
    )
    pt = decrypt_bytes(
        bundle=bundle,
        attrs="A",
        sk_path=str(abe_materials["sk_path"]),
    )
    assert pt == b""
