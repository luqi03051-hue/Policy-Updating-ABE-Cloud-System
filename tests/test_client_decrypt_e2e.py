import pytest
import os
from crypto_core import encrypt_bytes, decrypt_bytes

from conftest import has_charm

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_CHARM_TESTS") != "1",
    reason="Set RUN_CHARM_TESTS=1 to enable Charm-Crypto integration tests."
)

def test_e2e_encrypt_decrypt(keys_dir, ta_setup, user_sk_A):
    pt = b"e2e test"

    bundle = encrypt_bytes(
        plaintext=pt,
        policy="A or C",
        keys_dir=str(keys_dir),
    )

    out = decrypt_bytes(
        bundle=bundle,
        attrs="A",
        sk_path=str(user_sk_A),
    )

    assert out == pt


def test_policy_not_satisfied_should_fail(keys_dir, ta_setup, user_sk_A):
    bundle = encrypt_bytes(
        plaintext=b"secret",
        policy="A AND B",
        keys_dir=str(keys_dir),
    )

    with pytest.raises(Exception):
        decrypt_bytes(
            bundle=bundle,
            attrs="A",   
            sk_path=str(user_sk_A),
        )


def test_aad_object_id_tamper_should_fail(keys_dir, ta_setup, user_sk_A):
    bundle = encrypt_bytes(
        plaintext=b"tamper test",
        policy="A or C",
        keys_dir=str(keys_dir),
    )

  
    bundle["object_id"] = "fake_id"

    with pytest.raises(Exception):
        decrypt_bytes(
            bundle=bundle,
            attrs="A",
            sk_path=str(user_sk_A),
        )


def test_empty_plaintext(keys_dir, ta_setup, user_sk_A):
    bundle = encrypt_bytes(
        plaintext=b"",
        policy="A or C",
        keys_dir=str(keys_dir),
    )

    out = decrypt_bytes(
        bundle=bundle,
        attrs="A",
        sk_path=str(user_sk_A),
    )

    assert out == b""

