"""Unit proofs for bounded Ed25519 public-key point validation."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from etzio import crypto_v1


class _BytesSubclass(bytes):
    pass


@pytest.fixture(autouse=True)
def _isolate_point_validation_cache():
    validator = crypto_v1._is_valid_ed25519_public_key_bytes
    validator.cache_clear()
    yield
    validator.cache_clear()


def test_public_key_validation_preserves_exact_input_boundary() -> None:
    valid_key = (
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    )
    assert crypto_v1.is_valid_ed25519_public_key(valid_key)
    assert not crypto_v1.is_valid_ed25519_public_key(
        bytearray(valid_key)
    )
    assert not crypto_v1.is_valid_ed25519_public_key(
        memoryview(valid_key)
    )
    assert not crypto_v1.is_valid_ed25519_public_key(
        _BytesSubclass(valid_key)
    )
    assert not crypto_v1.is_valid_ed25519_public_key(valid_key[:-1])
    assert not crypto_v1.is_valid_ed25519_public_key(valid_key + b"\x00")


def test_invalid_point_remains_rejected_on_cache_hit() -> None:
    invalid_key = b"\x01" + (b"\x00" * 31)
    validator = crypto_v1._is_valid_ed25519_public_key_bytes

    assert not crypto_v1.is_valid_ed25519_public_key(invalid_key)
    first = validator.cache_info()
    assert not crypto_v1.is_valid_ed25519_public_key(invalid_key)
    second = validator.cache_info()

    assert first.misses == 1
    assert second.misses == 1
    assert second.hits == 1


def test_point_validation_cache_has_a_fixed_memory_bound() -> None:
    validator = crypto_v1._is_valid_ed25519_public_key_bytes

    for value in range(
        crypto_v1._ED25519_POINT_CACHE_MAXSIZE + 1
    ):
        crypto_v1.is_valid_ed25519_public_key(
            value.to_bytes(32, "little")
        )

    info = validator.cache_info()
    assert info.maxsize == crypto_v1._ED25519_POINT_CACHE_MAXSIZE
    assert info.currsize == crypto_v1._ED25519_POINT_CACHE_MAXSIZE
    assert info.misses == crypto_v1._ED25519_POINT_CACHE_MAXSIZE + 1
