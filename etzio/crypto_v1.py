"""Cryptographic input validation shared by Etzio protocol-v1 trust stores."""

from __future__ import annotations

from nacl.bindings import crypto_core_ed25519_is_valid_point


def is_valid_ed25519_public_key(public_key_bytes: object) -> bool:
    """Return whether bytes encode a canonical, prime-subgroup Ed25519 point.

    Merely constructing an Ed25519 public-key object is insufficient on some backends:
    small-order encodings can be accepted and may verify degenerate signatures. Libsodium's
    point validator additionally requires a canonical curve point in the main subgroup and
    rejects small-order points.
    """

    return (
        type(public_key_bytes) is bytes
        and len(public_key_bytes) == 32
        and bool(crypto_core_ed25519_is_valid_point(public_key_bytes))
    )
