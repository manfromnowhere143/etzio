"""Compact append state must agree with independent full-tree RFC proof generation."""

import hashlib

import pytest

from etzio.kernel.head_authority_adapters_v1 import (
    MAX_HEAD_TREE_SIZE_V1,
    merkle_consistency_proof_v1,
    merkle_inclusion_proof_v1,
    merkle_root_v1,
    verify_merkle_consistency_v1,
)
from etzio.kernel.merkle_frontier_v1 import MerkleAppendStateV1


def _leaves(count):
    return tuple(hashlib.sha256(b"\x00" + index.to_bytes(4, "big")).digest() for index in range(count))


def test_every_append_and_restart_matches_full_tree_proofs_across_512_sizes():
    leaves = _leaves(513)
    for size in range(1, 513):
        root = merkle_root_v1(leaves[:size])
        state = MerkleAppendStateV1.from_last_leaf(
            tree_size=size, leaf_hash=leaves[size - 1],
            proof=merkle_inclusion_proof_v1(leaves[:size], size - 1), root_hash=root,
        )
        successor, inclusion, consistency = state.append(leaves[size])
        assert successor.root_hash == merkle_root_v1(leaves[:size + 1])
        assert inclusion == merkle_inclusion_proof_v1(leaves[:size + 1], size)
        assert consistency == merkle_consistency_proof_v1(leaves[:size + 1], size)
        verify_merkle_consistency_v1(
            first_size=size, first_root=root, second_size=size + 1,
            second_root=successor.root_hash, proof=consistency,
        )
        assert MerkleAppendStateV1.from_last_leaf(
            tree_size=size + 1, leaf_hash=leaves[size], proof=inclusion, root_hash=successor.root_hash,
        ) == successor


@pytest.mark.parametrize("damage", ["root", "leaf", "size", "truncated", "padded", "reversed"])
def test_reconstruction_refuses_a_damaged_last_leaf_proof(damage):
    leaves = _leaves(13)
    args = dict(tree_size=13, leaf_hash=leaves[-1],
                proof=merkle_inclusion_proof_v1(leaves, 12), root_hash=merkle_root_v1(leaves))
    if damage == "root":
        args["root_hash"] = bytes(32)
    elif damage == "leaf":
        args["leaf_hash"] = bytes(32)
    elif damage == "size":
        args["tree_size"] = 12
    elif damage == "truncated":
        args["proof"] = args["proof"][:-1]
    elif damage == "padded":
        args["proof"] = (*args["proof"], bytes(32))
    else:
        args["proof"] = tuple(reversed(args["proof"]))
    with pytest.raises(ValueError):
        MerkleAppendStateV1.from_last_leaf(**args)


@pytest.mark.parametrize("size", [False, 0, -1, MAX_HEAD_TREE_SIZE_V1 + 1])
def test_append_state_refuses_unsupported_sizes(size):
    with pytest.raises(ValueError):
        MerkleAppendStateV1(size, (bytes(32),))
    with pytest.raises(ValueError):
        MerkleAppendStateV1.from_last_leaf(tree_size=size, leaf_hash=bytes(32), proof=(), root_hash=bytes(32))


@pytest.mark.parametrize("peaks", [(), (bytes(32),), (bytes(31), bytes(32)), (bytearray(32), bytes(32))])
def test_append_state_refuses_incomplete_or_mutable_peaks(peaks):
    with pytest.raises(ValueError):
        MerkleAppendStateV1(3, peaks)


def test_append_refuses_tree_overflow():
    with pytest.raises(ValueError, match="ceiling"):
        MerkleAppendStateV1(MAX_HEAD_TREE_SIZE_V1, (bytes(32),)).append(bytes(32))


@pytest.mark.parametrize("leaf", [bytes(31), bytearray(32), "0" * 32])
def test_append_refuses_malformed_or_mutable_leaf(leaf):
    with pytest.raises(ValueError):
        MerkleAppendStateV1(1, (bytes(32),)).append(leaf)
