"""Bounded RFC 9162 append state reconstructed from a last-leaf proof.

This is mathematical state only. It authenticates no provider or latest head.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .head_authority_adapters_v1 import MAX_HEAD_TREE_SIZE_V1, verify_merkle_inclusion_v1


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass(frozen=True, slots=True)
class MerkleAppendStateV1:
    """Roots of the complete subtrees in the binary decomposition of a tree size."""

    tree_size: int
    peaks: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.tree_size) is not int or not 1 <= self.tree_size <= MAX_HEAD_TREE_SIZE_V1:
            raise ValueError("Merkle append state requires a bounded positive tree size")
        if (
            type(self.peaks) is not tuple
            or len(self.peaks) != self.tree_size.bit_count()
            or any(type(node) is not bytes or len(node) != 32 for node in self.peaks)
        ):
            raise ValueError("Merkle append peaks must exactly cover the tree's binary decomposition")

    @property
    def root_hash(self) -> bytes:
        root = self.peaks[-1]
        for left in reversed(self.peaks[:-1]):
            root = _node(left, root)
        return root

    @classmethod
    def from_last_leaf(
        cls, *, tree_size: int, leaf_hash: bytes, proof: tuple[bytes, ...], root_hash: bytes,
    ) -> MerkleAppendStateV1:
        """Verify the proof before recovering the complete-subtree frontier."""

        if type(tree_size) is not int or not 1 <= tree_size <= MAX_HEAD_TREE_SIZE_V1:
            raise ValueError("Merkle reconstruction requires a bounded positive tree size")
        verify_merkle_inclusion_v1(
            leaf_hash=leaf_hash, leaf_index=tree_size - 1, tree_size=tree_size,
            proof=proof, root_hash=root_hash,
        )
        trailing_zeros = (tree_size & -tree_size).bit_length() - 1
        rightmost = leaf_hash
        for sibling in proof[:trailing_zeros]:
            rightmost = _node(sibling, rightmost)
        state = cls(tree_size=tree_size, peaks=(*reversed(proof[trailing_zeros:]), rightmost))
        if state.root_hash != root_hash:
            raise ValueError("reconstructed Merkle append state differs from its verified root")
        return state

    def append(
        self, leaf_hash: bytes,
    ) -> tuple[MerkleAppendStateV1, tuple[bytes, ...], tuple[bytes, ...]]:
        """Return successor state, new last-leaf proof, and exact predecessor consistency proof."""

        if type(leaf_hash) is not bytes or len(leaf_hash) != 32:
            raise ValueError("Merkle append requires one immutable 32-byte leaf hash")
        if self.tree_size == MAX_HEAD_TREE_SIZE_V1:
            raise ValueError("Merkle append would exceed the tree-size ceiling")
        inclusion = tuple(reversed(self.peaks))
        consistency = (
            (leaf_hash,) if self.tree_size & (self.tree_size - 1) == 0
            else (self.peaks[-1], leaf_hash, *reversed(self.peaks[:-1]))
        )
        peaks = list(self.peaks)
        size = self.tree_size
        carry = leaf_hash
        while size & 1:
            carry = _node(peaks.pop(), carry)
            size >>= 1
        peaks.append(carry)
        return MerkleAppendStateV1(self.tree_size + 1, tuple(peaks)), inclusion, consistency
