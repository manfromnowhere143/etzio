# Offline native checkpoint inspection

Status: implemented offline inspection contract, 2026-10-11. This work admits no provider,
clock, witness policy or kernel authority. It does not close the external latest-head gate.

## Decision

Add a finite offline inspector for Ed25519 log notes and timestamped Ed25519 checkpoint
cosignatures. This advances native head-format compatibility while the separately scoped
timestamp acquisition remains pending. The existing Merkle proof validators, fixture
lifecycle, complete-roster policy and recovery barrier stay unchanged.

The input is a local retained note, an exact expected origin, one caller-supplied log
verifier key and zero to fifteen required witness verifier keys. Key publication must be
assessed separately. Neither a key embedded in untrusted text nor its short identifier
establishes trust. Every configured key must verify; an unknown signature contributes
nothing to this roster. Successful inspection emits a deterministic documentary report.

## Finite wire profile

The source versions are C2SP [signed-note v1.1.0](https://c2sp.org/signed-note@v1.1.0),
[tlog-checkpoint v1.1.0](https://c2sp.org/tlog-checkpoint@v1.1.0) and
[tlog-cosignature v1.1.0](https://c2sp.org/tlog-cosignature@v1.1.0).
Only signature types `0x01` (log Ed25519) and `0x04` (timestamped Ed25519 cosignature)
are configured. The standards recommend ML-DSA for new deployments; inspecting an
existing Ed25519 example makes no new deployment or cryptographic migration decision.

Verifier strings contain a name, eight lowercase hexadecimal identifier characters and
canonical base64 of the type byte plus 32-byte public key. Recompute the identifier from
the exact name, newline, type and key. Require canonical prime-subgroup public keys using
Etzio's existing key-admissibility predicate. Pin the complete key, not the four-byte ID.
Each configured name and underlying key must be distinct, including across log/witness
roles; this avoids duplicate counting and cosigner-name substitution. Rotation and shared
keys require a different explicit profile.

Notes require exact UTF-8, LF framing, no ASCII controls below U+0020 except LF, a final
newline, and one separating blank line. The authenticated body has exactly three nonempty
lines: origin, canonical decimal tree size and canonical base64 of a 32-byte root.
Origins/names are at most 255 UTF-8 bytes and contain no whitespace or plus. The caller's
origin must match exactly; the log key name may differ. No normalization is performed.
Extensions, legacy origins containing spaces, alternate algorithms and arbitrary note
bodies are outside this subset. An empty tree must have SHA-256 of the empty string as root.

Authenticate exact body bytes before interpreting its checkpoint fields. A signature line
contains its name and canonical base64 of the four-byte ID plus signature payload. Match
both name and ID. Unknown tuples are ignored after structural validation; duplicate tuples,
including unknown ones, refuse. A bad signature from a configured key refuses the entire
note. Type `0x01` signs the body directly. Type `0x04` carries an eight-byte big-endian
timestamp and signs the specified `cosignature/v1` domain, decimal timestamp and complete
body. Its timestamp remains a signed claim, not qualified UTC or a freshness measurement.

Application ceilings are 128 KiB per note, 32 signature lines, 8192 decoded bytes per
signature value (including its four-byte identifier), 512 UTF-8 bytes per verifier string,
16 configured keys including the log, and unsigned 64-bit tree sizes/timestamps.
Check limits before dependent allocation
or integer conversion. These are parser/retention limits, not process isolation or a
worst-case CPU guarantee. No endpoint is contacted, and no downloaded program is executed.

## Evidence boundary and controls

The report binds the input bytes, exact signed body, expected origin and complete verifier
roster. It records authenticated roots, sizes and per-key signature results. It explicitly
denies provider admission, independent administration, clock qualification, inclusion,
consistency, latest-head authority and kernel authority. A valid historical checkpoint
still passes signature mathematics. A validly signed fork can also pass this isolated
inspection; consistency proofs and the retained predecessor are separate obligations.
Neither result may become a `HeadCheckpointFloorV1` or release a recovery barrier.

Owned controls must cover changed body/signature/time/domain, wrong origin or pin, missing
required keys, unknown tuples sharing only a name or ID, a forged matching tuple, duplicate
tuples/rosters, reused keys, wrong type, noncanonical encodings, Unicode/framing ambiguity,
all resource boundaries, empty-tree roots and CLI failures. Old and conflicting signed
heads must retain explicit non-authority results. Retained public bytes are replayed
offline on both supported runtimes; they are never fetched by tests.

The first documentary target is the 511-byte firmware-transparency example in the
[distributor README at commit 2425092](https://github.com/transparency-dev/distributor/blob/2425092797d5deda65c496d470cf3805558a0b35/README.md).
The same revision's log and witness configuration supplies the public key material.
Those witness entries use type `0x01` key strings; retain the underlying keys and derive
type `0x04` identifiers explicitly for the published cosignatures. This is a type-specific
encoding derivation, not independent key enrollment. The checkpoint and key publication
share repository custody. No administration, currentness or honest-witness conclusion
follows, and the log is not an Etzio catalog.

Primary-source review and byte identities belong in the accompanying dated evidence
record. Complete native time/revocation/anchor/catalog/monitor admission, inclusion and
consistency binding, current external floors and actual local-loss recovery remain open.

## Retained result

The [inspector](../scripts/inspect_native_checkpoint.py) verifies the published example's
one log signature and two timestamped cosignatures on CPython 3.11.15 and 3.14.2 with
identical reports. Its historical timestamp claims are `1729698503` and `1729698499`.
Changed body, missing required witness and altered witness signature controls all refuse.
The [105 owned controls](../tests/test_native_checkpoint_inspection.py) also exercise the
actual 128 KiB note ceiling and the complete 16-key roster. The
[dated evidence](evidence/native-checkpoint-inspection-2026-10-11.json) retains source
versions, raw-byte identities, derivation, review depth and development observations.
Full release results belong to the exact candidate's release record, not these focused
passes. Raw publisher captures remain private under the ignored checkpoint directory.
