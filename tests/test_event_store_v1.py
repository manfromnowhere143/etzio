"""Known-good and known-bad evidence for the durable mission event tranche."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from etzio.analysis import StaticFinding
from etzio.authority import (
    AuthorityAdmissionV1,
    AuthorityGrantV1,
    AuthoritySigner,
    TrustedAuthorityKey,
    TrustStore,
)
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventIntegrityError, EventV1
from etzio.kernel.reducer import ProjectionPhase, ReductionError, reduce_events
from etzio.kernel.store import (
    ClosedStreamError,
    EventStoreCorruptionError,
    EventStoreError,
    SignedCheckpoint,
    SQLiteEventStore,
    StaleHeadError,
)
from etzio.mission_v1 import StaticCandidateV1
from etzio.protocol import EnvelopeV1, content_id, strict_loads
from etzio.schemas import protocol_v1_schema

MISSION_ID = content_id("mission", {"fixture": "event-store"})
OTHER_MISSION_ID = content_id("mission", {"fixture": "other-event-store"})
SOURCE_DIGEST = content_id("artifact", {"fixture": "source"})

TARGET_SNAPSHOT = EnvelopeV1.create(
    "target_snapshot",
    {
        "files": [
            {
                "artifact_digest": SOURCE_DIGEST,
                "relative_path": "fixture/app.py",
                "size": 128,
            },
            {
                "artifact_digest": SOURCE_DIGEST,
                "relative_path": "fixture/broken.py",
                "size": 64,
            },
        ],
        "source": "repository_fixture",
    },
)
TARGET_ID = TARGET_SNAPSHOT.object_id
AUTHORITY_GRANT_VALUE = AuthorityGrantV1.issue(
    assets=("fixture://app.py",),
    evidence_digest=content_id("artifact", {"fixture": "authority"}),
    expires_at=1_800_000_000,
    issued_at=1_700_000_000,
    issuer="operator:daniel",
    max_bytes=1_000_000,
    max_candidates=100,
    max_wallclock_seconds=60,
    not_before=1_700_000_000,
    permitted_actions=("static_analysis",),
    subject="benchmark:event-store",
    target_snapshot_id=TARGET_ID,
)
AUTHORITY_GRANT = AUTHORITY_GRANT_VALUE.to_envelope()
AUTHORITY_ID = AUTHORITY_GRANT_VALUE.grant_id
AUTHORITY_SIGNER = AuthoritySigner.generate()
SIGNED_AUTHORITY_GRANT = AUTHORITY_SIGNER.sign(AUTHORITY_GRANT_VALUE)
AUTHORITY_TRUST = TrustStore.from_keys(
    (
        TrustedAuthorityKey(
            public_key_bytes=AUTHORITY_SIGNER.public_key_bytes,
            roles=frozenset({"operator"}),
            issuers=frozenset({"operator:daniel"}),
        ),
    )
)
AUTHORITY_ADMISSION = AuthorityAdmissionV1.issue(
    grant=AUTHORITY_GRANT_VALUE,
    signed_grant=SIGNED_AUTHORITY_GRANT,
    signer_key_id=AUTHORITY_SIGNER.key_id,
    trust_store=AUTHORITY_TRUST,
    decision_time=1_750_000_000,
    required_actions=("static_analysis",),
    target_snapshot_id=TARGET_ID,
)
KEY_ID = AUTHORITY_SIGNER.key_id
SIGNATURE_B64 = SIGNED_AUTHORITY_GRANT.signature_b64

_UNITS = {
    "authority_admitted": "AQUILA",
    "mission_admission_refused": "AQUILA",
    "mission_opened": "ETZIO",
    "analysis_lease_issued": "AQUILA",
    "candidate_recorded": "VELITES",
    "parse_failed": "VELITES",
    "scan_completed": "VELITES",
    "mission_closed": "ETZIO",
    "scan_failed": "ETZIO",
    "scan_timed_out": "ETZIO",
    "scan_cancelled": "AQUILA",
    "budget_exhausted": "AQUILA",
}


def store_path(tmp_path: Path, name: str = "events.sqlite3") -> Path:
    """Use a physical, explicitly private directory on symlinked-temp-dir platforms."""

    private = tmp_path.resolve()
    os.chmod(private, 0o700)
    return private / name


def lease_envelope(
    *,
    mission_id: str = MISSION_ID,
    authority_id: str = AUTHORITY_ID,
    target_id: str = TARGET_ID,
    issued_at: int = 1_750_000_000,
    expires_at: int = 1_750_000_060,
    max_bytes: int = 1_000_000,
    max_candidates: int = 100,
    max_wallclock_seconds: int = 60,
) -> EnvelopeV1:
    return EnvelopeV1.create(
        "analysis_lease",
        {
            "action": "static_analysis",
            "authority_id": authority_id,
            "expires_at": expires_at,
            "issued_at": issued_at,
            "lease_nonce": "6" * 32,
            "max_bytes": max_bytes,
            "max_candidates": max_candidates,
            "max_wallclock_seconds": max_wallclock_seconds,
            "mission_id": mission_id,
            "target_snapshot_id": target_id,
            "worker_identity": "VELITES",
        },
    )


def candidate_envelope(
    seq: int,
    *,
    mission_id: str = MISSION_ID,
    authority_id: str = AUTHORITY_ID,
    target_id: str = TARGET_ID,
    lease: EnvelopeV1 | None = None,
) -> EnvelopeV1:
    if lease is None:
        lease = lease_envelope(
            mission_id=mission_id,
            authority_id=authority_id,
            target_id=target_id,
        )
    finding = StaticFinding(
        rule_id=f"PY{seq:03d}",
        severity="high",
        message="test-only candidate",
        file="fixture/app.py",
        line=seq + 1,
        column=seq,
        symbol=f"fixture.symbol_{seq}",
        snippet="sensitive source excluded from candidate",
    )
    return StaticCandidateV1.from_finding(
        finding,
        mission_id=mission_id,
        authority_id=authority_id,
        analysis_lease_id=lease.object_id,
        target_snapshot_id=target_id,
        source_artifact_digest=SOURCE_DIGEST,
    ).to_envelope()


def valid_payload(
    kind: str,
    seq: int,
    *,
    mission_id: str = MISSION_ID,
    authority_id: str = AUTHORITY_ID,
    target_id: str = TARGET_ID,
    candidate_count: int = 0,
    parse_failure_count: int = 0,
) -> dict[str, object]:
    lease = lease_envelope(
        mission_id=mission_id,
        authority_id=authority_id,
        target_id=target_id,
    )
    if kind == "authority_admitted":
        return {
            "admission": AUTHORITY_ADMISSION.to_envelope().to_dict(),
            "grant": AUTHORITY_GRANT.to_dict(),
            "key_id": KEY_ID,
            "signature_b64": SIGNATURE_B64,
        }
    if kind == "mission_admission_refused":
        return {"reason_code": "authority_expired", "stage": "admission"}
    if kind == "mission_opened":
        return {"target_snapshot": TARGET_SNAPSHOT.to_dict()}
    if kind == "analysis_lease_issued":
        return {"lease": lease.to_dict()}
    if kind == "candidate_recorded":
        return {
            "candidate": candidate_envelope(
                seq,
                mission_id=mission_id,
                authority_id=authority_id,
                target_id=target_id,
            ).to_dict()
        }
    if kind == "parse_failed":
        return {
            "analysis_lease_id": lease.object_id,
            "parse_failure": {
                "column": 2,
                "line": 4,
                "reason_code": "syntax_error",
                "relative_path": "fixture/broken.py",
            },
            "source_artifact_digest": SOURCE_DIGEST,
        }
    if kind == "scan_completed":
        return {
            "analyzer_version": "python_ast.v1",
            "bytes_scanned": 192,
            "candidate_count": candidate_count,
            "file_count": 2,
            "parse_failure_count": parse_failure_count,
        }
    if kind == "mission_closed":
        return {
            "candidate_count": candidate_count,
            "parse_failure_count": parse_failure_count,
            "status": "completed",
        }
    if kind in {
        "scan_failed",
        "scan_timed_out",
        "scan_cancelled",
        "budget_exhausted",
    }:
        return {"reason_code": f"fixture_{kind}"}
    raise AssertionError(f"test helper has no payload for {kind}")


def output_payload_for_lease(
    kind: str,
    seq: int,
    lease: EnvelopeV1,
) -> dict[str, object]:
    if kind == "candidate_recorded":
        return {
            "candidate": candidate_envelope(seq, lease=lease).to_dict(),
        }
    if kind == "parse_failed":
        return {
            "analysis_lease_id": lease.object_id,
            "parse_failure": {
                "column": 2,
                "line": 4,
                "reason_code": "syntax_error",
                "relative_path": "fixture/broken.py",
            },
            "source_artifact_digest": SOURCE_DIGEST,
        }
    raise AssertionError(f"not an analyzer output kind: {kind}")


def make_event(
    kind: str,
    seq: int,
    prev_digest: str,
    *,
    mission_id: str = MISSION_ID,
    authority_id: str = AUTHORITY_ID,
    target_id: str = TARGET_ID,
    payload: dict[str, object] | None = None,
    unit: str | None = None,
    decision_time: int | None = None,
    candidate_count: int = 0,
    parse_failure_count: int = 0,
) -> EventV1:
    return EventV1.create(
        mission_id=mission_id,
        seq=seq,
        kind=kind,
        unit=unit or _UNITS[kind],
        authority_id=authority_id,
        target_id=target_id,
        decision_time=decision_time or 1_750_000_000 + seq,
        payload=(
            payload
            if payload is not None
            else valid_payload(
                kind,
                seq,
                mission_id=mission_id,
                authority_id=authority_id,
                target_id=target_id,
                candidate_count=candidate_count,
                parse_failure_count=parse_failure_count,
            )
        ),
        prev_digest=prev_digest,
    )


def make_chain(
    kinds: list[str],
    *,
    mission_id: str = MISSION_ID,
) -> tuple[EventV1, ...]:
    events: list[EventV1] = []
    previous = GENESIS_DIGEST
    candidate_count = 0
    parse_failure_count = 0
    for seq, kind in enumerate(kinds):
        event = make_event(
            kind,
            seq,
            previous,
            mission_id=mission_id,
            candidate_count=candidate_count,
            parse_failure_count=parse_failure_count,
        )
        events.append(event)
        previous = event.event_digest
        if kind == "candidate_recorded":
            candidate_count += 1
        elif kind == "parse_failed":
            parse_failure_count += 1
    return tuple(events)


def successful_chain() -> tuple[EventV1, ...]:
    return make_chain(
        [
            "authority_admitted",
            "mission_opened",
            "analysis_lease_issued",
            "candidate_recorded",
            "parse_failed",
            "candidate_recorded",
            "scan_completed",
            "mission_closed",
        ]
    )


def append_all(store: SQLiteEventStore, events: tuple[EventV1, ...]) -> None:
    head = GENESIS_DIGEST
    for event in events:
        store.append(event, expected_head=head)
        head = event.event_digest


def raw_insert(connection: sqlite3.Connection, event: EventV1) -> None:
    connection.execute(
        """
        INSERT INTO events (
            mission_id, seq, digest, prev_digest, kind, canonical
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event.mission_id,
            event.seq,
            event.event_digest,
            event.prev_digest,
            event.kind,
            sqlite3.Binary(event.to_canonical_bytes()),
        ),
    )


def test_event_uses_common_envelope_and_protocol_schema() -> None:
    event = make_event("authority_admitted", 0, GENESIS_DIGEST)
    raw = event.to_canonical_bytes()
    envelope = EnvelopeV1.from_bytes(raw)
    decoded = strict_loads(raw)

    Draft202012Validator(protocol_v1_schema()).validate(decoded)

    assert envelope.object_kind == "event"
    assert envelope.object_id == event.object_id == event.event_digest
    assert envelope.attestations == ()
    assert set(decoded) == {
        "attestations",
        "body",
        "object_id",
        "object_kind",
        "object_version",
        "protocol_version",
    }
    assert EventV1.from_canonical_bytes(raw) == event


def test_event_payload_is_detached_and_deeply_immutable() -> None:
    source = valid_payload("candidate_recorded", 3)
    event = make_event(
        "candidate_recorded",
        3,
        GENESIS_DIGEST,
        payload=source,
    )
    original_bytes = event.to_canonical_bytes()

    source["candidate"]["body"]["symbol"] = "caller.mutated"  # type: ignore[index]
    payload = event.payload
    assert payload["candidate"]["body"]["symbol"] == "fixture.symbol_3"
    with pytest.raises(TypeError):
        payload["candidate"]["body"]["symbol"] = "forbidden"
    with pytest.raises(FrozenInstanceError):
        event.kind = "tampered"
    assert event.to_canonical_bytes() == original_bytes


def test_every_semantic_field_is_committed() -> None:
    event = make_event("authority_admitted", 0, GENESIS_DIGEST)
    with pytest.raises(EventIntegrityError, match="authority admission"):
        replace(event, decision_time=event.decision_time + 1)
    with pytest.raises(EventIntegrityError, match="authored"):
        replace(event, unit="VELITES")
    with pytest.raises(EventIntegrityError):
        replace(event, payload_bytes=b"{}")


def test_noncanonical_event_bytes_are_rejected_by_common_parser() -> None:
    event = make_event("authority_admitted", 0, GENESIS_DIGEST)
    noncanonical = event.to_canonical_bytes().replace(
        b'{"attestations"', b'{ "attestations"', 1
    )
    with pytest.raises(EventIntegrityError, match="canonical"):
        EventV1.from_canonical_bytes(noncanonical)


def test_event_semantics_reject_wrong_identity_unit_and_payload() -> None:
    payload = valid_payload("authority_admitted", 0)
    with pytest.raises(EventIntegrityError, match="mission_id"):
        EventV1.create(
            mission_id="mission-not-a-digest",
            seq=0,
            kind="authority_admitted",
            unit="AQUILA",
            authority_id=AUTHORITY_ID,
            target_id=TARGET_ID,
            decision_time=1,
            payload=payload,
            prev_digest=GENESIS_DIGEST,
        )
    with pytest.raises(EventIntegrityError, match="AQUILA"):
        make_event(
            "authority_admitted",
            0,
            GENESIS_DIGEST,
            payload=payload,
            unit="VELITES",
        )
    with pytest.raises(EventIntegrityError, match="keys differ"):
        make_event(
            "authority_admitted",
            0,
            GENESIS_DIGEST,
            payload={},
        )
    malformed = dict(valid_payload("scan_completed", 3))
    malformed["candidate_count"] = True
    with pytest.raises(EventIntegrityError, match="non-negative integer"):
        make_event("scan_completed", 3, GENESIS_DIGEST, payload=malformed)


def test_nested_envelope_kind_and_binding_are_enforced() -> None:
    wrong_kind = valid_payload("mission_opened", 1)
    wrong_kind["target_snapshot"] = EnvelopeV1.create(
        "candidate", {"fixture": "wrong-kind"}
    ).to_dict()
    with pytest.raises(EventIntegrityError, match="target_snapshot envelope"):
        make_event("mission_opened", 1, GENESIS_DIGEST, payload=wrong_kind)

    wrong_lease = valid_payload("analysis_lease_issued", 2)
    wrong_lease["lease"] = lease_envelope(mission_id=OTHER_MISSION_ID).to_dict()
    with pytest.raises(EventIntegrityError, match="identities"):
        make_event("analysis_lease_issued", 2, GENESIS_DIGEST, payload=wrong_lease)


def test_forged_expected_kind_envelopes_fail_typed_validation() -> None:
    forged_admission = valid_payload("authority_admitted", 0)
    forged_admission["admission"] = EnvelopeV1.create(
        "authority_admission",
        {"authority_id": AUTHORITY_ID, "target_snapshot_id": TARGET_ID},
    ).to_dict()
    with pytest.raises(EventIntegrityError, match="invalid authority evidence"):
        make_event(
            "authority_admitted",
            0,
            GENESIS_DIGEST,
            payload=forged_admission,
        )

    forged_snapshot = {
        "target_snapshot": EnvelopeV1.create(
            "target_snapshot",
            {"files": [], "source": "repository_fixture"},
        ).to_dict()
    }
    with pytest.raises(EventIntegrityError, match="invalid target snapshot"):
        make_event(
            "mission_opened",
            1,
            GENESIS_DIGEST,
            payload=forged_snapshot,
        )

    forged_lease = {
        "lease": EnvelopeV1.create(
            "analysis_lease",
            {
                "authority_id": AUTHORITY_ID,
                "mission_id": MISSION_ID,
                "target_snapshot_id": TARGET_ID,
            },
        ).to_dict()
    }
    with pytest.raises(EventIntegrityError, match="invalid lease"):
        make_event(
            "analysis_lease_issued",
            2,
            GENESIS_DIGEST,
            payload=forged_lease,
        )

    forged_candidate = {
        "candidate": EnvelopeV1.create(
            "candidate",
            {
                "analysis_lease_id": lease_envelope().object_id,
                "authority_id": AUTHORITY_ID,
                "mission_id": MISSION_ID,
                "target_snapshot_id": TARGET_ID,
            },
        ).to_dict()
    }
    with pytest.raises(EventIntegrityError, match="invalid candidate"):
        make_event(
            "candidate_recorded",
            3,
            GENESIS_DIGEST,
            payload=forged_candidate,
        )


def test_authority_event_requires_literal_static_analysis_authority() -> None:
    grant = AuthorityGrantV1.issue(
        assets=("fixture://app.py",),
        evidence_digest=content_id("artifact", {"fixture": "alternate-authority"}),
        expires_at=1_800_000_000,
        issued_at=1_700_000_000,
        issuer="operator:daniel",
        max_bytes=1_000_000,
        max_candidates=100,
        max_wallclock_seconds=60,
        not_before=1_700_000_000,
        permitted_actions=("modeled_fixture_verification",),
        subject="benchmark:event-store",
        target_snapshot_id=TARGET_ID,
    )
    signed = AUTHORITY_SIGNER.sign(grant)
    admission = AuthorityAdmissionV1.issue(
        grant=grant,
        signed_grant=signed,
        signer_key_id=AUTHORITY_SIGNER.key_id,
        trust_store=AUTHORITY_TRUST,
        decision_time=1_750_000_000,
        required_actions=("modeled_fixture_verification",),
        target_snapshot_id=TARGET_ID,
    )
    payload = {
        "admission": admission.to_envelope().to_dict(),
        "grant": grant.to_envelope().to_dict(),
        "key_id": signed.key_id,
        "signature_b64": signed.signature_b64,
    }

    with pytest.raises(EventIntegrityError, match="does not authorize"):
        make_event(
            "authority_admitted",
            0,
            GENESIS_DIGEST,
            authority_id=grant.grant_id,
            payload=payload,
        )


def test_lease_expiry_cannot_exceed_its_wallclock_ceiling() -> None:
    lease = lease_envelope(
        expires_at=1_750_000_061,
        max_wallclock_seconds=60,
    )
    with pytest.raises(EventIntegrityError, match="wallclock ceiling"):
        make_event(
            "analysis_lease_issued",
            2,
            GENESIS_DIGEST,
            payload={"lease": lease.to_dict()},
        )


def test_lease_rejects_target_larger_than_byte_budget_before_persistence(
    tmp_path: Path,
) -> None:
    path = store_path(tmp_path)
    prefix = make_chain(["authority_admitted", "mission_opened"])
    lease = lease_envelope(max_bytes=191)
    lease_event = make_event(
        "analysis_lease_issued",
        2,
        prefix[-1].event_digest,
        payload={"lease": lease.to_dict()},
    )

    with SQLiteEventStore(path) as store:
        append_all(store, prefix)
        with pytest.raises(EventStoreError, match="byte budget"):
            store.append(lease_event, expected_head=prefix[-1].event_digest)
        assert store.load(MISSION_ID) == prefix


@pytest.mark.parametrize(
    ("first_kind", "overflow_kind"),
    [
        ("candidate_recorded", "parse_failed"),
        ("parse_failed", "candidate_recorded"),
    ],
)
def test_each_analyzer_output_enforces_shared_output_budget_before_persistence(
    tmp_path: Path,
    first_kind: str,
    overflow_kind: str,
) -> None:
    path = store_path(tmp_path, f"{first_kind}-then-{overflow_kind}.sqlite3")
    prefix = make_chain(["authority_admitted", "mission_opened"])
    lease = lease_envelope(max_candidates=1)
    lease_event = make_event(
        "analysis_lease_issued",
        2,
        prefix[-1].event_digest,
        payload={"lease": lease.to_dict()},
    )
    first = make_event(
        first_kind,
        3,
        lease_event.event_digest,
        payload=output_payload_for_lease(first_kind, 3, lease),
    )
    overflow = make_event(
        overflow_kind,
        4,
        first.event_digest,
        payload=output_payload_for_lease(overflow_kind, 4, lease),
    )
    retained = (*prefix, lease_event, first)

    with SQLiteEventStore(path) as store:
        append_all(store, retained)
        with pytest.raises(EventStoreError, match="output budget"):
            store.append(overflow, expected_head=first.event_digest)
        assert store.load(MISSION_ID) == retained


@pytest.mark.parametrize("output_kind", ["candidate_recorded", "parse_failed"])
def test_each_analyzer_output_enforces_retained_epoch_wallclock_before_persistence(
    tmp_path: Path,
    output_kind: str,
) -> None:
    path = store_path(tmp_path, f"{output_kind}-wallclock.sqlite3")
    prefix = make_chain(["authority_admitted", "mission_opened"])
    lease = lease_envelope(
        expires_at=1_750_000_003,
        max_wallclock_seconds=3,
    )
    lease_event = make_event(
        "analysis_lease_issued",
        2,
        prefix[-1].event_digest,
        payload={"lease": lease.to_dict()},
    )
    late = make_event(
        output_kind,
        3,
        lease_event.event_digest,
        decision_time=1_750_000_004,
        payload=output_payload_for_lease(output_kind, 3, lease),
    )
    retained = (*prefix, lease_event)

    with SQLiteEventStore(path) as store:
        append_all(store, retained)
        with pytest.raises(EventStoreError, match="epoch wallclock ceiling"):
            store.append(late, expected_head=lease_event.event_digest)
        assert store.load(MISSION_ID) == retained


def test_store_uses_hardened_sqlite_settings_without_write_handle(
    tmp_path: Path,
) -> None:
    path = store_path(tmp_path)
    path.touch(mode=0o666)
    os.chmod(path, 0o666)

    with SQLiteEventStore(path) as store:
        diagnostics = store.diagnostics()
        assert diagnostics.journal_mode == "wal"
        assert diagnostics.synchronous == 2
        assert diagnostics.foreign_keys
        assert diagnostics.database_mode == 0o600
        assert not hasattr(store, "connection")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_store_requires_private_nonsymlink_directory_chain(tmp_path: Path) -> None:
    with pytest.raises(EventStoreError, match="explicit"):
        SQLiteEventStore(":memory:")
    with pytest.raises(EventStoreError, match="parent"):
        SQLiteEventStore(tmp_path.resolve() / "missing" / "events.sqlite3")

    broad = tmp_path.resolve() / "broad"
    broad.mkdir(mode=0o755)
    with pytest.raises(EventStoreError, match="0700"):
        SQLiteEventStore(broad / "events.sqlite3")

    private = tmp_path.resolve() / "private"
    private.mkdir(mode=0o700)
    link = tmp_path.resolve() / "linked-parent"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(EventStoreError, match="symbolic"):
        SQLiteEventStore(link / "events.sqlite3")


def test_only_root_owned_sticky_temp_is_a_writable_ancestor_trust_boundary() -> None:
    sticky_mode = stat.S_IFDIR | stat.S_ISVTX | 0o777

    assert SQLiteEventStore._is_trusted_sticky_root(
        directory_uid=0,
        directory_mode=sticky_mode,
        effective_uid=1000,
    )
    assert not SQLiteEventStore._is_trusted_sticky_root(
        directory_uid=1001,
        directory_mode=sticky_mode,
        effective_uid=1000,
    )
    assert not SQLiteEventStore._is_trusted_sticky_root(
        directory_uid=0,
        directory_mode=stat.S_IFDIR | 0o777,
        effective_uid=1000,
    )
    assert not SQLiteEventStore._is_trusted_sticky_root(
        directory_uid=0,
        directory_mode=sticky_mode,
        effective_uid=0,
    )


def test_database_symlink_is_rejected(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    real = root / "real.sqlite3"
    real.touch(mode=0o600)
    link = root / "link.sqlite3"
    link.symlink_to(real)
    with pytest.raises(EventStoreError, match="symbolic"):
        SQLiteEventStore(link)


def test_database_hard_link_is_rejected_before_sqlite_open(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    os.chmod(root, 0o700)
    original = root / "original.sqlite3"
    original.touch(mode=0o600)
    linked = root / "linked.sqlite3"
    os.link(original, linked)

    with pytest.raises(EventStoreError, match="exactly one filesystem link"):
        SQLiteEventStore(linked)

    assert original.stat().st_size == 0
    assert stat.S_IMODE(original.stat().st_mode) == 0o600


def test_restart_replay_matches_original_projection(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    events = successful_chain()

    with SQLiteEventStore(path) as first:
        append_all(first, events[:4])
        interrupted = reduce_events(first.load(MISSION_ID))
        assert interrupted.phase is ProjectionPhase.ANALYZING

    with SQLiteEventStore(path) as resumed:
        head = resumed.head(MISSION_ID)
        for event in events[4:]:
            resumed.append(event, expected_head=head)
            head = event.event_digest
        replayed = reduce_events(resumed.load(MISSION_ID))

    assert replayed == reduce_events(events)
    assert replayed.phase is ProjectionPhase.CLOSED
    assert replayed.events == events
    assert len(replayed.candidate_events) == 2
    assert len(replayed.parse_failures) == 1


def test_compare_and_append_rejects_stale_head(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    first, second = make_chain(["authority_admitted", "mission_opened"])
    with SQLiteEventStore(path) as store:
        store.append(first, expected_head=GENESIS_DIGEST)
        with pytest.raises(StaleHeadError, match="stale"):
            store.append(second, expected_head=GENESIS_DIGEST)
        assert store.load(MISSION_ID) == (first,)


def test_concurrent_compare_and_append_commits_exactly_one_genesis_event(
    tmp_path: Path,
) -> None:
    path = store_path(tmp_path)
    event = make_event("authority_admitted", 0, GENESIS_DIGEST)
    with SQLiteEventStore(path):
        pass
    barrier = threading.Barrier(2)

    def attempt() -> str:
        with SQLiteEventStore(path) as store:
            barrier.wait(timeout=5)
            try:
                store.append(event, expected_head=GENESIS_DIGEST)
            except StaleHeadError:
                return "stale"
            return "committed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _: attempt(), range(2)))

    assert outcomes == ["committed", "stale"]
    with SQLiteEventStore(path) as store:
        assert store.load(MISSION_ID) == (event,)


def test_store_rejects_illegal_seq_zero_without_persistence(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    illegal = make_event("mission_opened", 0, GENESIS_DIGEST)
    with SQLiteEventStore(path) as store:
        with pytest.raises(EventStoreError, match="illegal mission lifecycle"):
            store.append(illegal, expected_head=GENESIS_DIGEST)
        assert store.load(MISSION_ID) == ()
        assert store.head(MISSION_ID) == GENESIS_DIGEST


def test_store_rejects_illegal_transition_without_persistence(
    tmp_path: Path,
) -> None:
    path = store_path(tmp_path)
    admitted = make_event("authority_admitted", 0, GENESIS_DIGEST)
    illegal = make_event(
        "analysis_lease_issued",
        1,
        admitted.event_digest,
    )
    with SQLiteEventStore(path) as store:
        store.append(admitted, expected_head=GENESIS_DIGEST)
        with pytest.raises(EventStoreError, match="illegal mission lifecycle"):
            store.append(illegal, expected_head=admitted.event_digest)
        assert store.load(MISSION_ID) == (admitted,)


def test_store_rejects_sequence_gap_and_forked_predecessor(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    with SQLiteEventStore(path) as store:
        gap = make_event("mission_opened", 1, GENESIS_DIGEST)
        with pytest.raises(EventStoreError, match="sequence gap"):
            store.append(gap, expected_head=GENESIS_DIGEST)

        first = make_event("authority_admitted", 0, GENESIS_DIGEST)
        store.append(first, expected_head=GENESIS_DIGEST)
        fork = make_event("mission_opened", 1, GENESIS_DIGEST)
        with pytest.raises(StaleHeadError, match="predecessor"):
            store.append(fork, expected_head=first.event_digest)


def test_database_trigger_rejects_gap_without_public_write_bypass(
    tmp_path: Path,
) -> None:
    path = store_path(tmp_path)
    with SQLiteEventStore(path):
        pass
    gap = make_event("mission_opened", 2, GENESIS_DIGEST)
    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="gap or fork"):
            raw_insert(connection, gap)
    finally:
        connection.close()


def test_database_rejects_event_update_and_delete(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    first = make_event("authority_admitted", 0, GENESIS_DIGEST)
    with SQLiteEventStore(path) as store:
        store.append(first, expected_head=GENESIS_DIGEST)

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "UPDATE events SET kind = 'tampered' WHERE mission_id = ?",
                (MISSION_ID,),
            )
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "DELETE FROM events WHERE mission_id = ?",
                (MISSION_ID,),
            )
    finally:
        connection.close()

    with SQLiteEventStore(path) as store:
        assert store.load(MISSION_ID) == (first,)


def test_loading_detects_payload_tamper_after_offline_compromise(
    tmp_path: Path,
) -> None:
    path = store_path(tmp_path)
    first = make_event("authority_admitted", 0, GENESIS_DIGEST)
    with SQLiteEventStore(path) as store:
        store.append(first, expected_head=GENESIS_DIGEST)

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER events_reject_update")
        corrupt = bytearray(first.to_canonical_bytes())
        object_id_start = corrupt.index(b'"object_id":"sha256:') + len(
            b'"object_id":"sha256:'
        )
        corrupt[object_id_start] = ord("0") if corrupt[object_id_start] != ord("0") else ord("1")
        connection.execute(
            "UPDATE events SET canonical = ? WHERE mission_id = ? AND seq = 0",
            (sqlite3.Binary(bytes(corrupt)), MISSION_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with SQLiteEventStore(path) as store:
        with pytest.raises(EventStoreCorruptionError, match="invalid canonical event"):
            store.load(MISSION_ID)


def test_load_detects_offline_injected_post_close_transition(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    events = successful_chain()
    with SQLiteEventStore(path) as store:
        append_all(store, events)

    injected = make_event(
        "parse_failed",
        len(events),
        events[-1].event_digest,
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER events_validate_insert")
        raw_insert(connection, injected)
        connection.commit()
    finally:
        connection.close()

    with SQLiteEventStore(path) as store:
        with pytest.raises(
            EventStoreCorruptionError,
            match="retained mission lifecycle is invalid",
        ):
            store.load(MISSION_ID)


def test_append_after_close_is_rejected_and_stream_unchanged(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    events = successful_chain()
    with SQLiteEventStore(path) as store:
        append_all(store, events)
        extra = make_event(
            "parse_failed",
            len(events),
            events[-1].event_digest,
        )
        with pytest.raises(ClosedStreamError, match="mission_closed"):
            store.append(extra, expected_head=events[-1].event_digest)
        assert store.load(MISSION_ID) == events


def test_refusal_is_a_distinct_one_event_terminal_mission(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    refusal = make_event("mission_admission_refused", 0, GENESIS_DIGEST)
    projection = reduce_events((refusal,))
    assert projection.phase is ProjectionPhase.REFUSED
    assert projection.refusal is refusal
    assert projection.failure_event is None
    assert projection.terminal_event is refusal

    with SQLiteEventStore(path) as store:
        store.append(refusal, expected_head=GENESIS_DIGEST)
        illegal = make_event("mission_opened", 1, refusal.event_digest)
        with pytest.raises(ClosedStreamError, match="mission_admission_refused"):
            store.append(illegal, expected_head=refusal.event_digest)


@pytest.mark.parametrize(
    "kinds",
    [
        ["mission_opened"],
        ["authority_admitted", "analysis_lease_issued"],
        ["authority_admitted", "mission_opened", "scan_completed"],
        [
            "authority_admitted",
            "mission_opened",
            "analysis_lease_issued",
            "mission_closed",
        ],
        ["mission_admission_refused", "mission_opened"],
        ["scan_failed"],
    ],
)
def test_reducer_rejects_illegal_transitions(kinds: list[str]) -> None:
    with pytest.raises(ReductionError, match="illegal event transition"):
        reduce_events(make_chain(kinds))


def test_reducer_rejects_time_regression_and_summary_mismatch() -> None:
    first, second = make_chain(["authority_admitted", "mission_opened"])
    regressed = make_event(
        "mission_opened",
        1,
        first.event_digest,
        decision_time=first.decision_time - 1,
    )
    with pytest.raises(ReductionError, match="decision_time regressed"):
        reduce_events((first, regressed))

    prefix = make_chain(
        [
            "authority_admitted",
            "mission_opened",
            "analysis_lease_issued",
            "candidate_recorded",
        ]
    )
    bad_summary = make_event(
        "scan_completed",
        len(prefix),
        prefix[-1].event_digest,
        candidate_count=0,
    )
    with pytest.raises(ReductionError, match="candidate_count"):
        reduce_events((*prefix, bad_summary))


def test_store_rolls_back_summary_mismatch(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    prefix = make_chain(
        [
            "authority_admitted",
            "mission_opened",
            "analysis_lease_issued",
            "candidate_recorded",
        ]
    )
    bad_summary = make_event(
        "scan_completed",
        len(prefix),
        prefix[-1].event_digest,
        candidate_count=0,
    )
    with SQLiteEventStore(path) as store:
        append_all(store, prefix)
        with pytest.raises(EventStoreError, match="candidate_count"):
            store.append(bad_summary, expected_head=prefix[-1].event_digest)
        assert store.load(MISSION_ID) == prefix


@pytest.mark.parametrize(
    ("failure_kind", "expected_phase"),
    [
        ("scan_failed", ProjectionPhase.FAILED),
        ("scan_cancelled", ProjectionPhase.CANCELLED),
        ("scan_timed_out", ProjectionPhase.TIMED_OUT),
        ("budget_exhausted", ProjectionPhase.BUDGET_EXHAUSTED),
    ],
)
@pytest.mark.parametrize("prior_phase", ["admitted", "open", "analyzing", "completed"])
def test_failure_outcomes_are_distinct_terminal_from_every_recovery_phase(
    tmp_path: Path,
    failure_kind: str,
    expected_phase: ProjectionPhase,
    prior_phase: str,
) -> None:
    prefix_by_phase = {
        "admitted": ["authority_admitted"],
        "open": ["authority_admitted", "mission_opened"],
        "analyzing": [
            "authority_admitted",
            "mission_opened",
            "analysis_lease_issued",
        ],
        "completed": [
            "authority_admitted",
            "mission_opened",
            "analysis_lease_issued",
            "scan_completed",
        ],
    }
    events = make_chain([*prefix_by_phase[prior_phase], failure_kind])
    projection = reduce_events(events)
    assert projection.phase is expected_phase
    assert projection.failure_event is events[-1]
    assert projection.terminal_event is events[-1]
    assert projection.is_terminal

    path = store_path(tmp_path, f"{failure_kind}-{prior_phase}.sqlite3")
    with SQLiteEventStore(path) as store:
        append_all(store, events)
        extra = make_event(
            "analysis_lease_issued",
            len(events),
            events[-1].event_digest,
        )
        with pytest.raises(ClosedStreamError, match=failure_kind):
            store.append(extra, expected_head=events[-1].event_digest)


def test_mission_heads_are_independent_and_cannot_cross_link(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    event_a = make_event("authority_admitted", 0, GENESIS_DIGEST)
    event_b = make_event(
        "authority_admitted",
        0,
        GENESIS_DIGEST,
        mission_id=OTHER_MISSION_ID,
    )
    cross_linked = make_event(
        "authority_admitted",
        0,
        event_a.event_digest,
        mission_id=content_id("mission", {"fixture": "cross-linked"}),
    )
    with SQLiteEventStore(path) as store:
        store.append(event_a, expected_head=GENESIS_DIGEST)
        store.append(event_b, expected_head=GENESIS_DIGEST)
        assert store.head(MISSION_ID) == event_a.event_digest
        assert store.head(OTHER_MISSION_ID) == event_b.event_digest
        with pytest.raises(StaleHeadError, match="predecessor"):
            store.append(cross_linked, expected_head=GENESIS_DIGEST)


def test_signed_checkpoint_is_retained_as_unverified_data(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    event = make_event("authority_admitted", 0, GENESIS_DIGEST)
    checkpoint = SignedCheckpoint(
        mission_id=MISSION_ID,
        event_digest=event.event_digest,
        signer_id="operator-key-001",
        algorithm="ed25519",
        signed_at=1_750_000_100,
        signature=b"opaque-signature-bytes",
    )
    with SQLiteEventStore(path) as store:
        with pytest.raises(EventStoreError, match="retained"):
            store.store_checkpoint(checkpoint)
        store.append(event, expected_head=GENESIS_DIGEST)
        assert store.store_checkpoint(checkpoint) is checkpoint
        assert store.load_checkpoints(MISSION_ID) == (checkpoint,)

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "DELETE FROM signed_checkpoints WHERE mission_id = ?",
                (MISSION_ID,),
            )
    finally:
        connection.close()
