"""Adversarial evidence for atomic event-and-artifact retention.

The filesystem evidence store is staging only.  These controls require every
byte-claiming event to commit its code-derived artifact manifest and exact bytes in the
same SQLite transaction as the canonical event.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from etzio.authority import (
    AuthorityAdmissionV1,
    AuthorityGrantV1,
    AuthoritySigner,
    TrustedAuthorityKey,
    TrustStore,
)
from etzio.evidence import (
    MAX_AUTHORITY_EVIDENCE_BYTES_V1,
    VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1,
    VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1,
    FileEvidenceStore,
    SnapshotFileV1,
    TargetSnapshotV1,
    evidence_digest,
    read_etzio_fixture,
    retain_snapshot,
)
from etzio.kernel.artifact_resolution import (
    resolve_modeled_fixture_verification_artifacts,
)
from etzio.kernel.events_v1 import GENESIS_DIGEST, EventV1
from etzio.kernel.evidence_vault import (
    DEFAULT_MAX_VAULT_BYTES_V1,
    MAX_VAULT_BATCH_REQUESTS_V1,
    NON_RECEIPT_EVIDENCE_EVENT_KINDS_V1,
    PROTECTED_EVIDENCE_EVENT_KINDS_V1,
    VERIFICATION_EFFECT_OUTPUT_ROLE_V1,
    VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1,
    VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
    VERIFICATION_POC_INPUT_ROLE_V1,
    VaultArtifactRefV1,
    VaultArtifactResolutionRequestV1,
    VaultEventArtifactSelectorV1,
    derive_event_artifact_manifest_v1,
)
from etzio.kernel.fixture_scan import prepare_fixture_scan_for_verification
from etzio.kernel.receipt_admission import (
    admit_modeled_fixture_verifier_receipt,
)
from etzio.kernel.store import (
    EventStoreCorruptionError,
    EventStoreError,
    EvidenceVaultCapacityError,
    EvidenceVaultRequestError,
    SQLiteEventStore,
    StaleHeadError,
    StoreOperationalError,
)
from etzio.kernel.verification_lease import (
    issue_modeled_fixture_verification_lease,
)
from etzio.protocol import canonical_dumps, content_id, thaw_json
from etzio.verification import (
    MODELED_FIXTURE_TIER,
    VERIFIER_ROLE,
    TrustedVerifierKey,
    VerifierReceiptV1,
    VerifierSigner,
    VerifierTrustStore,
)

NOW = 2_000_000_000
_ARTIFACT_TABLE = "evidence_artifacts"
_EVENT_ARTIFACT_TABLE = "event_artifact_roles"


@dataclass(frozen=True, slots=True)
class _VaultHarness:
    database: Path
    evidence_store: FileEvidenceStore
    mission_id: str
    snapshot: TargetSnapshotV1
    authority_evidence_digest: str
    authority_evidence_bytes: bytes
    fixture_bytes: bytes
    events: tuple[EventV1, ...]


class _TransactionSabotageEvidenceStore(FileEvidenceStore):
    """A hostile subclass that tries to end the event store's transaction."""

    def __init__(
        self,
        root: Path,
        *,
        connection: sqlite3.Connection,
        statement: str,
    ) -> None:
        super().__init__(root)
        self.connection = connection
        self.statement = statement
        self.read_attempts = 0

    def _sabotage(self) -> None:
        self.read_attempts += 1
        self.connection.execute(self.statement)

    def get(
        self,
        digest: str,
        *,
        maximum: int | None = None,
    ) -> bytes:
        self._sabotage()
        return super().get(digest, maximum=maximum)

    def get_typed(
        self,
        digest: str,
        *,
        expected_type: str,
        maximum: int | None = None,
    ) -> bytes:
        self._sabotage()
        return super().get_typed(
            digest,
            expected_type=expected_type,
            maximum=maximum,
        )


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _put_typed_inputs(
    store: FileEvidenceStore,
) -> tuple[dict[str, object], int]:
    poc = store.put_typed(
        b"inert-poc",
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["poc"],
    )
    supporting = tuple(
        sorted(
            (
                store.put_typed(
                    b"supporting-a",
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
                ),
                store.put_typed(
                    b"supporting-b",
                    artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["evidence"],
                ),
            ),
            key=lambda value: value.digest,
        )
    )
    environment = store.put_typed(
        b"environment-spec",
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["environment"],
    )
    oracle = store.put_typed(
        b"effect-oracle",
        artifact_type=VERIFICATION_ARTIFACT_TYPE_BY_ROLE_V1["effect_oracle"],
    )
    return (
        {
            "effect_oracle_id": oracle.digest,
            "environment_digest": environment.digest,
            "evidence_artifact_digests": tuple(value.digest for value in supporting),
            "poc_artifact_digest": poc.digest,
        },
        (poc.size + environment.size + oracle.size + sum(value.size for value in supporting)),
    )


def _put_typed_outputs(
    store: FileEvidenceStore,
) -> tuple[dict[str, tuple[str, int]], int]:
    outputs: dict[str, tuple[str, int]] = {}
    total = 0
    for role, data in (
        ("execution_output", b"execution-transcript"),
        ("effect_output", b"effect-observation"),
        ("measured_environment_output", b"measured-environment"),
        ("termination_output", b"termination-record"),
    ):
        retained = store.put_typed(
            data,
            artifact_type=VERIFICATION_OUTPUT_ARTIFACT_TYPE_BY_ROLE_V1[role],
        )
        outputs[role] = (retained.digest, retained.size)
        total += retained.size
    return outputs, total


def _build_harness(
    root: Path,
    *,
    authority_marker: str = "transactional_vault_test_authority",
) -> _VaultHarness:
    _private_directory(root)
    evidence_store = FileEvidenceStore(root / "evidence")
    relative_path, fixture_bytes = read_etzio_fixture(
        "vulnerable_app.py",
        maximum=64 * 1024,
    )
    snapshot = retain_snapshot(
        "repository_fixture",
        {relative_path: fixture_bytes},
        evidence_store,
    )
    inputs, input_bytes = _put_typed_inputs(evidence_store)
    outputs, output_bytes = _put_typed_outputs(evidence_store)
    authority_evidence_bytes = canonical_dumps(
        {
            "fixture": relative_path,
            "kind": authority_marker,
        }
    )
    authority_evidence = evidence_store.put(authority_evidence_bytes)
    authority_signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:transactional-evidence-vault",
        target_snapshot_id=snapshot.object_id,
        assets=(f"fixture://{relative_path}",),
        permitted_actions=(
            "modeled_fixture_verification",
            "static_analysis",
        ),
        evidence_digest=authority_evidence.digest,
        issued_at=NOW - 1,
        not_before=NOW,
        expires_at=NOW + 300,
        max_bytes=len(fixture_bytes) + input_bytes + output_bytes + 1024,
        max_candidates=100,
        max_wallclock_seconds=120,
    )
    signed_grant = authority_signer.sign(grant)
    authority_trust = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                public_key_bytes=authority_signer.public_key_bytes,
                roles=frozenset({"operator"}),
                issuers=frozenset({"operator:daniel"}),
            ),
        )
    )
    verifier_signer = VerifierSigner.generate()
    verifier_trust = VerifierTrustStore.from_keys(
        (
            TrustedVerifierKey(
                verifier_id="CATO",
                public_key_bytes=verifier_signer.public_key_bytes,
                roles=frozenset({VERIFIER_ROLE}),
            ),
        )
    )
    mission_id = content_id(
        "mission",
        {
            "fixture": relative_path,
            "nonce": "transactional-evidence-vault-v1",
        },
    )
    database = root / "events.sqlite3"
    with SQLiteEventStore(database) as event_store:
        prepared = prepare_fixture_scan_for_verification(
            mission_id=mission_id,
            snapshot=snapshot,
            signed_authority=signed_grant,
            trust_store=authority_trust,
            evidence_store=evidence_store,
            event_store=event_store,
            decision_time=NOW,
        )
        candidate_id = thaw_json(prepared.candidate_events[0].payload)["candidate"]["object_id"]
        issuance = issue_modeled_fixture_verification_lease(
            event_store=event_store,
            mission_id=mission_id,
            expected_head=prepared.events[-1].event_digest,
            candidate_id=candidate_id,
            **inputs,
            verifier_key_id=verifier_signer.key_id,
            verifier_trust_store=verifier_trust,
            decision_time=NOW + 1,
            requested_wallclock_seconds=60,
        )
        resolution = resolve_modeled_fixture_verification_artifacts(
            event_store=event_store,
            evidence_store=evidence_store,
            mission_id=mission_id,
            expected_head=issuance.event.event_digest,
            verification_lease_id=issuance.lease.lease_id,
            decision_time=NOW + 2,
        )
        receipt = VerifierReceiptV1.for_lease(
            issuance.lease,
            artifact_resolution_id=resolution.resolution.resolution_id,
            execution_output_digest=outputs["execution_output"][0],
            execution_output_size=outputs["execution_output"][1],
            effect_output_digest=outputs["effect_output"][0],
            effect_output_size=outputs["effect_output"][1],
            measured_environment_output_digest=outputs["measured_environment_output"][0],
            measured_environment_output_size=outputs["measured_environment_output"][1],
            termination_output_digest=outputs["termination_output"][0],
            termination_output_size=outputs["termination_output"][1],
            evidence_tier=MODELED_FIXTURE_TIER,
            verdict="confirmed",
            effect_observed=True,
            oracle_satisfied=True,
            completed_at=NOW + 3,
        )
        admitted = admit_modeled_fixture_verifier_receipt(
            event_store=event_store,
            evidence_store=evidence_store,
            mission_id=mission_id,
            expected_head=resolution.event.event_digest,
            verification_lease_id=issuance.lease.lease_id,
            signed_receipt=verifier_signer.sign(receipt),
            decision_trust_store=verifier_trust,
            decision_time=NOW + 4,
        )
        events = event_store.load(mission_id)
        assert events == admitted.projection.events
    return _VaultHarness(
        database=database,
        evidence_store=evidence_store,
        mission_id=mission_id,
        snapshot=snapshot,
        authority_evidence_digest=authority_evidence.digest,
        authority_evidence_bytes=authority_evidence_bytes,
        fixture_bytes=fixture_bytes,
        events=events,
    )


@pytest.fixture
def vault_harness(tmp_path: Path) -> _VaultHarness:
    return _build_harness(tmp_path / "source")


def _event(harness: _VaultHarness, kind: str) -> EventV1:
    matches = tuple(event for event in harness.events if event.kind == kind)
    assert len(matches) == 1
    return matches[0]


def _append_protected_prefix(
    store: SQLiteEventStore,
    events: tuple[EventV1, ...],
    *,
    stop_before: EventV1,
    evidence_store: FileEvidenceStore,
) -> tuple[EventV1, ...]:
    appended: list[EventV1] = []
    head = GENESIS_DIGEST
    for event in events:
        if event == stop_before:
            break
        if event.kind in NON_RECEIPT_EVIDENCE_EVENT_KINDS_V1:
            store.append_evidence_event(
                event,
                expected_head=head,
                evidence_store=evidence_store,
            )
        elif event.kind == "verifier_receipt_admitted":
            store.append_receipt_admission(
                event,
                expected_head=head,
                evidence_store=evidence_store,
            )
        else:
            store.append(event, expected_head=head)
        appended.append(event)
        head = event.event_digest
    return tuple(appended)


def _raw_insert_event(connection: sqlite3.Connection, event: EventV1) -> None:
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


def test_locked_receipt_revalidation_preserves_store_failure_classification(
    vault_harness: _VaultHarness,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import etzio.kernel.receipt_admission as receipt_admission

    receipt_event = _event(vault_harness, "verifier_receipt_admitted")
    target_root = _private_directory(tmp_path / "classified-revalidation")
    database = target_root / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        prefix = _append_protected_prefix(
            store,
            vault_harness.events,
            stop_before=receipt_event,
            evidence_store=vault_harness.evidence_store,
        )
        before = store.load(vault_harness.mission_id)

        def fail_operationally(*, retained, event, evidence_store):
            raise StoreOperationalError("classified locked revalidation failure")

        monkeypatch.setattr(
            receipt_admission,
            "validate_retained_receipt_admission_event",
            fail_operationally,
        )
        with pytest.raises(
            StoreOperationalError,
            match="classified locked revalidation failure",
        ):
            store.append_receipt_admission(
                receipt_event,
                expected_head=prefix[-1].event_digest,
                evidence_store=vault_harness.evidence_store,
            )
        after = store.load(vault_harness.mission_id)

    assert before == prefix
    assert after == prefix


def _table_count(database: Path, table: str) -> int:
    connection = sqlite3.connect(database)
    try:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
    finally:
        connection.close()
    assert row is not None
    return int(row[0])


def _drop_table_triggers(
    connection: sqlite3.Connection,
    table: str,
) -> tuple[str, ...]:
    rows = connection.execute(
        """
        SELECT name, sql
        FROM sqlite_schema
        WHERE type = 'trigger' AND tbl_name = ? AND sql IS NOT NULL
        ORDER BY name
        """,
        (table,),
    ).fetchall()
    assert rows
    definitions: list[str] = []
    for name, definition in rows:
        assert isinstance(definition, str)
        definitions.append(definition)
        quoted = str(name).replace('"', '""')
        connection.execute(f'DROP TRIGGER "{quoted}"')
    return tuple(definitions)


def _restore_triggers(
    connection: sqlite3.Connection,
    definitions: tuple[str, ...],
) -> None:
    for definition in definitions:
        connection.execute(definition)


def _blob_column(connection: sqlite3.Connection, table: str) -> str:
    rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    matches = [str(row[1]) for row in rows if str(row[2]).upper() == "BLOB"]
    assert len(matches) == 1
    return matches[0]


def _schema_state(
    database: Path,
) -> tuple[int, int, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(database)
    try:
        application_id = connection.execute("PRAGMA application_id").fetchone()
        user_version = connection.execute("PRAGMA user_version").fetchone()
        schema_rows = tuple(
            connection.execute(
                """
                SELECT type, name, tbl_name, rootpage, sql
                FROM sqlite_schema
                ORDER BY rowid
                """
            ).fetchall()
        )
    finally:
        connection.close()
    assert application_id is not None
    assert user_version is not None
    return int(application_id[0]), int(user_version[0]), schema_rows


def _typed_artifact(
    harness: _VaultHarness,
    role: str,
) -> VaultArtifactRefV1:
    matches = tuple(
        artifact
        for event in harness.events
        for artifact in derive_event_artifact_manifest_v1(event)
        if artifact.role == role
    )
    assert len(matches) == 1
    artifact = matches[0]
    assert artifact.byte_size is not None
    return artifact


@pytest.mark.parametrize(
    "protected_kind",
    sorted(PROTECTED_EVIDENCE_EVENT_KINDS_V1),
)
def test_generic_append_rejects_every_byte_claiming_event(
    tmp_path: Path,
    vault_harness: _VaultHarness,
    protected_kind: str,
) -> None:
    event = _event(vault_harness, protected_kind)
    destination = _private_directory(tmp_path / f"generic-{protected_kind}") / "events.sqlite3"
    with SQLiteEventStore(destination) as store:
        prefix = _append_protected_prefix(
            store,
            vault_harness.events,
            stop_before=event,
            evidence_store=vault_harness.evidence_store,
        )
        head = prefix[-1].event_digest if prefix else GENESIS_DIGEST
        with pytest.raises(EventStoreError):
            store.append(event, expected_head=head)
        assert store.load(vault_harness.mission_id) == prefix


def test_authority_and_target_bytes_survive_staging_deletion(
    tmp_path: Path,
    vault_harness: _VaultHarness,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    opened = _event(vault_harness, "mission_opened")
    destination = _private_directory(tmp_path / "canonical-retention") / "events.sqlite3"
    with SQLiteEventStore(destination) as store:
        store.append_evidence_event(
            authority,
            expected_head=GENESIS_DIGEST,
            evidence_store=vault_harness.evidence_store,
        )
        store.append_evidence_event(
            opened,
            expected_head=authority.event_digest,
            evidence_store=vault_harness.evidence_store,
        )

    vault_harness.evidence_store._path_for(vault_harness.authority_evidence_digest).unlink()
    for snapshot_file in vault_harness.snapshot.files:
        vault_harness.evidence_store._path_for(snapshot_file.artifact_digest).unlink()

    expected_by_digest = {
        vault_harness.authority_evidence_digest: (vault_harness.authority_evidence_bytes),
        **{value.artifact_digest: vault_harness.fixture_bytes for value in vault_harness.snapshot.files},
    }
    with SQLiteEventStore(destination) as store:
        assert store.load(vault_harness.mission_id) == (authority, opened)
        for event in (authority, opened):
            for artifact in derive_event_artifact_manifest_v1(event):
                assert (
                    store.load_event_artifact(
                        event.event_digest,
                        artifact.role,
                        artifact.ordinal,
                    )
                    == expected_by_digest[artifact.digest]
                )


def test_raw_sql_cannot_insert_a_protected_event_without_mappings(
    tmp_path: Path,
    vault_harness: _VaultHarness,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    database = _private_directory(tmp_path / "raw-protected") / "events.sqlite3"
    with SQLiteEventStore(database):
        pass

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.DatabaseError):
            _raw_insert_event(connection, authority)
        connection.rollback()
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize("table", (_ARTIFACT_TABLE, _EVENT_ARTIFACT_TABLE))
def test_vault_relations_reject_update_and_delete(
    vault_harness: _VaultHarness,
    table: str,
) -> None:
    connection = sqlite3.connect(vault_harness.database)
    try:
        columns = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        assert columns
        mutable_column = str(columns[-1][1])
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(f'UPDATE "{table}" SET "{mutable_column}" = "{mutable_column}"')
        connection.rollback()
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(f'DELETE FROM "{table}"')
        connection.rollback()
    finally:
        connection.close()


@pytest.mark.parametrize("failure_mode", ("missing", "mismatched"))
def test_failed_protected_append_rolls_back_event_and_vault_rows(
    tmp_path: Path,
    vault_harness: _VaultHarness,
    failure_mode: str,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    staged_path = vault_harness.evidence_store._path_for(vault_harness.authority_evidence_digest)
    staged_path.unlink()
    if failure_mode == "mismatched":
        staged_path.write_bytes(b"x" * len(vault_harness.authority_evidence_bytes))
        staged_path.chmod(0o600)

    database = _private_directory(tmp_path / f"rollback-{failure_mode}") / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        with pytest.raises(EventStoreError):
            store.append_evidence_event(
                authority,
                expected_head=GENESIS_DIGEST,
                evidence_store=vault_harness.evidence_store,
            )
        assert store.load(vault_harness.mission_id) == ()

    assert _table_count(database, _ARTIFACT_TABLE) == 0
    assert _table_count(database, _EVENT_ARTIFACT_TABLE) == 0


def test_vault_capacity_failure_is_atomic_and_recoverable_with_a_sufficient_ceiling(
    tmp_path: Path,
    vault_harness: _VaultHarness,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    database = _private_directory(tmp_path / "vault-capacity") / "events.sqlite3"
    insufficient_ceiling = len(vault_harness.authority_evidence_bytes) - 1
    assert insufficient_ceiling > 0

    with SQLiteEventStore(
        database,
        max_vault_bytes=insufficient_ceiling,
    ) as store:
        with pytest.raises(
            EvidenceVaultCapacityError,
            match="vault byte ceiling",
        ):
            store.append_evidence_event(
                authority,
                expected_head=GENESIS_DIGEST,
                evidence_store=vault_harness.evidence_store,
            )
        assert store.load(vault_harness.mission_id) == ()
        for table in ("events", _ARTIFACT_TABLE, _EVENT_ARTIFACT_TABLE):
            assert store._connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone() == (0,)

    with SQLiteEventStore(
        database,
        max_vault_bytes=len(vault_harness.authority_evidence_bytes),
    ) as store:
        store.append_evidence_event(
            authority,
            expected_head=GENESIS_DIGEST,
            evidence_store=vault_harness.evidence_store,
        )
        assert store.load(vault_harness.mission_id) == (authority,)
        for table in ("events", _ARTIFACT_TABLE, _EVENT_ARTIFACT_TABLE):
            assert store._connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone() == (1,)


def test_reopen_refuses_retained_vault_above_the_configured_ceiling(
    vault_harness: _VaultHarness,
) -> None:
    connection = sqlite3.connect(vault_harness.database)
    try:
        row = connection.execute(
            "SELECT sum(byte_size) FROM evidence_artifacts"
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    retained_bytes = row[0]
    assert type(retained_bytes) is int and retained_bytes > 1

    with pytest.raises(
        EvidenceVaultCapacityError,
        match="retained unique evidence exceeds",
    ):
        SQLiteEventStore(
            vault_harness.database,
            max_vault_bytes=retained_bytes - 1,
        )

    with SQLiteEventStore(
        vault_harness.database,
        max_vault_bytes=retained_bytes,
    ) as store:
        assert store.load(vault_harness.mission_id) == vault_harness.events


def test_exact_artifacts_deduplicate_across_missions_without_losing_roles(
    tmp_path: Path,
    vault_harness: _VaultHarness,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    opened = _event(vault_harness, "mission_opened")
    second_mission_id = content_id(
        "mission",
        {"nonce": "transactional-vault-deduplication-second-mission"},
    )
    second_authority = EventV1.create(
        mission_id=second_mission_id,
        seq=0,
        kind=authority.kind,
        unit=authority.unit,
        authority_id=authority.authority_id,
        target_id=authority.target_id,
        decision_time=authority.decision_time,
        payload=thaw_json(authority.payload),
        prev_digest=GENESIS_DIGEST,
    )
    second_opened = EventV1.create(
        mission_id=second_mission_id,
        seq=1,
        kind=opened.kind,
        unit=opened.unit,
        authority_id=opened.authority_id,
        target_id=opened.target_id,
        decision_time=opened.decision_time,
        payload=thaw_json(opened.payload),
        prev_digest=second_authority.event_digest,
    )
    protected_events = (
        authority,
        opened,
        second_authority,
        second_opened,
    )
    database = _private_directory(tmp_path / "vault-deduplication") / "events.sqlite3"

    with SQLiteEventStore(database) as store:
        store.append_evidence_event(
            authority,
            expected_head=GENESIS_DIGEST,
            evidence_store=vault_harness.evidence_store,
        )
        store.append_evidence_event(
            opened,
            expected_head=authority.event_digest,
            evidence_store=vault_harness.evidence_store,
        )
        store.append_evidence_event(
            second_authority,
            expected_head=GENESIS_DIGEST,
            evidence_store=vault_harness.evidence_store,
        )
        store.append_evidence_event(
            second_opened,
            expected_head=second_authority.event_digest,
            evidence_store=vault_harness.evidence_store,
        )

        expected_identities = {
            artifact.identity_key
            for event in protected_events
            for artifact in derive_event_artifact_manifest_v1(event)
        }
        retained_identities = set(
            store._connection.execute(
                """
                SELECT identity_scheme, type_tag, digest
                FROM evidence_artifacts
                """
            ).fetchall()
        )
        assert retained_identities == expected_identities
        expected_origins: dict[tuple[str, str, str], str] = {}
        for event in protected_events:
            for artifact in derive_event_artifact_manifest_v1(event):
                expected_origins.setdefault(
                    artifact.identity_key,
                    event.event_digest,
                )
        retained_origins = {
            (identity_scheme, type_tag, digest): origin_event_digest
            for (
                identity_scheme,
                type_tag,
                digest,
                origin_event_digest,
            ) in store._connection.execute(
                """
                SELECT
                    identity_scheme,
                    type_tag,
                    digest,
                    origin_event_digest
                FROM evidence_artifacts
                """
            ).fetchall()
        }
        assert retained_origins == expected_origins

        expected_mappings = {
            (
                event.event_digest,
                event.kind,
                artifact.slot,
                artifact.role,
                artifact.ordinal,
                artifact.locator,
                artifact.identity_scheme,
                artifact.type_tag,
                artifact.digest,
            )
            for event in protected_events
            for artifact in derive_event_artifact_manifest_v1(event)
        }
        retained_mappings = set(
            store._connection.execute(
                """
                SELECT
                    event_digest,
                    event_kind,
                    slot,
                    role,
                    ordinal,
                    locator,
                    identity_scheme,
                    type_tag,
                    artifact_digest
                FROM event_artifact_roles
                """
            ).fetchall()
        )
        assert retained_mappings == expected_mappings
        assert len(retained_identities) < len(retained_mappings)
        assert store.load(vault_harness.mission_id) == (authority, opened)
        assert store.load(second_mission_id) == (
            second_authority,
            second_opened,
        )


def test_stale_protected_append_retains_only_the_winner(
    tmp_path: Path,
    vault_harness: _VaultHarness,
) -> None:
    winner = _event(vault_harness, "authority_admitted")
    loser_harness = _build_harness(
        tmp_path / "stale-loser-source",
        authority_marker="transactional_vault_stale_loser_authority",
    )
    loser = _event(loser_harness, "authority_admitted")
    assert loser.mission_id == winner.mission_id
    assert loser.event_digest != winner.event_digest
    assert loser_harness.authority_evidence_digest != (
        vault_harness.authority_evidence_digest
    )

    database = _private_directory(tmp_path / "stale-protected") / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        store.append_evidence_event(
            winner,
            expected_head=GENESIS_DIGEST,
            evidence_store=vault_harness.evidence_store,
        )
        before_counts = tuple(
            store._connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()
            for table in ("events", _ARTIFACT_TABLE, _EVENT_ARTIFACT_TABLE)
        )

        with pytest.raises(StaleHeadError, match="stale mission head"):
            store.append_evidence_event(
                loser,
                expected_head=GENESIS_DIGEST,
                evidence_store=loser_harness.evidence_store,
            )

        after_counts = tuple(
            store._connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()
            for table in ("events", _ARTIFACT_TABLE, _EVENT_ARTIFACT_TABLE)
        )
        assert after_counts == before_counts == ((1,), (1,), (1,))
        assert store.load(vault_harness.mission_id) == (winner,)
        assert store._connection.execute(
            """
            SELECT COUNT(*)
            FROM event_artifact_roles
            WHERE event_digest = ?
            """,
            (loser.event_digest,),
        ).fetchone() == (0,)
        assert store._connection.execute(
            """
            SELECT COUNT(*)
            FROM evidence_artifacts
            WHERE digest = ?
            """,
            (loser_harness.authority_evidence_digest,),
        ).fetchone() == (0,)


def test_nonempty_pre_vault_database_requires_explicit_migration(
    tmp_path: Path,
    vault_harness: _VaultHarness,
) -> None:
    database = _private_directory(tmp_path / "pre-vault") / "events.sqlite3"
    authority = _event(vault_harness, "authority_admitted")
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            CREATE TABLE events (
                mission_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                digest TEXT NOT NULL,
                prev_digest TEXT NOT NULL,
                kind TEXT NOT NULL,
                canonical BLOB NOT NULL,
                PRIMARY KEY (mission_id, seq),
                UNIQUE (mission_id, digest),
                UNIQUE (digest)
            ) STRICT
            """
        )
        _raw_insert_event(connection, authority)
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)

    with pytest.raises(EventStoreError):
        SQLiteEventStore(database)


def test_malformed_empty_unversioned_schema_is_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    database = _private_directory(tmp_path / "malformed-empty-unversioned") / "events.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            CREATE TABLE events (
                payload TEXT
            ) STRICT
            """
        )
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)

    before_state = _schema_state(database)
    before_bytes = database.read_bytes()
    assert before_state[:2] == (0, 0)

    with pytest.raises(EventStoreError):
        SQLiteEventStore(database)

    assert _schema_state(database) == before_state
    assert database.read_bytes() == before_bytes


@pytest.mark.parametrize("statement", ("COMMIT", "ROLLBACK"))
@pytest.mark.parametrize("surface", ("public", "private"))
def test_transaction_sabotaging_staging_subclass_is_rejected_before_append(
    tmp_path: Path,
    vault_harness: _VaultHarness,
    statement: str,
    surface: str,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    database = _private_directory(tmp_path / f"sabotage-{surface}-{statement.lower()}") / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        malicious = _TransactionSabotageEvidenceStore(
            vault_harness.evidence_store.root,
            connection=store._connection,
            statement=statement,
        )
        with pytest.raises(EventStoreError):
            if surface == "public":
                store.append_evidence_event(
                    authority,
                    expected_head=GENESIS_DIGEST,
                    evidence_store=malicious,
                )
            else:
                store._append_verified_event(
                    authority,
                    expected_head=GENESIS_DIGEST,
                    evidence_store=malicious,
                )

        assert malicious.read_attempts == 0
        assert not store._connection.in_transaction
        assert store.load(vault_harness.mission_id) == ()
        for table in ("events", _ARTIFACT_TABLE, _EVENT_ARTIFACT_TABLE):
            assert store._connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone() == (0,)

        store.append_evidence_event(
            authority,
            expected_head=GENESIS_DIGEST,
            evidence_store=vault_harness.evidence_store,
        )
        assert store.load(vault_harness.mission_id) == (authority,)


@pytest.mark.parametrize(
    ("role", "wrong_role"),
    (
        (
            VERIFICATION_POC_INPUT_ROLE_V1,
            VERIFICATION_ENVIRONMENT_SPEC_ROLE_V1,
        ),
        (
            VERIFICATION_EXECUTION_OUTPUT_ROLE_V1,
            VERIFICATION_EFFECT_OUTPUT_ROLE_V1,
        ),
    ),
)
def test_typed_artifact_resolution_uses_exact_role_and_survives_staging_loss(
    vault_harness: _VaultHarness,
    role: str,
    wrong_role: str,
) -> None:
    artifact = _typed_artifact(vault_harness, role)
    assert artifact.byte_size is not None
    expected = vault_harness.evidence_store.get_typed(
        artifact.digest,
        expected_type=artifact.type_tag,
        maximum=artifact.byte_size,
    )

    with SQLiteEventStore(vault_harness.database) as store:
        with pytest.raises(
            EventStoreError,
            match="absent from the vault and staging",
        ):
            store.resolve_evidence_artifact(
                wrong_role,
                artifact.digest,
                artifact.byte_size,
                vault_harness.evidence_store,
            )

        vault_harness.evidence_store._path_for(artifact.digest).unlink()
        assert (
            store.resolve_evidence_artifact(
                role,
                artifact.digest,
                artifact.byte_size,
                vault_harness.evidence_store,
            )
            == expected
        )


def test_protocol_max_batches_validate_one_origin_and_read_each_blob_once(
    vault_harness: _VaultHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _typed_artifact(
        vault_harness,
        VERIFICATION_POC_INPUT_ROLE_V1,
    )
    assert artifact.byte_size is not None
    origin_event = _event(
        vault_harness,
        "verification_artifacts_resolved",
    )
    request = VaultArtifactResolutionRequestV1(
        role=VERIFICATION_POC_INPUT_ROLE_V1,
        digest=artifact.digest,
        maximum=artifact.byte_size,
    )
    selector = VaultEventArtifactSelectorV1(
        event_digest=origin_event.event_digest,
        role=VERIFICATION_POC_INPUT_ROLE_V1,
    )
    expected_cache_key = (*artifact.identity_key, artifact.byte_size)

    decode_calls: list[str] = []
    read_calls: dict[tuple[str, str, str], int] = {}
    cache_calls: list[
        tuple[
            tuple[str, ...],
            frozenset[tuple[str, str, str, int]],
            frozenset[tuple[str, str, str, int]],
        ]
    ] = []
    original_decode = SQLiteEventStore._decode_rows
    original_read = SQLiteEventStore._read_vault_identity_locked
    original_load = (
        SQLiteEventStore._load_missions_with_shared_evidence_validation
    )

    def counted_decode(mission_id, rows):
        decode_calls.append(mission_id)
        return original_decode(mission_id, rows)

    def counted_read(
        self,
        identity_scheme,
        type_tag,
        digest,
        maximum=None,
        *,
        expected_size=None,
    ):
        key = (identity_scheme, type_tag, digest)
        read_calls[key] = read_calls.get(key, 0) + 1
        return original_read(
            self,
            identity_scheme,
            type_tag,
            digest,
            maximum,
            expected_size=expected_size,
        )

    def counted_load(self, mission_ids, *, cache_keys):
        result = original_load(
            self,
            mission_ids,
            cache_keys=cache_keys,
        )
        cache_calls.append(
            (
                mission_ids,
                cache_keys,
                frozenset(result),
            )
        )
        return result

    monkeypatch.setattr(
        SQLiteEventStore,
        "_decode_rows",
        staticmethod(counted_decode),
    )
    monkeypatch.setattr(
        SQLiteEventStore,
        "_read_vault_identity_locked",
        counted_read,
    )
    monkeypatch.setattr(
        SQLiteEventStore,
        "_load_missions_with_shared_evidence_validation",
        counted_load,
    )

    with SQLiteEventStore(vault_harness.database) as store:
        resolved = store.resolve_evidence_artifacts(
            (request,) * MAX_VAULT_BATCH_REQUESTS_V1,
            vault_harness.evidence_store,
            maximum_total=artifact.byte_size,
        )
        assert len(resolved) == MAX_VAULT_BATCH_REQUESTS_V1
        assert all(value is resolved[0] for value in resolved)
        assert decode_calls == [vault_harness.mission_id]
        assert read_calls[artifact.identity_key] == 1
        assert max(read_calls.values()) == 1
        assert cache_calls == [
            (
                (vault_harness.mission_id,),
                frozenset({expected_cache_key}),
                frozenset({expected_cache_key}),
            )
        ]

        decode_calls.clear()
        read_calls.clear()
        cache_calls.clear()
        loaded = store.load_event_artifacts(
            (selector,) * MAX_VAULT_BATCH_REQUESTS_V1,
            maximum_total=artifact.byte_size,
        )
        assert len(loaded) == MAX_VAULT_BATCH_REQUESTS_V1
        assert all(value is loaded[0] for value in loaded)
        assert decode_calls == [vault_harness.mission_id]
        assert read_calls[artifact.identity_key] == 1
        assert max(read_calls.values()) == 1
        assert cache_calls == [
            (
                (vault_harness.mission_id,),
                frozenset({expected_cache_key}),
                frozenset({expected_cache_key}),
            )
        ]

        with pytest.raises(EventStoreError, match="bounded tuple"):
            store.resolve_evidence_artifacts(
                (request,) * (MAX_VAULT_BATCH_REQUESTS_V1 + 1),
                vault_harness.evidence_store,
                maximum_total=artifact.byte_size,
            )
        with pytest.raises(EventStoreError, match="outside the fixed vault bound"):
            store.resolve_evidence_artifacts(
                (request,),
                vault_harness.evidence_store,
                maximum_total=DEFAULT_MAX_VAULT_BYTES_V1 + 1,
            )
        with pytest.raises(
            EvidenceVaultRequestError,
            match="aggregate byte ceiling",
        ):
            store.load_event_artifacts(
                (selector,),
                maximum_total=artifact.byte_size - 1,
            )


def test_protocol_max_distinct_targets_share_one_origin_validation_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_directory(tmp_path / "distinct-target-batch")
    evidence_store = FileEvidenceStore(root / "evidence")
    retained_sources = tuple(
        evidence_store.put(bytes((index,)))
        for index in range(256)
    )
    snapshot = TargetSnapshotV1.create(
        "repository_fixture",
        tuple(
            SnapshotFileV1(
                relative_path=f"fixture/source-{index:03d}.py",
                artifact_digest=retained.digest,
                size=retained.size,
            )
            for index, retained in enumerate(retained_sources)
        ),
    )
    authority_bytes = b"protocol-max-distinct-target-authority"
    authority_artifact = evidence_store.put(authority_bytes)
    signer = AuthoritySigner.generate()
    grant = AuthorityGrantV1.issue(
        issuer="operator:daniel",
        subject="benchmark:protocol-max-distinct-targets",
        target_snapshot_id=snapshot.object_id,
        assets=("fixture://protocol-max-distinct-targets",),
        permitted_actions=("static_analysis",),
        evidence_digest=evidence_digest(authority_bytes),
        issued_at=NOW - 1,
        not_before=NOW,
        expires_at=NOW + 300,
        max_bytes=1024,
        max_candidates=1,
        max_wallclock_seconds=60,
    )
    signed = signer.sign(grant)
    trust = TrustStore.from_keys(
        (
            TrustedAuthorityKey(
                public_key_bytes=signer.public_key_bytes,
                roles=frozenset({"operator"}),
                issuers=frozenset({"operator:daniel"}),
            ),
        )
    )
    admission = AuthorityAdmissionV1.issue(
        grant=grant,
        signed_grant=signed,
        signer_key_id=signer.key_id,
        trust_store=trust,
        decision_time=NOW,
        required_actions=("static_analysis",),
        target_snapshot_id=snapshot.object_id,
    )
    mission_id = content_id(
        "mission",
        {"fixture": "protocol-max-distinct-targets"},
    )
    authority_event = EventV1.create(
        mission_id=mission_id,
        seq=0,
        kind="authority_admitted",
        unit="AQUILA",
        authority_id=grant.grant_id,
        target_id=snapshot.object_id,
        decision_time=NOW,
        payload={
            "admission": admission.to_envelope().to_dict(),
            "grant": grant.to_envelope().to_dict(),
            "key_id": signer.key_id,
            "signature_b64": signed.signature_b64,
        },
        prev_digest=GENESIS_DIGEST,
    )
    opened_event = EventV1.create(
        mission_id=mission_id,
        seq=1,
        kind="mission_opened",
        unit="ETZIO",
        authority_id=grant.grant_id,
        target_id=snapshot.object_id,
        decision_time=NOW,
        payload={"target_snapshot": snapshot.to_envelope().to_dict()},
        prev_digest=authority_event.event_digest,
    )

    decode_calls: list[str] = []
    read_calls: dict[tuple[str, str, str], int] = {}
    cache_calls: list[
        tuple[
            frozenset[tuple[str, str, str, int]],
            frozenset[tuple[str, str, str, int]],
        ]
    ] = []
    original_decode = SQLiteEventStore._decode_rows
    original_read = SQLiteEventStore._read_vault_identity_locked
    original_load = (
        SQLiteEventStore._load_missions_with_shared_evidence_validation
    )

    def counted_decode(owner_mission_id, rows):
        decode_calls.append(owner_mission_id)
        return original_decode(owner_mission_id, rows)

    def counted_read(
        self,
        identity_scheme,
        type_tag,
        digest,
        maximum=None,
        *,
        expected_size=None,
    ):
        key = (identity_scheme, type_tag, digest)
        read_calls[key] = read_calls.get(key, 0) + 1
        return original_read(
            self,
            identity_scheme,
            type_tag,
            digest,
            maximum,
            expected_size=expected_size,
        )

    def counted_load(self, mission_ids, *, cache_keys):
        result = original_load(
            self,
            mission_ids,
            cache_keys=cache_keys,
        )
        cache_calls.append((cache_keys, frozenset(result)))
        return result

    database = root / "events.sqlite3"
    with SQLiteEventStore(database) as store:
        store.append_evidence_event(
            authority_event,
            expected_head=GENESIS_DIGEST,
            evidence_store=evidence_store,
        )
        store.append_evidence_event(
            opened_event,
            expected_head=authority_event.event_digest,
            evidence_store=evidence_store,
        )
        monkeypatch.setattr(
            SQLiteEventStore,
            "_decode_rows",
            staticmethod(counted_decode),
        )
        monkeypatch.setattr(
            SQLiteEventStore,
            "_read_vault_identity_locked",
            counted_read,
        )
        monkeypatch.setattr(
            SQLiteEventStore,
            "_load_missions_with_shared_evidence_validation",
            counted_load,
        )

        selectors = tuple(
            VaultEventArtifactSelectorV1(
                event_digest=opened_event.event_digest,
                role="target_source",
                ordinal=ordinal,
            )
            for ordinal in range(256)
        )
        loaded = store.load_event_artifacts(
            selectors,
            maximum_total=256,
        )

    target_manifest = derive_event_artifact_manifest_v1(opened_event)
    requested_cache_keys = frozenset(
        (*artifact.identity_key, artifact.byte_size)
        for artifact in target_manifest
    )
    authority_manifest = derive_event_artifact_manifest_v1(authority_event)
    authority_cache_key = (
        *authority_manifest[0].identity_key,
        len(authority_bytes),
    )
    assert loaded == tuple(bytes((index,)) for index in range(256))
    assert decode_calls == [mission_id]
    assert len(read_calls) == 257
    assert max(read_calls.values()) == 1
    assert cache_calls == [
        (requested_cache_keys, requested_cache_keys),
    ]
    assert authority_cache_key not in cache_calls[0][1]
    assert authority_artifact.digest == authority_manifest[0].digest


def test_duplicate_batch_limit_reports_the_strictest_request_index(
    vault_harness: _VaultHarness,
) -> None:
    artifact = _typed_artifact(
        vault_harness,
        VERIFICATION_POC_INPUT_ROLE_V1,
    )
    assert artifact.byte_size is not None and artifact.byte_size > 1
    requests = (
        VaultArtifactResolutionRequestV1(
            role=VERIFICATION_POC_INPUT_ROLE_V1,
            digest=artifact.digest,
            maximum=artifact.byte_size,
        ),
        VaultArtifactResolutionRequestV1(
            role=VERIFICATION_POC_INPUT_ROLE_V1,
            digest=artifact.digest,
            maximum=artifact.byte_size - 1,
        ),
        VaultArtifactResolutionRequestV1(
            role=VERIFICATION_POC_INPUT_ROLE_V1,
            digest=artifact.digest,
            maximum=artifact.byte_size - 1,
        ),
    )

    with SQLiteEventStore(vault_harness.database) as store:
        with pytest.raises(EvidenceVaultRequestError) as caught:
            store.resolve_evidence_artifacts(
                requests,
                vault_harness.evidence_store,
                maximum_total=artifact.byte_size,
            )

    assert caught.value.reason_code == "artifact_limit"
    assert caught.value.request_index == 1


def test_typed_vault_corruption_never_falls_back_to_valid_staging(
    vault_harness: _VaultHarness,
) -> None:
    artifact = _typed_artifact(
        vault_harness,
        VERIFICATION_POC_INPUT_ROLE_V1,
    )
    assert artifact.byte_size is not None
    assert vault_harness.evidence_store._path_for(artifact.digest).is_file()

    connection = sqlite3.connect(vault_harness.database)
    try:
        trigger_definitions = _drop_table_triggers(
            connection,
            _ARTIFACT_TABLE,
        )
        row = connection.execute(
            """
            SELECT artifact_rowid, content
            FROM evidence_artifacts
            WHERE identity_scheme = ?
              AND type_tag = ?
              AND digest = ?
            """,
            (
                artifact.identity_scheme,
                artifact.type_tag,
                artifact.digest,
            ),
        ).fetchone()
        assert row is not None
        artifact_rowid, retained = row
        assert isinstance(retained, bytes)
        replacement = bytes([retained[0] ^ 1]) + retained[1:]
        connection.execute(
            """
            UPDATE evidence_artifacts
            SET content = ?
            WHERE artifact_rowid = ?
            """,
            (sqlite3.Binary(replacement), artifact_rowid),
        )
        _restore_triggers(connection, trigger_definitions)
        connection.commit()
    finally:
        connection.close()

    with SQLiteEventStore(vault_harness.database) as store:
        with pytest.raises(EventStoreCorruptionError):
            store.resolve_evidence_artifact(
                VERIFICATION_POC_INPUT_ROLE_V1,
                artifact.digest,
                artifact.byte_size,
                vault_harness.evidence_store,
            )


@pytest.mark.parametrize("corruption", ("artifact_bytes", "missing_mapping"))
def test_offline_vault_corruption_is_detected_on_reopen(
    vault_harness: _VaultHarness,
    corruption: str,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    connection = sqlite3.connect(vault_harness.database)
    try:
        if corruption == "artifact_bytes":
            trigger_definitions = _drop_table_triggers(
                connection,
                _ARTIFACT_TABLE,
            )
            blob_column = _blob_column(connection, _ARTIFACT_TABLE)
            row = connection.execute(
                f'SELECT rowid, "{blob_column}" FROM "{_ARTIFACT_TABLE}" ORDER BY rowid LIMIT 1'
            ).fetchone()
            assert row is not None
            rowid, retained = row
            assert isinstance(retained, bytes)
            replacement = bytes([retained[0] ^ 1]) + retained[1:]
            connection.execute(
                f'UPDATE "{_ARTIFACT_TABLE}" SET "{blob_column}" = ? WHERE rowid = ?',
                (sqlite3.Binary(replacement), rowid),
            )
        else:
            trigger_definitions = _drop_table_triggers(
                connection,
                _EVENT_ARTIFACT_TABLE,
            )
            connection.execute(
                f'DELETE FROM "{_EVENT_ARTIFACT_TABLE}" WHERE event_digest = ?',
                (authority.event_digest,),
            )
        _restore_triggers(connection, trigger_definitions)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EventStoreCorruptionError):
        with SQLiteEventStore(vault_harness.database) as reopened:
            reopened.load(vault_harness.mission_id)


def test_oversized_retained_authority_mapping_is_classified_as_corruption(
    vault_harness: _VaultHarness,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    oversized = b"x" * (MAX_AUTHORITY_EVIDENCE_BYTES_V1 + 1)
    connection = sqlite3.connect(vault_harness.database)
    try:
        trigger_definitions = (
            *_drop_table_triggers(connection, _ARTIFACT_TABLE),
            *_drop_table_triggers(connection, _EVENT_ARTIFACT_TABLE),
        )
        connection.execute(
            """
            UPDATE evidence_artifacts
            SET byte_size = ?, content = ?
            WHERE origin_event_digest = ?
            """,
            (
                len(oversized),
                sqlite3.Binary(oversized),
                authority.event_digest,
            ),
        )
        connection.execute(
            """
            UPDATE event_artifact_roles
            SET byte_size = ?
            WHERE event_digest = ?
            """,
            (
                len(oversized),
                authority.event_digest,
            ),
        )
        _restore_triggers(connection, trigger_definitions)
        connection.commit()
    finally:
        connection.close()

    with SQLiteEventStore(vault_harness.database) as store:
        with pytest.raises(
            EventStoreCorruptionError,
            match="retained event-artifact manifest is invalid",
        ):
            store.load(vault_harness.mission_id)


def test_missing_canonical_blob_is_classified_as_corruption(
    vault_harness: _VaultHarness,
) -> None:
    authority = _event(vault_harness, "authority_admitted")
    with SQLiteEventStore(vault_harness.database) as store:
        connection = sqlite3.connect(vault_harness.database)
        try:
            trigger_definitions = _drop_table_triggers(
                connection,
                _ARTIFACT_TABLE,
            )
            connection.execute(
                """
                DELETE FROM evidence_artifacts
                WHERE origin_event_digest = ?
                """,
                (authority.event_digest,),
            )
            _restore_triggers(connection, trigger_definitions)
            connection.commit()
        finally:
            connection.close()

        with pytest.raises(
            EventStoreCorruptionError,
            match="absent from the canonical vault",
        ):
            store.load(vault_harness.mission_id)


def test_etziov1_schema_contract_drift_is_classified_as_corruption(
    vault_harness: _VaultHarness,
) -> None:
    connection = sqlite3.connect(vault_harness.database)
    try:
        connection.execute("DROP TRIGGER evidence_artifacts_reject_update")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(
        EventStoreCorruptionError,
        match="schema objects differ",
    ):
        SQLiteEventStore(vault_harness.database)
