"""Adversarial qualification tests for networkless trusted-time/revocation adapters."""

from __future__ import annotations

import hashlib
import socket
import time
from collections.abc import Iterator, Mapping
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from etzio.integrity_v1 import (
    TRUSTED_TIME_EVIDENCE_KIND,
    IntegrityValidationPolicyV1,
)
from etzio.kernel.integrity_adapters_v1 import (
    INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
    REPOSITORY_OWNED_ADAPTER_PROFILE_V1,
    REVOCATION_FLOOR_ADAPTER_ROLE_V1,
    REVOCATION_METADATA_ADAPTER_ROLE_V1,
    TRUSTED_TIME_ADAPTER_ROLE_V1,
    AdapterEvidenceSignerV1,
    AdapterSourceBindingV1,
    AuthenticatedProviderEvidencePackageV1,
    ExpectedRevocationStateV1,
    IntegrityAdapterError,
    IntegrityAdapterQualificationReportV1,
    IntegrityAdapterTrustProfileV1,
    IntegrityAdapterTrustStoreV1,
    ProviderEvidenceStatementV1,
    QualifiedIntegrityInputsV1,
    QualifiedRevocationBundleV1,
    QualifiedTimeBundleV1,
    RepositoryOwnedDeterministicAdapterFixtureV1,
    RepositoryOwnedDeterministicTrustedTimeAdapterV1,
    RevocationRequestV1,
    SignedProviderEvidenceV1,
    TrustedAdapterKeyV1,
    TrustedTimeRequestV1,
    authenticate_provider_evidence_v1,
    create_repository_owned_adapter_fixture_v1,
    map_qualified_integrity_inputs_v1,
    qualify_repository_time_revocation_adapters_v1,
    qualify_revocation_bundle_v1,
    qualify_time_bundle_v1,
    reauthenticate_revocation_bundle_v1,
    reauthenticate_time_bundle_v1,
)
from etzio.protocol import canonical_dumps, content_id

_SERVICE_INSTANCE_ID = "Etzio.adapter-qualification-fixture"
_ENVIRONMENT_ID = "fixture.adapter-qualification-control-plane"
_NAMESPACES = ("authority", "verifier")
_CODEC_BY_ROLE = {
    TRUSTED_TIME_ADAPTER_ROLE_V1: "etzio.fixture.signed-time.v1",
    REVOCATION_METADATA_ADAPTER_ROLE_V1: (
        "etzio.fixture.signed-revocation-metadata.v1"
    ),
    REVOCATION_FLOOR_ADAPTER_ROLE_V1: (
        "etzio.fixture.signed-revocation-floor.v1"
    ),
}
_SIGNATURE_DOMAIN_BY_ROLE = {
    TRUSTED_TIME_ADAPTER_ROLE_V1: (
        b"etzio.integrity-adapter.trusted-time.signature.v1\x00"
    ),
    REVOCATION_METADATA_ADAPTER_ROLE_V1: (
        b"etzio.integrity-adapter.revocation-metadata.signature.v1\x00"
    ),
    REVOCATION_FLOOR_ADAPTER_ROLE_V1: (
        b"etzio.integrity-adapter.revocation-floor.signature.v1\x00"
    ),
}


class _DuplicateEmittingMapping(Mapping[str, object]):
    """Hostile Mapping whose items stream repeats one logical source."""

    def __init__(self, pairs: tuple[tuple[str, object], ...]) -> None:
        self._pairs = pairs
        self._collapsed = dict(pairs)

    def __getitem__(self, key: str) -> object:
        return self._collapsed[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._collapsed)

    def __len__(self) -> int:
        return len(self._collapsed)

    def items(self) -> tuple[tuple[str, object], ...]:
        return self._pairs


def _digest(label: str) -> str:
    return content_id("integrity_adapter_qualification_test", {"label": label})


def _private_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(
        b"etzio.integrity-adapter-test-key.v1\x00" + label.encode("ascii")
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _private_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _validation_policy(
    *,
    max_decision_uncertainty_seconds: int = 4,
) -> IntegrityValidationPolicyV1:
    return IntegrityValidationPolicyV1(
        decision_policy_id=_digest("decision-policy"),
        decision_time_policy_id=_digest("decision-time-policy"),
        checkpoint_time_policy_id=_digest("checkpoint-time-policy"),
        anchor_policy_id=_digest("anchor-policy"),
        required_revocation_namespaces=frozenset(_NAMESPACES),
        max_decision_uncertainty_seconds=max_decision_uncertainty_seconds,
        max_checkpoint_uncertainty_seconds=4,
    )


def _source_specs() -> tuple[tuple[str, str, str | None], ...]:
    values: list[tuple[str, str, str | None]] = [
        ("fixture.time.a", TRUSTED_TIME_ADAPTER_ROLE_V1, None),
        ("fixture.time.b", TRUSTED_TIME_ADAPTER_ROLE_V1, None),
    ]
    for namespace in _NAMESPACES:
        values.extend(
            (
                (
                    f"fixture.revocation-metadata.{namespace}",
                    REVOCATION_METADATA_ADAPTER_ROLE_V1,
                    namespace,
                ),
                (
                    f"fixture.revocation-floor.{namespace}.a",
                    REVOCATION_FLOOR_ADAPTER_ROLE_V1,
                    namespace,
                ),
                (
                    f"fixture.revocation-floor.{namespace}.b",
                    REVOCATION_FLOOR_ADAPTER_ROLE_V1,
                    namespace,
                ),
            )
        )
    return tuple(
        sorted(values, key=lambda value: (value[1], value[2] or "", value[0]))
    )


def _profile(
    *,
    policy: IntegrityValidationPolicyV1 | None = None,
    revoked_key_ids: frozenset[str] = frozenset(),
) -> IntegrityAdapterTrustProfileV1:
    policy = policy or _validation_policy()
    keys: list[TrustedAdapterKeyV1] = []
    bindings: list[AdapterSourceBindingV1] = []
    for source_id, role, namespace in _source_specs():
        key = TrustedAdapterKeyV1(
            source_id=source_id,
            principal_id=f"{source_id}.principal",
            role=role,
            public_key_bytes=_public_key_bytes(_private_key(source_id)),
        )
        keys.append(key)
        bindings.append(
            AdapterSourceBindingV1(
                source_id=source_id,
                role=role,
                namespace=namespace,
                key_id=key.key_id,
                principal_id=key.principal_id,
                provider_policy_id=_digest(f"{source_id}-provider-policy"),
                codec_profile=_CODEC_BY_ROLE[role],
            )
        )
    trust_store = IntegrityAdapterTrustStoreV1.from_keys(
        keys,
        revoked_key_ids=revoked_key_ids,
    )
    return IntegrityAdapterTrustProfileV1(
        adapter_profile=REPOSITORY_OWNED_ADAPTER_PROFILE_V1,
        contract_version=INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
        service_instance_id=_SERVICE_INSTANCE_ID,
        environment_id=_ENVIRONMENT_ID,
        validation_policy=policy,
        validation_policy_id=content_id(
            "integrity_validation_policy",
            policy.to_body(),
        ),
        trust_store=trust_store,
        trust_root_id=trust_store.root_id,
        source_bindings=tuple(bindings),
        max_revocation_staleness_seconds=60,
    )


def _source_role(source_id: str) -> str:
    return next(
        role
        for candidate_source, role, _ in _source_specs()
        if candidate_source == source_id
    )


def _signer(source_id: str) -> AdapterEvidenceSignerV1:
    return AdapterEvidenceSignerV1(
        source_id=source_id,
        principal_id=f"{source_id}.principal",
        role=_source_role(source_id),
        private_key_bytes=_private_key_bytes(_private_key(source_id)),
    )


def _nonce(label: str) -> str:
    return hashlib.sha256(
        b"etzio.integrity-adapter-test-nonce.v1\x00" + label.encode("ascii")
    ).hexdigest()


def _time_request(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    source_id: str = "fixture.time.a",
    nonce_label: str = "time-bundle",
    purpose: str = "decision",
) -> TrustedTimeRequestV1:
    return TrustedTimeRequestV1.issue(
        profile=profile,
        source_id=source_id,
        purpose=purpose,
        mission_id=_digest("mission"),
        authority_id=_digest("authority"),
        target_id=_digest("target"),
        event_digest=_digest("event"),
        transition_intent_id=_digest("transition-intent"),
        imprint_id=_digest("imprint"),
        request_nonce=_nonce(nonce_label),
    )


def _time_claim(
    request: TrustedTimeRequestV1,
    *,
    lower: int = 100,
    upper: int = 104,
) -> dict[str, object]:
    return {
        "accuracy_authenticated": True,
        "authority_id": request.authority_id,
        "event_digest": request.event_digest,
        "imprint_id": request.imprint_id,
        "mission_id": request.mission_id,
        "purpose": request.purpose,
        "target_id": request.target_id,
        "time_lower_bound": lower,
        "time_policy_id": request.time_policy_id,
        "time_upper_bound": upper,
        "transition_intent_id": request.transition_intent_id,
    }


def _time_statement(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    request: TrustedTimeRequestV1,
    claim: dict[str, object] | None = None,
) -> ProviderEvidenceStatementV1:
    binding = profile.binding_for(
        role=TRUSTED_TIME_ADAPTER_ROLE_V1,
        source_id=request.source_id,
        namespace=None,
    )
    return ProviderEvidenceStatementV1(
        contract_version=INTEGRITY_ADAPTER_CONTRACT_VERSION_V1,
        profile_id=profile.profile_id,
        trust_root_id=profile.trust_root_id,
        service_instance_id=profile.service_instance_id,
        environment_id=profile.environment_id,
        source_id=request.source_id,
        evidence_role=TRUSTED_TIME_ADAPTER_ROLE_V1,
        provider_policy_id=binding.provider_policy_id,
        request_id=request.request_id,
        claim=claim if claim is not None else _time_claim(request),
    )


def _sign_raw_statement(
    *,
    source_id: str,
    evidence_role: str,
    statement_bytes: bytes,
) -> SignedProviderEvidenceV1:
    key = _private_key(source_id)
    return SignedProviderEvidenceV1(
        evidence_role=evidence_role,
        key_id=_signer(source_id).trusted_key.key_id,
        statement_bytes=statement_bytes,
        signature_bytes=key.sign(
            _SIGNATURE_DOMAIN_BY_ROLE[evidence_role] + statement_bytes
        ),
    )


def _replace_time_request(
    request: TrustedTimeRequestV1,
    **changes: object,
) -> TrustedTimeRequestV1:
    body = request.to_body()
    body.update(changes)
    del body["request_id"]
    request_id = content_id("trusted_time_adapter_request", body)
    return TrustedTimeRequestV1(request_id=request_id, **body)  # type: ignore[arg-type]


def _time_bundle_inputs(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    intervals: dict[str, tuple[int, int]],
    nonce_label: str = "time-bundle",
    purpose: str = "decision",
) -> tuple[
    dict[str, TrustedTimeRequestV1],
    dict[str, SignedProviderEvidenceV1],
]:
    sources = tuple(
        binding.source_id
        for binding in profile.source_bindings
        if binding.role == TRUSTED_TIME_ADAPTER_ROLE_V1
    )
    assert set(intervals) == set(sources)
    requests: dict[str, TrustedTimeRequestV1] = {}
    signed: dict[str, SignedProviderEvidenceV1] = {}
    for source_id in sources:
        request = _time_request(
            profile=profile,
            source_id=source_id,
            nonce_label=nonce_label,
            purpose=purpose,
        )
        lower, upper = intervals[source_id]
        requests[source_id] = request
        signed[source_id] = _signer(source_id).sign(
            _time_statement(
                profile=profile,
                request=request,
                claim=_time_claim(request, lower=lower, upper=upper),
            )
        )
    return requests, signed


def _qualified_time(
    *,
    profile: IntegrityAdapterTrustProfileV1,
    intervals: dict[str, tuple[int, int]] | None = None,
    nonce_label: str = "time-bundle",
) -> QualifiedTimeBundleV1:
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals=intervals
        or {
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
        nonce_label=nonce_label,
    )
    return qualify_time_bundle_v1(
        profile=profile,
        requests=requests,
        signed_evidence=signed,
    )


def _repository_fixture() -> RepositoryOwnedDeterministicAdapterFixtureV1:
    return create_repository_owned_adapter_fixture_v1(
        seed=b"etzio-integrity-adapter-known-bad-corpus-v1",
        expected_epoch_second=2_000_000_000,
    )


def _fixture_time_bundle(
    fixture: RepositoryOwnedDeterministicAdapterFixtureV1,
    *,
    purpose: str = "decision",
) -> QualifiedTimeBundleV1:
    vector = fixture.vector
    requests = {
        adapter.source_id: TrustedTimeRequestV1.issue(
            profile=fixture.profile,
            source_id=adapter.source_id,
            purpose=purpose,
            mission_id=vector.mission_id,
            authority_id=vector.authority_id,
            target_id=vector.target_id,
            event_digest=vector.event_digest,
            transition_intent_id=vector.transition_intent_id,
            imprint_id=_digest(f"fixture-{purpose}-imprint"),
            request_nonce=vector.request_nonce,
        )
        for adapter in fixture.time_adapters
    }
    signed = {
        adapter.source_id: adapter.acquire(requests[adapter.source_id])
        for adapter in fixture.time_adapters
    }
    return qualify_time_bundle_v1(
        profile=fixture.profile,
        requests=requests,
        signed_evidence=signed,
    )


def _fixture_revocation_state(
    fixture: RepositoryOwnedDeterministicAdapterFixtureV1,
    namespace: str,
) -> ExpectedRevocationStateV1:
    return next(
        state
        for state in fixture.vector.expected_revocation
        if state.namespace == namespace
    )


def _revocation_inputs(
    *,
    fixture: RepositoryOwnedDeterministicAdapterFixtureV1,
    time_bundle: QualifiedTimeBundleV1,
    namespace: str,
    state: ExpectedRevocationStateV1 | None = None,
    source_states: dict[str, ExpectedRevocationStateV1] | None = None,
) -> tuple[
    dict[str, RevocationRequestV1],
    dict[str, SignedProviderEvidenceV1],
]:
    state = state or _fixture_revocation_state(fixture, namespace)
    adapters = tuple(
        adapter
        for adapter in fixture.revocation_adapters
        if adapter.namespace == namespace
    )
    requests = {
        adapter.source_id: RevocationRequestV1.issue(
            profile=fixture.profile,
            source_id=adapter.source_id,
            evidence_role=adapter.role,
            namespace=namespace,
            time_bundle=time_bundle,
            prior_root_version=state.prior_root_version,
            prior_version=state.prior_version,
            prior_snapshot_id=state.prior_snapshot_id,
            request_nonce=_nonce(f"revocation-{namespace}"),
        )
        for adapter in adapters
    }
    signed: dict[str, SignedProviderEvidenceV1] = {}
    for adapter in adapters:
        selected_state = (
            source_states.get(adapter.source_id, state)
            if source_states is not None
            else state
        )
        selected_adapter = (
            adapter
            if selected_state == adapter.state
            else replace(adapter, state=selected_state)
        )
        signed[adapter.source_id] = selected_adapter.acquire(
            requests[adapter.source_id]
        )
    return requests, signed


def _qualified_revocation(
    *,
    fixture: RepositoryOwnedDeterministicAdapterFixtureV1,
    time_bundle: QualifiedTimeBundleV1,
    namespace: str,
    state: ExpectedRevocationStateV1 | None = None,
) -> QualifiedRevocationBundleV1:
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=namespace,
        state=state,
    )
    return qualify_revocation_bundle_v1(
        profile=fixture.profile,
        namespace=namespace,
        time_bundle=time_bundle,
        requests=requests,
        signed_evidence=signed,
    )


def test_adapter_profile_is_deterministic_canonical_and_deeply_snapshotted() -> None:
    first = _profile()
    second = _profile()

    assert first == second
    assert first.profile_id == second.profile_id
    assert first.to_canonical_bytes() == second.to_canonical_bytes()
    assert (
        IntegrityAdapterTrustProfileV1.from_canonical_bytes(
            first.to_canonical_bytes()
        )
        == first
    )

    body = first.to_body()
    body["service_instance_id"] = "Etzio.mutated"
    body["source_bindings"][0]["source_id"] = "fixture.mutated"  # type: ignore[index]
    body["trust_root"]["keys"][0]["principal_id"] = "fixture.mutated"  # type: ignore[index]
    body["validation_policy"]["required_revocation_namespaces"].append(  # type: ignore[index, union-attr]
        "mutated"
    )
    assert first == second
    assert first.profile_id == second.profile_id


def test_adapter_profile_rejects_policy_and_trust_root_substitution() -> None:
    profile = _profile()

    with pytest.raises(IntegrityAdapterError) as policy_mismatch:
        replace(
            profile,
            validation_policy_id=_digest("substituted-validation-policy"),
        )
    assert policy_mismatch.value.reason_code == "adapter_policy_binding_mismatch"

    with pytest.raises(IntegrityAdapterError) as root_mismatch:
        replace(profile, trust_root_id=_digest("substituted-trust-root"))
    assert (
        root_mismatch.value.reason_code
        == "adapter_trust_root_binding_mismatch"
    )


@pytest.mark.parametrize(
    "mutation",
    ("missing_time", "missing_metadata", "missing_floor", "duplicate_source"),
)
def test_adapter_profile_requires_the_exact_source_roster(
    mutation: str,
) -> None:
    profile = _profile()
    bindings = list(profile.source_bindings)
    if mutation == "missing_time":
        bindings = [
            value
            for value in bindings
            if value.source_id != "fixture.time.a"
        ]
    elif mutation == "missing_metadata":
        bindings = [
            value
            for value in bindings
            if value.source_id != "fixture.revocation-metadata.authority"
        ]
    elif mutation == "missing_floor":
        bindings = [
            value
            for value in bindings
            if value.source_id != "fixture.revocation-floor.authority.a"
        ]
    else:
        bindings[-1] = replace(
            bindings[-1],
            source_id=bindings[0].source_id,
        )

    retained_key_ids = {value.key_id for value in bindings}
    trust_store = IntegrityAdapterTrustStoreV1.from_keys(
        tuple(
            value
            for key_id, value in profile.trust_store.keys.items()
            if key_id in retained_key_ids
        )
    )
    with pytest.raises(IntegrityAdapterError) as refused:
        replace(
            profile,
            source_bindings=tuple(bindings),
            trust_store=trust_store,
            trust_root_id=trust_store.root_id,
        )
    assert refused.value.reason_code in {
        "adapter_source_independence_confusion",
        "invalid_adapter_source_roster",
        "invalid_revocation_source_roster",
        "missing_trusted_time_source",
    }


def test_adapter_profile_rejects_source_key_principal_and_role_confusion() -> None:
    profile = _profile()
    first, second, *rest = profile.source_bindings
    confused = (
        replace(first, key_id=second.key_id, principal_id=second.principal_id),
        second,
        *rest,
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        replace(profile, source_bindings=confused)
    assert refused.value.reason_code in {
        "adapter_source_independence_confusion",
        "adapter_trust_root_roster_mismatch",
    }


def test_adapter_profile_rejects_noncanonical_wire_and_unknown_fields() -> None:
    profile = _profile()
    wire = profile.to_canonical_bytes()

    with pytest.raises(IntegrityAdapterError) as whitespace:
        IntegrityAdapterTrustProfileV1.from_canonical_bytes(wire + b"\n")
    assert whitespace.value.reason_code == "invalid_adapter_trust_profile"

    body = profile.to_body()
    body["unknown"] = _digest("unknown")

    with pytest.raises(IntegrityAdapterError) as unknown:
        IntegrityAdapterTrustProfileV1.from_canonical_bytes(
            canonical_dumps(body)
        )
    assert unknown.value.reason_code == "invalid_adapter_trust_profile"


def test_provider_authentication_is_exact_retry_stable_and_retains_signed_wire() -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    signed = _signer(request.source_id).sign(
        _time_statement(profile=profile, request=request)
    )

    first = authenticate_provider_evidence_v1(
        profile=profile,
        request=request,
        signed_evidence=signed,
    )
    second = authenticate_provider_evidence_v1(
        profile=profile,
        request=request,
        signed_evidence=signed,
    )

    assert first == second
    assert first.request == request
    assert first.signed_evidence == signed
    assert first.provider_evidence.content == signed.to_canonical_bytes()
    assert first.provider_evidence.evidence_kind == TRUSTED_TIME_EVIDENCE_KIND
    assert first.provider_evidence.source_id == request.source_id
    assert (
        first.provider_evidence.evidence_id
        == "sha256:" + hashlib.sha256(signed.to_canonical_bytes()).hexdigest()
    )
    assert first.provider_evidence.reference.evidence_id == (
        first.provider_evidence.evidence_id
    )


def test_provider_authentication_rejects_cross_request_replay() -> None:
    profile = _profile()
    first_request = _time_request(profile=profile, nonce_label="first")
    second_request = _time_request(profile=profile, nonce_label="second")
    signed = _signer(first_request.source_id).sign(
        _time_statement(profile=profile, request=first_request)
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=second_request,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "provider_request_mismatch"


@pytest.mark.parametrize(
    ("field", "replacement", "reason_code"),
    (
        ("profile_id", _digest("other-profile"), "provider_profile_mismatch"),
        ("trust_root_id", _digest("other-root"), "provider_root_mismatch"),
        (
            "service_instance_id",
            "Etzio.other-service",
            "provider_scope_mismatch",
        ),
        (
            "environment_id",
            "fixture.other-environment",
            "provider_scope_mismatch",
        ),
        (
            "source_id",
            "fixture.time.b",
            "provider_source_mismatch",
        ),
        (
            "evidence_role",
            REVOCATION_METADATA_ADAPTER_ROLE_V1,
            "provider_role_mismatch",
        ),
        (
            "provider_policy_id",
            _digest("other-provider-policy"),
            "provider_policy_mismatch",
        ),
        ("request_id", _digest("other-request"), "provider_request_mismatch"),
    ),
)
def test_provider_authentication_rejects_resigned_framing_substitution(
    field: str,
    replacement: object,
    reason_code: str,
) -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    statement = replace(
        _time_statement(profile=profile, request=request),
        **{field: replacement},
    )
    signed = _sign_raw_statement(
        source_id=request.source_id,
        evidence_role=TRUSTED_TIME_ADAPTER_ROLE_V1,
        statement_bytes=statement.to_canonical_bytes(),
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("field", "replacement", "reason_code"),
    (
        ("authority_id", _digest("other-authority"), "provider_authority_id_mismatch"),
        ("event_digest", _digest("other-event"), "provider_event_digest_mismatch"),
        ("imprint_id", _digest("other-imprint"), "provider_imprint_id_mismatch"),
        ("mission_id", _digest("other-mission"), "provider_mission_id_mismatch"),
        ("purpose", "checkpoint", "provider_purpose_mismatch"),
        ("target_id", _digest("other-target"), "provider_target_id_mismatch"),
        (
            "time_policy_id",
            _digest("other-time-policy"),
            "provider_time_policy_id_mismatch",
        ),
        (
            "transition_intent_id",
            _digest("other-transition"),
            "provider_transition_intent_id_mismatch",
        ),
        (
            "accuracy_authenticated",
            False,
            "provider_accuracy_authenticated_mismatch",
        ),
    ),
)
def test_provider_authentication_rejects_resigned_time_claim_substitution(
    field: str,
    replacement: object,
    reason_code: str,
) -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    claim = _time_claim(request)
    claim[field] = replacement
    signed = _signer(request.source_id).sign(
        _time_statement(profile=profile, request=request, claim=claim)
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == reason_code


def test_provider_authentication_rejects_request_profile_and_scope_substitution() -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    signed = _signer(request.source_id).sign(
        _time_statement(profile=profile, request=request)
    )

    for field, replacement in (
        ("profile_id", _digest("substituted-request-profile")),
        ("trust_root_id", _digest("substituted-request-root")),
        ("service_instance_id", "Etzio.substituted-service"),
        ("environment_id", "fixture.substituted-environment"),
    ):
        substituted = _replace_time_request(
            request,
            **{field: replacement},
        )
        with pytest.raises(IntegrityAdapterError) as refused:
            authenticate_provider_evidence_v1(
                profile=profile,
                request=substituted,
                signed_evidence=signed,
            )
        assert refused.value.reason_code == "provider_profile_mismatch"


def test_provider_authentication_rejects_role_key_and_signature_substitution() -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    signed = _signer(request.source_id).sign(
        _time_statement(profile=profile, request=request)
    )

    wrong_role = replace(
        signed,
        evidence_role=REVOCATION_METADATA_ADAPTER_ROLE_V1,
    )
    with pytest.raises(IntegrityAdapterError) as role:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=wrong_role,
        )
    assert role.value.reason_code == "provider_role_mismatch"

    wrong_key = replace(
        signed,
        key_id=_signer("fixture.time.b").trusted_key.key_id,
    )
    with pytest.raises(IntegrityAdapterError) as key:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=wrong_key,
        )
    assert key.value.reason_code == "unknown_adapter_key"

    corrupted_signature = bytes([signed.signature_bytes[0] ^ 1]) + (
        signed.signature_bytes[1:]
    )
    with pytest.raises(IntegrityAdapterError) as signature:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=replace(
                signed,
                signature_bytes=corrupted_signature,
            ),
        )
    assert signature.value.reason_code == "provider_signature_invalid"


def test_provider_authentication_rejects_reversed_or_malformed_time_claim() -> None:
    profile = _profile()
    request = _time_request(profile=profile)

    reversed_claim = _time_claim(request, lower=105, upper=104)
    reversed_signed = _signer(request.source_id).sign(
        _time_statement(
            profile=profile,
            request=request,
            claim=reversed_claim,
        )
    )
    with pytest.raises(IntegrityAdapterError) as reversed_interval:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=reversed_signed,
        )
    assert (
        reversed_interval.value.reason_code
        == "trusted_time_interval_reversed"
    )

    malformed_claim = _time_claim(request)
    malformed_claim["unknown"] = _digest("unknown-claim-field")
    malformed_signed = _signer(request.source_id).sign(
        _time_statement(
            profile=profile,
            request=request,
            claim=malformed_claim,
        )
    )
    with pytest.raises(IntegrityAdapterError) as malformed:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=malformed_signed,
        )
    assert malformed.value.reason_code == "invalid_trusted_time_claim"


def test_signed_provider_evidence_rejects_noncanonical_or_malformed_wire() -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    statement = _time_statement(profile=profile, request=request)
    signed = _signer(request.source_id).sign(statement)

    with pytest.raises(IntegrityAdapterError) as whitespace:
        SignedProviderEvidenceV1.from_canonical_bytes(
            signed.to_canonical_bytes() + b"\n"
        )
    assert whitespace.value.reason_code == "invalid_signed_provider_evidence"

    body = signed.to_body()
    body["unknown"] = "refused"
    with pytest.raises(IntegrityAdapterError) as unknown:
        SignedProviderEvidenceV1.from_canonical_bytes(canonical_dumps(body))
    assert unknown.value.reason_code == "invalid_signed_provider_evidence"

    body = signed.to_body()
    body["signature_b64"] = "not/canonical==="
    with pytest.raises(IntegrityAdapterError) as base64_refused:
        SignedProviderEvidenceV1.from_canonical_bytes(canonical_dumps(body))
    assert base64_refused.value.reason_code == "invalid_adapter_base64"

    noncanonical_statement = statement.to_canonical_bytes() + b"\n"
    signed_noncanonical_statement = _sign_raw_statement(
        source_id=request.source_id,
        evidence_role=TRUSTED_TIME_ADAPTER_ROLE_V1,
        statement_bytes=noncanonical_statement,
    )
    with pytest.raises(IntegrityAdapterError) as statement_refused:
        authenticate_provider_evidence_v1(
            profile=profile,
            request=request,
            signed_evidence=signed_noncanonical_statement,
        )
    assert statement_refused.value.reason_code == "invalid_provider_statement"


def test_authenticated_package_direct_construction_is_refused() -> None:
    profile = _profile()
    request = _time_request(profile=profile)
    signed = _signer(request.source_id).sign(
        _time_statement(profile=profile, request=request)
    )
    valid = authenticate_provider_evidence_v1(
        profile=profile,
        request=request,
        signed_evidence=signed,
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        AuthenticatedProviderEvidencePackageV1(
            profile_id=valid.profile_id,
            request=valid.request,
            signed_evidence=valid.signed_evidence,
            statement=valid.statement,
            source_binding=valid.source_binding,
            provider_evidence=valid.provider_evidence,
            claim=valid.claim,
            _seal=object(),
        )
    assert refused.value.reason_code == "unauthenticated_result_construction"


def test_time_qualification_is_deterministic_and_reauthenticates_exact_bytes() -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
    )

    first = qualify_time_bundle_v1(
        profile=profile,
        requests=requests,
        signed_evidence=signed,
    )
    second = qualify_time_bundle_v1(
        profile=profile,
        requests=dict(reversed(tuple(requests.items()))),
        signed_evidence=dict(reversed(tuple(signed.items()))),
    )
    fresh = reauthenticate_time_bundle_v1(profile=profile, bundle=first)

    assert first == second == fresh
    assert first.to_body() == second.to_body() == fresh.to_body()
    assert first.bundle_id == second.bundle_id == fresh.bundle_id
    assert first.time_lower_bound == 100
    assert first.time_upper_bound == 104
    assert first.requests == tuple(requests.values())
    assert first.signed_evidence == tuple(signed.values())
    assert first.evidence == tuple(
        blob.reference for blob in first.evidence_blobs
    )
    for request, package, blob in zip(
        first.requests,
        first.authenticated_packages,
        first.evidence_blobs,
        strict=True,
    ):
        exact_signed = signed[request.source_id]
        assert package.request == request
        assert package.signed_evidence == exact_signed
        assert blob == package.provider_evidence
        assert blob.content == exact_signed.to_canonical_bytes()


@pytest.mark.parametrize(
    ("mapping_name", "mutation"),
    (
        ("requests", "missing"),
        ("requests", "extra"),
        ("signed_evidence", "missing"),
        ("signed_evidence", "extra"),
    ),
)
def test_time_qualification_requires_exact_source_roster(
    mapping_name: str,
    mutation: str,
) -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
    )
    mapping: dict[str, object] = (
        dict(requests) if mapping_name == "requests" else dict(signed)
    )
    if mutation == "missing":
        del mapping["fixture.time.a"]
    else:
        mapping["fixture.time.extra"] = next(iter(mapping.values()))

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_time_bundle_v1(
            profile=profile,
            requests=(
                mapping  # type: ignore[arg-type]
                if mapping_name == "requests"
                else requests
            ),
            signed_evidence=(
                mapping  # type: ignore[arg-type]
                if mapping_name == "signed_evidence"
                else signed
            ),
        )
    assert refused.value.reason_code == "provider_source_set_mismatch"


@pytest.mark.parametrize("mapping_name", ("requests", "signed_evidence"))
def test_time_qualification_rejects_a_duplicate_emitting_hostile_mapping(
    mapping_name: str,
) -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
    )
    source = "fixture.time.a"
    source_mapping: dict[str, object] = (
        requests if mapping_name == "requests" else signed
    )
    hostile = _DuplicateEmittingMapping(
        (
            *source_mapping.items(),
            (source, source_mapping[source]),
        )
    )
    assert tuple(key for key, _ in hostile.items()).count(source) == 2

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_time_bundle_v1(
            profile=profile,
            requests=(
                hostile  # type: ignore[arg-type]
                if mapping_name == "requests"
                else requests
            ),
            signed_evidence=(
                hostile  # type: ignore[arg-type]
                if mapping_name == "signed_evidence"
                else signed
            ),
        )
    assert refused.value.reason_code == "provider_source_set_mismatch"


def test_time_qualification_uses_common_overlap_and_conservative_outer_hull() -> None:
    profile = _profile(
        policy=_validation_policy(max_decision_uncertainty_seconds=6)
    )
    bundle = _qualified_time(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 104),
            "fixture.time.b": (102, 106),
        },
    )

    assert bundle.time_lower_bound == 100
    assert bundle.time_upper_bound == 106


def test_time_qualification_accepts_exact_uncertainty_and_point_overlap_boundary() -> None:
    profile = _profile()
    bundle = _qualified_time(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
    )

    assert bundle.time_lower_bound == 100
    assert bundle.time_upper_bound == 104
    assert bundle.time_upper_bound - bundle.time_lower_bound == (
        profile.validation_policy.max_decision_uncertainty_seconds
    )


def test_time_qualification_rejects_disjoint_intervals() -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 101),
            "fixture.time.b": (102, 103),
        },
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "trusted_time_intervals_disjoint"


def test_time_qualification_rejects_outer_hull_above_exact_uncertainty_limit() -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 103),
            "fixture.time.b": (102, 105),
        },
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "trusted_time_uncertainty_exceeded"


def test_time_qualification_rejects_source_interval_above_policy() -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 105),
            "fixture.time.b": (102, 104),
        },
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=signed,
        )
    assert (
        refused.value.reason_code
        == "trusted_time_source_uncertainty_exceeded"
    )


def test_time_qualification_rejects_cross_source_request_context_mix() -> None:
    profile = _profile()
    requests, signed = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
    )
    mixed_request = _time_request(
        profile=profile,
        source_id="fixture.time.b",
        nonce_label="different-bundle",
    )
    requests["fixture.time.b"] = mixed_request
    signed["fixture.time.b"] = _signer("fixture.time.b").sign(
        _time_statement(
            profile=profile,
            request=mixed_request,
            claim=_time_claim(mixed_request, lower=102, upper=104),
        )
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "provider_request_mismatch"


def test_repository_time_adapter_exact_retry_has_no_clock_or_network_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    requests, _ = _time_bundle_inputs(
        profile=profile,
        intervals={
            "fixture.time.a": (100, 102),
            "fixture.time.b": (102, 104),
        },
    )
    adapters = {
        binding.source_id: RepositoryOwnedDeterministicTrustedTimeAdapterV1(
            profile=profile,
            binding=binding,
            signer=_signer(binding.source_id),
            time_lower_bound=(
                100 if binding.source_id == "fixture.time.a" else 102
            ),
            time_upper_bound=(
                102 if binding.source_id == "fixture.time.a" else 104
            ),
        )
        for binding in profile.source_bindings
        if binding.role == TRUSTED_TIME_ADAPTER_ROLE_V1
    }

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ambient clock or network access is forbidden")

    with monkeypatch.context() as guarded:
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "getaddrinfo", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(time, "time", forbidden)
        guarded.setattr(time, "time_ns", forbidden)
        guarded.setattr(time, "monotonic", forbidden)
        first = {
            source_id: adapter.acquire(requests[source_id])
            for source_id, adapter in adapters.items()
        }
        second = {
            source_id: adapter.acquire(requests[source_id])
            for source_id, adapter in adapters.items()
        }
        first_bundle = qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=first,
        )
        second_bundle = qualify_time_bundle_v1(
            profile=profile,
            requests=requests,
            signed_evidence=second,
        )

    assert first == second
    assert first_bundle == second_bundle


def test_provider_authentication_rejects_a_profile_revoked_source_key() -> None:
    active = _profile()
    revoked_key_id = active.binding_for(
        role=TRUSTED_TIME_ADAPTER_ROLE_V1,
        source_id="fixture.time.a",
        namespace=None,
    ).key_id
    revoked = _profile(revoked_key_ids=frozenset({revoked_key_id}))
    request = _time_request(profile=revoked)
    signed = _signer(request.source_id).sign(
        _time_statement(profile=revoked, request=request)
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        authenticate_provider_evidence_v1(
            profile=revoked,
            request=request,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "revoked_adapter_key"


def test_revocation_qualification_is_deterministic_and_retains_exact_coverage() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    state = _fixture_revocation_state(fixture, "authority")
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=state.namespace,
        state=state,
    )

    first = qualify_revocation_bundle_v1(
        profile=fixture.profile,
        namespace=state.namespace,
        time_bundle=time_bundle,
        requests=requests,
        signed_evidence=signed,
    )
    second = qualify_revocation_bundle_v1(
        profile=fixture.profile,
        namespace=state.namespace,
        time_bundle=time_bundle,
        requests=dict(reversed(tuple(requests.items()))),
        signed_evidence=dict(reversed(tuple(signed.items()))),
    )
    fresh = reauthenticate_revocation_bundle_v1(
        profile=fixture.profile,
        time_bundle=time_bundle,
        bundle=first,
    )

    assert first == second == fresh
    assert first.to_body() == second.to_body() == fresh.to_body()
    assert first.bundle_id == second.bundle_id == fresh.bundle_id
    assert first.root_version == state.expected_root_version
    assert first.version == state.expected_version
    assert first.snapshot_id == state.expected_snapshot_id
    assert first.valid_from == state.expected_valid_from
    assert first.valid_until == state.expected_valid_until
    assert first.published_at == state.expected_published_at
    blobs_by_source = {
        blob.source_id: blob for blob in first.evidence_blobs
    }
    assert set(blobs_by_source) == set(requests)
    for source_id, exact_signed in signed.items():
        assert (
            blobs_by_source[source_id].content
            == exact_signed.to_canonical_bytes()
        )
    metadata_source = next(
        adapter.source_id
        for adapter in fixture.revocation_adapters
        if adapter.namespace == state.namespace
        and adapter.role == REVOCATION_METADATA_ADAPTER_ROLE_V1
    )
    floor_sources = {
        adapter.source_id
        for adapter in fixture.revocation_adapters
        if adapter.namespace == state.namespace
        and adapter.role == REVOCATION_FLOOR_ADAPTER_ROLE_V1
    }
    assert first.revocation_view.evidence == (
        blobs_by_source[metadata_source].reference
    )
    assert set(first.external_floor.evidence) == {
        blobs_by_source[source_id].reference for source_id in floor_sources
    }


@pytest.mark.parametrize(
    ("mapping_name", "mutation"),
    (
        ("requests", "missing"),
        ("requests", "extra"),
        ("signed_evidence", "missing"),
        ("signed_evidence", "extra"),
    ),
)
def test_revocation_qualification_requires_exact_source_roster(
    mapping_name: str,
    mutation: str,
) -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace="authority",
    )
    mapping: dict[str, object] = (
        dict(requests) if mapping_name == "requests" else dict(signed)
    )
    if mutation == "missing":
        del mapping[next(iter(mapping))]
    else:
        mapping["fixture.revocation-extra.authority"] = next(
            iter(mapping.values())
        )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace="authority",
            time_bundle=time_bundle,
            requests=(
                mapping  # type: ignore[arg-type]
                if mapping_name == "requests"
                else requests
            ),
            signed_evidence=(
                mapping  # type: ignore[arg-type]
                if mapping_name == "signed_evidence"
                else signed
            ),
        )
    assert refused.value.reason_code == "provider_source_set_mismatch"


def test_revocation_qualification_rejects_an_unrequired_namespace() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace="authority",
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace="catalog",
            time_bundle=time_bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert (
        refused.value.reason_code
        == "revocation_namespace_coverage_mismatch"
    )


def test_revocation_full_hull_accepts_exact_half_open_validity_boundaries() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    boundary = replace(
        base,
        expected_valid_from=time_bundle.time_lower_bound,
        expected_valid_until=time_bundle.time_upper_bound + 1,
    )

    qualified = _qualified_revocation(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=boundary,
    )

    assert qualified.valid_from == time_bundle.time_lower_bound
    assert qualified.valid_until == time_bundle.time_upper_bound + 1


@pytest.mark.parametrize("boundary", ("lower", "upper"))
def test_revocation_full_hull_rejects_outside_half_open_validity(
    boundary: str,
) -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    state = (
        replace(
            base,
            expected_valid_from=time_bundle.time_lower_bound + 1,
        )
        if boundary == "lower"
        else replace(
            base,
            expected_valid_until=time_bundle.time_upper_bound,
        )
    )
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=state,
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace=base.namespace,
            time_bundle=time_bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert (
        refused.value.reason_code
        == "revocation_validity_outside_window"
    )


def test_revocation_staleness_accepts_the_exact_policy_boundary() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    boundary = replace(
        base,
        expected_published_at=(
            time_bundle.time_upper_bound
            - fixture.profile.max_revocation_staleness_seconds
        ),
    )

    qualified = _qualified_revocation(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=boundary,
    )

    assert (
        time_bundle.time_upper_bound - qualified.published_at
        == fixture.profile.max_revocation_staleness_seconds
    )


@pytest.mark.parametrize("failure", ("stale", "future"))
def test_revocation_staleness_rejects_one_second_outside_policy(
    failure: str,
) -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    published_at = (
        time_bundle.time_upper_bound
        - fixture.profile.max_revocation_staleness_seconds
        - 1
        if failure == "stale"
        else time_bundle.time_lower_bound + 1
    )
    state = replace(base, expected_published_at=published_at)
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=state,
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace=base.namespace,
            time_bundle=time_bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "revocation_metadata_stale"


@pytest.mark.parametrize(
    "role",
    (
        REVOCATION_METADATA_ADAPTER_ROLE_V1,
        REVOCATION_FLOOR_ADAPTER_ROLE_V1,
    ),
)
def test_revocation_qualification_rejects_metadata_or_floor_disagreement(
    role: str,
) -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    changed = replace(
        base,
        expected_version=base.expected_version + 1,
        expected_snapshot_id=_digest(f"disagreeing-{role}-snapshot"),
    )
    changed_source = next(
        adapter.source_id
        for adapter in fixture.revocation_adapters
        if adapter.namespace == base.namespace and adapter.role == role
    )
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=base,
        source_states={changed_source: changed},
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace=base.namespace,
            time_bundle=time_bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == "revocation_floor_disagreement"


@pytest.mark.parametrize(
    ("changes", "reason_code"),
    (
        (
            {"prior_root_version": 2, "expected_root_version": 1},
            "revocation_root_rollback",
        ),
        (
            {"prior_root_version": 1, "expected_root_version": 3},
            "revocation_root_update_skipped",
        ),
        (
            {"prior_version": 3, "expected_version": 2},
            "revocation_version_rollback",
        ),
        (
            {"prior_version": 2, "expected_version": 2},
            "revocation_same_version_mutation",
        ),
    ),
)
def test_revocation_qualification_rejects_rollback_or_equivocation(
    changes: dict[str, object],
    reason_code: str,
) -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    state = replace(base, **changes)
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=state,
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        qualify_revocation_bundle_v1(
            profile=fixture.profile,
            namespace=base.namespace,
            time_bundle=time_bundle,
            requests=requests,
            signed_evidence=signed,
        )
    assert refused.value.reason_code == reason_code


def test_revocation_same_version_exact_snapshot_is_idempotent() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    base = _fixture_revocation_state(fixture, "authority")
    state = replace(
        base,
        expected_root_version=base.prior_root_version,
        expected_version=base.prior_version,
        expected_snapshot_id=base.prior_snapshot_id,
    )

    qualified = _qualified_revocation(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace=base.namespace,
        state=state,
    )

    assert qualified.version == base.prior_version
    assert qualified.snapshot_id == base.prior_snapshot_id


@pytest.mark.parametrize(
    ("field", "replacement", "reason_code"),
    (
        ("namespace", "verifier", "provider_namespace_mismatch"),
        (
            "decision_policy_id",
            _digest("other-decision-policy"),
            "provider_decision_policy_id_mismatch",
        ),
        (
            "time_bundle_id",
            _digest("other-time-bundle"),
            "provider_time_bundle_id_mismatch",
        ),
    ),
)
def test_revocation_authentication_rejects_resigned_claim_substitution(
    field: str,
    replacement: object,
    reason_code: str,
) -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace="authority",
    )
    adapter = next(
        value
        for value in fixture.revocation_adapters
        if value.namespace == "authority"
        and value.role == REVOCATION_METADATA_ADAPTER_ROLE_V1
    )
    request = requests[adapter.source_id]
    statement = ProviderEvidenceStatementV1.from_canonical_bytes(
        signed[adapter.source_id].statement_bytes
    )
    claim = dict(statement.claim)
    claim[field] = replacement
    substituted = adapter.signer.sign(replace(statement, claim=claim))

    with pytest.raises(IntegrityAdapterError) as refused:
        authenticate_provider_evidence_v1(
            profile=fixture.profile,
            request=request,
            signed_evidence=substituted,
        )
    assert refused.value.reason_code == reason_code


def test_revocation_authentication_rejects_invalid_authenticated_window() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    requests, signed = _revocation_inputs(
        fixture=fixture,
        time_bundle=time_bundle,
        namespace="authority",
    )
    adapter = next(
        value
        for value in fixture.revocation_adapters
        if value.namespace == "authority"
        and value.role == REVOCATION_METADATA_ADAPTER_ROLE_V1
    )
    request = requests[adapter.source_id]
    statement = ProviderEvidenceStatementV1.from_canonical_bytes(
        signed[adapter.source_id].statement_bytes
    )
    claim = dict(statement.claim)
    claim["valid_until"] = claim["valid_from"]
    malformed = adapter.signer.sign(replace(statement, claim=claim))

    with pytest.raises(IntegrityAdapterError) as refused:
        authenticate_provider_evidence_v1(
            profile=fixture.profile,
            request=request,
            signed_evidence=malformed,
        )
    assert refused.value.reason_code == "invalid_revocation_window"


def test_provider_neutral_mapping_requires_every_namespace_and_exact_blob() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    revocations = {
        namespace: _qualified_revocation(
            fixture=fixture,
            time_bundle=time_bundle,
            namespace=namespace,
        )
        for namespace in ("authority", "verifier")
    }

    mapped = map_qualified_integrity_inputs_v1(
        profile=fixture.profile,
        time_bundle=time_bundle,
        revocation_bundles=revocations,
    )
    raw_by_source = {
        request.source_id: signed.to_canonical_bytes()
        for request, signed in zip(
            time_bundle.requests,
            time_bundle.signed_evidence,
            strict=True,
        )
    }
    for bundle in revocations.values():
        raw_by_source.update(
            {
                request.source_id: signed.to_canonical_bytes()
                for request, signed in zip(
                    bundle.requests,
                    bundle.signed_evidence,
                    strict=True,
                )
            }
        )
    assert len(mapped.evidence_blobs) == len(raw_by_source)
    assert {
        blob.source_id: blob.content for blob in mapped.evidence_blobs
    } == raw_by_source
    references = {
        (
            reference.evidence_kind,
            reference.source_id,
            reference.evidence_id,
        )
        for reference in (
            *mapped.time_evidence,
            *(view.evidence for view in mapped.revocation_views),
            *(
                evidence
                for floor in mapped.external_floors
                for evidence in floor.evidence
            ),
        )
    }
    retained = {
        (
            blob.evidence_kind,
            blob.source_id,
            blob.evidence_id,
        )
        for blob in mapped.evidence_blobs
    }
    assert references == retained
    assert len(references) == len(mapped.evidence_blobs)

    with pytest.raises(IntegrityAdapterError) as missing:
        map_qualified_integrity_inputs_v1(
            profile=fixture.profile,
            time_bundle=time_bundle,
            revocation_bundles={"authority": revocations["authority"]},
        )
    assert missing.value.reason_code == "provider_source_set_mismatch"

    with pytest.raises(IntegrityAdapterError) as extra:
        map_qualified_integrity_inputs_v1(
            profile=fixture.profile,
            time_bundle=time_bundle,
            revocation_bundles={
                **revocations,
                "catalog": revocations["authority"],
            },
        )
    assert extra.value.reason_code == "provider_source_set_mismatch"


def test_provider_neutral_mapping_rejects_swapped_sealed_namespace_bundles() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    revocations = {
        namespace: _qualified_revocation(
            fixture=fixture,
            time_bundle=time_bundle,
            namespace=namespace,
        )
        for namespace in ("authority", "verifier")
    }

    with pytest.raises(IntegrityAdapterError) as refused:
        map_qualified_integrity_inputs_v1(
            profile=fixture.profile,
            time_bundle=time_bundle,
            revocation_bundles={
                "authority": revocations["verifier"],
                "verifier": revocations["authority"],
            },
        )
    assert (
        refused.value.reason_code
        == "revocation_namespace_coverage_mismatch"
    )


def test_qualification_harness_and_report_are_exactly_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_fixture = _repository_fixture()
    second_fixture = _repository_fixture()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("qualification used ambient clock or network")

    with monkeypatch.context() as guarded:
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "getaddrinfo", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(time, "time", forbidden)
        guarded.setattr(time, "time_ns", forbidden)
        guarded.setattr(time, "monotonic", forbidden)
        first = qualify_repository_time_revocation_adapters_v1(
            first_fixture
        )
        retry = qualify_repository_time_revocation_adapters_v1(
            first_fixture
        )
        independently_rebuilt = (
            qualify_repository_time_revocation_adapters_v1(second_fixture)
        )

    assert first_fixture == second_fixture
    assert first == retry == independently_rebuilt
    assert first.to_body() == retry.to_body() == independently_rebuilt.to_body()
    assert first.report_id == retry.report_id == independently_rebuilt.report_id
    assert first.passed
    assert tuple(case.case_id for case in first.cases) == (
        "decision-time-exact-retry",
        "decision-time-qualification",
        "checkpoint-time-exact-retry",
        "checkpoint-time-qualification",
        "cross-request-replay-refused",
        "revocation-authority-exact-retry",
        "revocation-authority-qualification",
        "revocation-verifier-exact-retry",
        "revocation-verifier-qualification",
        "provider-neutral-mapping",
    )
    assert all(case.passed for case in first.cases)
    replay = next(
        case
        for case in first.cases
        if case.case_id == "cross-request-replay-refused"
    )
    assert replay.expected_disposition == "refused"
    assert replay.observed_disposition == "refused"
    assert replay.reason_code == "provider_request_mismatch"


def test_qualification_harness_rejects_manifest_substitution() -> None:
    fixture = _repository_fixture()

    with pytest.raises(IntegrityAdapterError) as refused:
        replace(
            fixture,
            corpus_manifest_id=_digest("substituted-corpus-manifest"),
        )
    assert refused.value.reason_code == "qualification_manifest_mismatch"


@pytest.mark.parametrize(
    ("adapter_field", "mutation"),
    (
        ("time_adapters", "duplicate"),
        ("time_adapters", "reordered"),
        ("revocation_adapters", "duplicate"),
        ("revocation_adapters", "reordered"),
    ),
)
def test_qualification_fixture_requires_exact_canonical_adapter_tuples(
    adapter_field: str,
    mutation: str,
) -> None:
    fixture = _repository_fixture()
    adapters = getattr(fixture, adapter_field)
    changed = (
        (*adapters, adapters[0])
        if mutation == "duplicate"
        else tuple(reversed(adapters))
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        replace(fixture, **{adapter_field: changed})
    assert refused.value.reason_code == "provider_source_set_mismatch"


def test_qualification_manifest_binds_implementation_and_time_adapter_inputs() -> None:
    fixture = _repository_fixture()

    with pytest.raises(IntegrityAdapterError) as implementation:
        replace(
            fixture,
            adapter_implementation_id=_digest(
                "substituted-adapter-implementation"
            ),
        )
    assert (
        implementation.value.reason_code
        == "qualification_manifest_mismatch"
    )

    first, *remaining = fixture.time_adapters
    changed_time = replace(
        first,
        time_lower_bound=first.time_lower_bound + 1,
    )
    with pytest.raises(IntegrityAdapterError) as interval:
        replace(
            fixture,
            time_adapters=(changed_time, *remaining),
        )
    assert interval.value.reason_code == "qualification_manifest_mismatch"


def test_qualification_manifest_binds_revocation_vector_and_adapter_inputs() -> None:
    fixture = _repository_fixture()
    original = _fixture_revocation_state(fixture, "authority")
    changed = replace(
        original,
        expected_published_at=original.expected_published_at + 1,
    )
    changed_states = tuple(
        changed if state.namespace == changed.namespace else state
        for state in fixture.vector.expected_revocation
    )
    changed_vector = replace(
        fixture.vector,
        expected_revocation=changed_states,
    )
    changed_adapters = tuple(
        replace(adapter, state=changed)
        if adapter.namespace == changed.namespace
        else adapter
        for adapter in fixture.revocation_adapters
    )

    with pytest.raises(IntegrityAdapterError) as refused:
        replace(
            fixture,
            vector=changed_vector,
            revocation_adapters=changed_adapters,
        )
    assert refused.value.reason_code == "qualification_manifest_mismatch"


def test_all_sealed_results_refuse_direct_or_replace_construction() -> None:
    fixture = _repository_fixture()
    time_bundle = _fixture_time_bundle(fixture)
    revocations = {
        namespace: _qualified_revocation(
            fixture=fixture,
            time_bundle=time_bundle,
            namespace=namespace,
        )
        for namespace in ("authority", "verifier")
    }
    mapped = map_qualified_integrity_inputs_v1(
        profile=fixture.profile,
        time_bundle=time_bundle,
        revocation_bundles=revocations,
    )
    report = qualify_repository_time_revocation_adapters_v1(fixture)
    request = time_bundle.requests[0]
    authenticated = authenticate_provider_evidence_v1(
        profile=fixture.profile,
        request=request,
        signed_evidence=time_bundle.signed_evidence[0],
    )
    results: tuple[
        AuthenticatedProviderEvidencePackageV1
        | QualifiedTimeBundleV1
        | QualifiedRevocationBundleV1
        | QualifiedIntegrityInputsV1
        | IntegrityAdapterQualificationReportV1,
        ...,
    ] = (
        authenticated,
        time_bundle,
        revocations["authority"],
        mapped,
        report,
    )

    for result in results:
        with pytest.raises(IntegrityAdapterError) as direct:
            type(result)()
        assert (
            direct.value.reason_code
            == "unauthenticated_result_construction"
        )
        with pytest.raises(IntegrityAdapterError) as copied:
            replace(result)
        assert (
            copied.value.reason_code
            == "unauthenticated_result_construction"
        )
