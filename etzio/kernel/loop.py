"""ETZIO master loop — one disciplined pass, not a chaotic swarm. It drives the chain,
enforces the laws mechanically, and appends every consequential step to the ledger.

Laws enforced here in code (not by convention):
  * Authorization before action  — AQUILA.permit() gates every stage; refusal fails closed.
  * Generator never confirms      — a candidate's producer identity may not equal the verifier's.
  * Evidence before claim         — only a CATO 'confirmed' verdict mints a Finding.
  * Nulls are first-class         — a hypothesis with no candidate is recorded as a NullResult.
"""

from __future__ import annotations

from ..contracts import (
    Candidate,
    Finding,
    NullResult,
    Stage,
    TargetContract,
    VerdictKind,
)
from ..engines import Target, Unit
from .events import EventLedger
from .state import MissionState


class ScopeError(RuntimeError):
    """Raised when a stage is attempted outside the TargetContract. Fails closed."""


class GeneratorIsVerifierError(RuntimeError):
    """Raised if the unit that produced a candidate would also verify it (law 2)."""


class MasterLoop:
    def __init__(self, mission_id: str, contract: TargetContract,
                 roster: dict[str, Unit], target: Target) -> None:
        self.mission_id = mission_id
        self.contract = contract
        self.roster = roster
        self.target = target
        self.ledger = EventLedger()
        self.state = MissionState(mission_id)

    def _emit(self, kind: str, unit: str, payload: dict) -> None:
        self.ledger.append(self.mission_id, kind, unit, payload)

    def _gate(self, action: str, asset: str) -> None:
        ok, reason = self.roster["AQUILA"].permit(action, asset, self.contract)
        if not ok:
            self._emit("scope_refused", "AQUILA", {"action": action, "asset": asset, "reason": reason})
            raise ScopeError(f"{action} on {asset}: {reason}")

    def run(self) -> MissionState:
        s, r, mid = self.state, self.roster, self.mission_id
        asset = self.contract.in_scope[0]

        self._emit("mission_opened", "ETZIO", {"program": self.contract.program})
        s.advance(Stage.AUTHORIZED)
        self._emit("scope_authorized", "AQUILA", {"in_scope": list(self.contract.in_scope)})

        # RECON
        self._gate("static_analysis", asset)
        s.advance(Stage.RECON)
        surface = r["SCIPIO"].map_surface(self.contract)
        self._emit("recon_recorded", "SCIPIO", {"entrypoints": surface["entrypoints"]})

        # THREAT MODEL
        s.advance(Stage.THREAT_MODEL)
        hyps = r["FABIUS"].hypotheses(surface, self.contract)
        self._emit("hypotheses_recorded", "FABIUS", {"count": len(hyps),
                                                     "ids": [h.id for h in hyps]})

        # INVESTIGATE (the swarm proposes; nulls are recorded honestly)
        s.advance(Stage.INVESTIGATE)
        candidates: list[Candidate] = []
        for h in hyps:
            self._gate("dynamic_analysis", asset)
            cand = r["VELITES"].investigate(h, self.contract, self.target)
            if cand is None:
                nr = NullResult(mid, h.id, "no candidate under this hypothesis")
                s.nulls.append(nr)
                self._emit("null_recorded", "VELITES", {"hypothesis_id": h.id})
            else:
                candidates.append(cand)
                self._emit("candidate_recorded", "VELITES",
                           {"candidate_id": cand.id, "hypothesis_id": h.id})

        # CONSTRUCT + VERIFY + ADJUDICATE, per candidate
        if candidates:
            s.advance(Stage.CONSTRUCT)
            for cand in candidates:
                self._gate("poc_execution", cand.target_asset)
                built = r["MARCELLUS"].construct_poc(cand, self.target)
                if built is None or built.poc is None:
                    self._emit("null_recorded", "MARCELLUS",
                               {"candidate_id": cand.id, "reason": "no reproducing PoC"})
                    s.nulls.append(NullResult(mid, cand.hypothesis_id, "no reproducing PoC"))
                    continue
                self._emit("poc_built", "MARCELLUS",
                           {"candidate_id": built.id, "poc_digest": built.poc.artifact_digest})

                # LAW 2 — the producer may not be the verifier.
                verifier = r["CATO"]
                if built.producer == verifier.identity:
                    raise GeneratorIsVerifierError(built.id)

                verdict = verifier.verify(built, self.contract, self.target)
                self._emit("verdict_recorded", "CATO",
                           {"candidate_id": built.id, "verdict": verdict.verdict.value,
                            "reasons": list(verdict.reasons)})

                if verdict.verdict is VerdictKind.CONFIRMED:
                    finding = Finding(
                        id=f"F-{built.id}",
                        mission_id=mid,
                        target_revision=self.target.revision,
                        hypothesis_id=built.hypothesis_id,
                        triggering_input=built.poc.payload,
                        poc_artifact_digest=built.poc.artifact_digest,
                        environment_digest=verdict.environment_digest,
                        verifier_identity=verdict.verifier_identity,
                        severity_level="high",
                        exploitability="demonstrated",
                        in_scope=True,
                    )
                    s.findings.append(finding)
                    self._emit("finding_minted", "ETZIO", {"finding_id": finding.id})
                else:
                    # not_reproduced / out_of_scope / inconclusive: a first-class non-finding.
                    s.nulls.append(NullResult(mid, built.hypothesis_id,
                                              f"verdict={verdict.verdict.value}"))

            s.advance(Stage.VERIFY)
            s.advance(Stage.ADJUDICATE)

        # TRIAGE
        if s.findings:
            s.advance(Stage.TRIAGE) if s.stage is Stage.ADJUDICATE else None
            ordered = r["CAMILLUS"].triage(s.findings)
            s.findings = ordered
            self._emit("triaged", "CAMILLUS", {"order": [f.id for f in ordered]})
            # DISCLOSE (draft only; submission stays a separate human effect)
            self._gate("disclosure_draft", asset)
            s.advance(Stage.DISCLOSE)
            for f in ordered:
                _ = r["FABRICIUS"].report(f)
                self._emit("report_drafted", "FABRICIUS", {"finding_id": f.id})

        # LEARN
        s.advance(Stage.LEARN)
        lesson = r["MINERVA"].learn(s.findings, s.nulls)
        self._emit("lesson_recorded", "MINERVA", lesson)
        s.advance(Stage.CLOSED)
        self._emit("mission_closed", "ETZIO",
                   {"findings": len(s.findings), "nulls": len(s.nulls)})
        return s
