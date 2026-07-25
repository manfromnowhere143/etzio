"""The ten units as typed ports. Bodies here are SKELETON stubs: deterministic, clearly
fake, enough to run the chain end-to-end and prove the architecture. Each real unit is
closed later by its own vertical slice. A unit proposes; it never writes the ledger, and a
producer unit never issues its own verdict.

`Target` is the thing under test. For the foundation it is a tiny deterministic sandbox
(`BenchmarkTarget`) so CATO can genuinely re-run a PoC and reject a planted false positive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from ..contracts import (
    Candidate,
    Hypothesis,
    PoCArtifact,
    TargetContract,
    Verdict,
    VerdictKind,
    digest,
)


class Target(Protocol):
    """Minimal contract for a thing under test: replay a payload, observe an effect."""
    revision: str
    def run(self, payload: str) -> str: ...


@dataclass
class Unit:
    identity: str          # execution identity, used to enforce generator != verifier
    role: str


# --- SCIPIO: recon & attack-surface mapping ---------------------------------------------
class Scipio(Unit):
    def __init__(self) -> None:
        super().__init__("SCIPIO", "recon")

    def map_surface(self, contract: TargetContract) -> dict:
        # STUB: a real SCIPIO parses the repo/protocol and returns entrypoints + trust boundaries.
        return {"assets": list(contract.in_scope), "entrypoints": ["transfer", "withdraw", "approve"]}


# --- FABIUS: threat modeling & ranked hypotheses ----------------------------------------
class Fabius(Unit):
    def __init__(self) -> None:
        super().__init__("FABIUS", "threat_model")

    def hypotheses(self, surface: dict, contract: TargetContract) -> list[Hypothesis]:
        # STUB: a real FABIUS builds a domain hypothesis library (e.g. DeFi: reentrancy, oracle, replay).
        asset = surface["assets"][0]
        return [
            Hypothesis("H1", "integer_overflow",
                       f"withdraw() on {asset} allows unbounded amount", "replay overflow payload", 0.9),
            Hypothesis("H2", "access_control",
                       f"approve() on {asset} is missing an owner check", "replay unauthorized approve", 0.6),
            Hypothesis("H3", "reentrancy",
                       f"transfer() on {asset} is reentrant", "replay reentrant call", 0.5),
        ]


# --- VELITES: the finder swarm (proposes candidates; never confirms) --------------------
class Velites(Unit):
    def __init__(self) -> None:
        super().__init__("VELITES", "investigate")

    def investigate(self, hyp: Hypothesis, contract: TargetContract, target: Target) -> Optional[Candidate]:
        # STUB: a real VELITES agent statically/dynamically probes the target for this hypothesis.
        # The foundation encodes three deterministic outcomes to exercise every path:
        #   H1 -> a genuine candidate (payload truly drains)         -> becomes a confirmed finding
        #   H2 -> a planted FALSE POSITIVE (claims effect it lacks)  -> CATO must reject
        #   H3 -> nothing under this hypothesis                      -> a first-class NullResult
        asset = contract.in_scope[0]
        if hyp.id == "H1":
            poc = PoCArtifact(payload="withdraw(amount=2**256)", claimed_effect="balance_drained")
            return Candidate("C1", hyp.id, self.identity, asset, poc, "overflow reachable from withdraw()")
        if hyp.id == "H2":
            poc = PoCArtifact(payload="approve(spender=attacker)", claimed_effect="balance_drained")
            return Candidate("C2", hyp.id, self.identity, asset, poc, "looks unauthorized (unverified)")
        return None  # H3: honest null


# --- MARCELLUS: exploit / PoC construction in isolation ----------------------------------
class Marcellus(Unit):
    def __init__(self) -> None:
        super().__init__("MARCELLUS", "construct")

    def construct_poc(self, candidate: Candidate, target: Target) -> Optional[Candidate]:
        # STUB: a real MARCELLUS builds a compiling, reproducing PoC in a hard-isolated sandbox.
        # Here the candidate already carries its PoC; a candidate without a PoC cannot proceed.
        return candidate if candidate.poc is not None else None


# Effects CATO recognizes as materially impactful (a modeled impact oracle for the
# benchmark). A candidate only becomes a finding if its re-execution produces one of these
# AND matches the producer's claim. Benign-but-honest effects are rejected, not confirmed.
KNOWN_EXPLOIT_EFFECTS = frozenset({"balance_drained", "price_manipulated", "funds_stolen"})


# --- CATO: independent verification & adjudication (the gate) ----------------------------
class Cato(Unit):
    def __init__(self, exploit_effects: frozenset[str] = KNOWN_EXPLOIT_EFFECTS) -> None:
        super().__init__("CATO", "verify")
        self.exploit_effects = exploit_effects

    def verify(self, candidate: Candidate, contract: TargetContract, target: Target) -> Verdict:
        # A DIFFERENT identity from the producer. Re-runs the PoC from bytes; trusts the
        # observed effect, not the producer's claim. This is where false positives die.
        # A finding requires BOTH: (1) the observed effect matches the claim on re-execution,
        # and (2) the observed effect is materially impactful. Either failing => not a finding.
        env = digest({"env": "clean-verify-sandbox", "revision": target.revision})
        if candidate.poc is None:
            return Verdict(candidate.id, VerdictKind.INCONCLUSIVE, self.identity, False, env,
                           ("no PoC to reproduce",))
        if not contract.covers(candidate.target_asset):
            return Verdict(candidate.id, VerdictKind.OUT_OF_SCOPE, self.identity, False, env,
                           ("asset outside TargetContract scope",))
        observed = target.run(candidate.poc.payload)
        claim_matches = observed == candidate.poc.claimed_effect
        is_impactful = observed in self.exploit_effects
        if claim_matches and is_impactful:
            return Verdict(candidate.id, VerdictKind.CONFIRMED, self.identity, True, env,
                           (f"re-execution produced impactful effect '{observed}' matching claim",))
        if not claim_matches:
            reason = f"claimed '{candidate.poc.claimed_effect}' but re-execution produced '{observed}'"
        else:
            reason = f"effect '{observed}' reproduces but is not materially impactful"
        return Verdict(candidate.id, VerdictKind.NOT_REPRODUCED, self.identity, False, env, (reason,))


# --- CAMILLUS: dedup, ranking, triage ----------------------------------------------------
class Camillus(Unit):
    def __init__(self) -> None:
        super().__init__("CAMILLUS", "triage")

    def triage(self, findings: list) -> list:
        _order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        return sorted(findings, key=lambda f: _order.get(f.severity_level, 0), reverse=True)


# --- FABRICIUS: disclosure & report generation ------------------------------------------
class Fabricius(Unit):
    def __init__(self) -> None:
        super().__init__("FABRICIUS", "disclose")

    def report(self, finding) -> str:
        # Renders from retained evidence only. Submission stays a separate human-authorized effect.
        return (
            f"# Finding {finding.id} — {finding.severity_level.upper()}\n"
            f"Target: {finding.target_revision}\n"
            f"Hypothesis: {finding.hypothesis_id}\n"
            f"Trigger: {finding.triggering_input}\n"
            f"PoC: {finding.poc_artifact_digest} (env {finding.environment_digest})\n"
            f"Independently reproduced by: {finding.verifier_identity}\n"
        )


# --- AQUILA: governance, scope, egress, kill-switch --------------------------------------
class Aquila(Unit):
    def __init__(self) -> None:
        super().__init__("AQUILA", "governance")
        self.killed = False

    def permit(self, action: str, asset: str, contract: TargetContract) -> tuple[bool, str]:
        if self.killed:
            return False, "kill-switch engaged"
        if not contract.allows(action):
            return False, f"action '{action}' not permitted by contract"
        if not contract.covers(asset):
            return False, f"asset '{asset}' out of scope"
        return True, "in scope"

    def kill(self) -> None:
        self.killed = True


# --- MINERVA: grounded learning & memory (offline promotion only) -----------------------
class Minerva(Unit):
    def __init__(self) -> None:
        super().__init__("MINERVA", "learn")

    def learn(self, confirmed: list, nulls: list) -> dict:
        # STUB: real MINERVA records which hypotheses paid off per target class; promotes offline only.
        return {
            "confirmed": len(confirmed),
            "nulls": len(nulls),
            "note": "offline lesson recorded; no production self-modification",
        }
