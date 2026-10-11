# Effect evidence: a finite falsification experiment

Status: repository-owned experiment, 2026-10-11. This specifies and tests a proposed
evaluation requirement. It implements no CATO runner, finding admission, benchmark,
target adapter or native-provider integration. The foundation order is unchanged.

## Question and contract before execution

Can an effect disappearing after a patch establish a useful repair or identify one
root cause? Test this in a completely enumerated, benign state machine before relying
on that implication in future structured execution evidence.

The owned model has two actors (owner and outsider), two independent write routes,
and a single bit of state. A policy has four permission bits, one per actor/route.
Owner is actor `0`, outsider is actor `1`, and the permission bit is `2 * actor + route`.
Enumerate all `16` policies and, for each, all `16` actor/route/initial/requested-state
combinations. An allowed write sets the requested bit; a refused write leaves state
unchanged. There is no network, filesystem target, subprocess or third-party code.

The frozen specification requires outsider operations to preserve state and owner
operations on either route to produce the requested state. These requirements come
from this experiment's authored specification, not from a generator's success claim.
They are evaluated from complete transitions and cross-checked against a separate
four-bit permission-table characterization. This is logical cross-checking by one
implementation team, not independent operational verification.

The deliberately insufficient rule accepts a candidate patch when one outsider
write changes state under the permissive reference policy but no longer does so
under the candidate. The stronger requirement also checks all protected operations
and all legitimate operations over the declared finite space. Missing or incomplete
observations stay `unobserved`; silence never turns them into a successful repair.

## Reproduction and acceptance

Run `.venv/bin/python scripts/replay_effect_evidence_experiment.py`. Its deterministic
JSON report retains every policy's complete transitions and verdict. The research
controls are in `tests/test_effect_evidence_experiment.py`.

The experiment is successful only if it exposes the expected counterexamples:

- the single differential accepts eight policies, seven of which violate the full
  specification;
- three accepted policies preserve security while breaking legitimate behavior;
- four accepted policies leave the other outsider route writable;
- only policy `3` preserves all required behavior and blocks both outsider routes;
- the correct patch and the disable-everything patch have the same single-attack
  differential; their legitimate-operation outcomes distinguish them;
- two distinct route defects produce the same effect, and one combined patch removes
  both; an effect or patch identity alone cannot identify the defect;
- incomplete observations stay unknown even if stale post-state happens to be present.

These are results over this finite model, not performance rates or evidence that an
existing Etzio verifier admits bad repairs. The current receipts authenticate opaque
modeled output bytes and make no execution/finding claim. No such admission is changed.

## Consequence for the later execution contract

Keep four separate judgments: observed property violation, causal attribution,
repair effectiveness, and legitimate behavior preservation. Bind each to exact target,
candidate, probe, patch, environment, initial state and actor authority. Retain failed
and incomplete runs. A patch that prevents startup or breaks the permitted workflow
cannot earn a repair claim merely because the original probe becomes silent.

Require independently controlled state observation, predeclared legitimate workloads,
no-op and near-miss controls, exact replay, and explicit coverage limits. A no-op control
addresses spontaneous changes; it does not prove resistance to an attacker manipulating
the observation channel. A comprehensive claim about a real application remains out of
reach when its state space and legitimate behavior are not completely specified.

Root-cause deduplication needs separate evidence. Multiple probes may describe one cause;
one probe may be triggered by several causes. A bundled patch can remove several causes,
or suppress their shared prerequisite. Report unresolved attribution rather than
collapsing these cases into an invented count of distinct vulnerabilities.

This experiment informs the future structured receipt contract after the existing
foundation and isolation gates. It does not authorize building that execution service
early. See the [decision packet](FRONTIER_EXECUTION_DECISION_2026-10-11.md).
