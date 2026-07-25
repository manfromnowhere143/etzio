# Security & authorized-use posture

Etzio is a vulnerability-research engine. It is built for, and may be used only for,
**authorized** security work:

- bug-bounty programs whose published scope permits automated testing;
- written-permission engagements;
- responsible-disclosure research on code we are permitted to analyze;
- locally-owned benchmark targets.

## Non-negotiable operating rules

1. **Authorization before action.** Every hunt carries a `TargetContract`. Anything not in
   scope is out of scope by default. Missing or ambiguous authorization fails closed.
   AQUILA enforces this at the kernel and holds the kill-switch.
2. **Exploit code runs only in hard isolation** — default-deny egress, no ambient
   credentials, scoped expiring leases. Model-generated and candidate-exploit code is treated
   as untrusted.
3. **Disclosure is a separate, human-authorized effect.** Etzio drafts reports (FABRICIUS);
   it never submits or discloses on its own.
4. **No result exists until CATO independently reproduces it.** Etzio does not present
   LLM-confidence as verification and does not manufacture proofs.

## Reporting an issue in Etzio itself

Etzio is private and pre-release. Report concerns through the estate's governed channel:
research@danielwahnich.dev.
