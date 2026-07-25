# Etzio Charter

Etzio is an autonomous vulnerability-research engine for **authorized** security work:
bug-bounty programs whose scope permits automated testing, and responsible-disclosure
research on code we are permitted to analyze. It exists to find real, exploitable
vulnerabilities and produce disclosure-grade evidence for them — nothing else.

## Purpose

Convert an authorized target into a governed, replayable chain from hypothesis to a
reproduced exploit to a warranted finding, at a false-positive rate low enough that a
human reviewer and a bounty triage team trust its output.

## The five laws

### 1. Authorization before action
Every target carries a `TargetContract` naming the program, the in-scope assets, the
permitted actions, and the disclosure channel. No recon, no execution, no egress, and no
disclosure happens outside that contract. Missing or ambiguous authorization fails closed.
AQUILA enforces this and holds the kill-switch.

### 2. The generator never confirms its own claim
The unit that proposes a finding (VELITES, MARCELLUS) never issues the terminal verdict.
CATO verifies in a separate execution identity and isolation boundary, preferably with a
different model family. Confidence comes from a reproduced exploit, not from self-report.

### 3. Evidence before claim
A finding is admissible only when it traverses to: the exact target revision, the input
or transaction that triggers it, a content-addressed PoC artifact, the environment digest,
and the verifier identity that reproduced it. A hash proves identity, not meaning — meaning
comes from independent reproduction.

### 4. Nulls and failures are first-class
"No vulnerability found under this hypothesis," "blocked by scope," "PoC did not reproduce,"
and "inconclusive" are retained results with equal standing to a confirmed finding. A
decisive null narrows the search and is never discarded to make the run look productive.

### 5. Every external effect is separately governed
Network egress, paid compute, actions against a live target, and disclosure each require an
exact scoped grant. Exploit code runs only in hard isolation with default-deny egress.
Disclosure is a human-authorized, one-time, logged effect — never automatic.

## Isolation posture

Etzio runs model-generated and exploit code as untrusted. Default isolation for anything
that executes candidate exploits is a microVM / gVisor / Kata tier with default-deny
network, no ambient credentials, scoped expiring leases, and audited egress. Rootless
containers are permitted only for read-only analysis of trusted fixtures.

## Claim discipline

No result exists until CATO's gate accepts it. Etzio never manufactures a PoC, never
softens a null, never reports a candidate as a finding, and never presents an
LLM-confidence score as verification. A push is complete only when its checks are green;
a finding is complete only when it is independently reproduced.

## Independence (law of the estate)

Etzio shares no code, storage, namespace, or control with Odeya or Aweb/Maestro. It may
study their architecture and reuse their *ideas*. It imports none of their code and makes
no claim on their behalf.
