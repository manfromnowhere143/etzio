# Contributing to Etzio

Etzio is currently a private, owner-maintained research repository. External contributions
are not accepted during the foundation phase.

## Engineering flow

1. Recover the exact mission state from `docs/SESSION_HANDOFF.md`.
2. Create a focused `agent/<description>` branch from `main`.
3. Change one dependency-complete tranche.
4. Add a known-bad test for every new consequential gate.
5. Run `make verify`.
6. Inspect the complete diff and commit only the declared scope.
7. Open a pull request; integrate only after required checks pass.

## Authorship

Daniel Wahnich is the sole author. Commits use:

```text
Daniel Wahnich <cogitoergosum143@gmail.com>
```

Do not add `Co-Authored-By` trailers. Dependency upgrades are reviewed and committed by
Daniel rather than committed by automation.

## Dependency and workflow changes

- Python validation dependencies are exact and hash-locked in
  `tools/ci/requirements-ci.lock`.
- Regenerate the lock from `tools/ci/requirements-ci.in`; never hand-edit it.
- GitHub Actions must be pinned to immutable 40-character commit SHAs.
- Workflows use least privilege, explicit timeouts, credential-free checkout, and retained
  diagnostic evidence.
- Workflow YAML does not use anchors, aliases, or merge keys; repository policy rejects
  syntax that its dependency-free checker cannot resolve safely.

## Security research constraints

Do not add real credentials, third-party exploit payloads, undisclosed findings, private
target source, or live mission ledgers to Git. Execute only repository-owned deterministic
fixtures until the authority and isolation gates permit more. Historical benchmark material
is read-only during the foundation phase.

Report concerns using `SECURITY.md`; do not create public disclosure from repository bytes.
