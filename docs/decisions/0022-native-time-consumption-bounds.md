# ADR-0022: Native timestamp acquisition and consumption bounds

- Status: accepted for offline conditional evaluation only
- Date: 2026-10-10
- Owner: Daniel Wahnich

## Decision and boundary

Add a separate offline composition over the unchanged ADR-0020 and ADR-0021 validators.
Reauthenticate the complete native dossier, bind it to an exact timing trace, and
propagate the issuance interval to receipt and consumption. Check the entire consumption
interval against an explicit half-open evaluation window. No supplied observation object
is accepted as authentication evidence. No network client, clock collector, provider
enrollment, kernel time conversion or lifecycle change is added.

This closes a mathematical prerequisite to acquisition. A fresh nonce binds a response
to a challenge but does not bound a network delay or a later scheduling pause. The current
offline validators intentionally describe issuance only. Their outputs must not be used
as the time of a later decision without an elapsed-time contract.

## Assumptions requiring external qualification

Let s be a local sample taken **before first disclosure of a fresh unpredictable
challenge**, r a sample after the complete response is received, and c the instant of
the intended use. An honest source and unique challenge imply s <= i <= r <= c,
where i is issuance. Sending the same disclosed challenge again does not reset s.
Repository fixture nonces and traces do not establish this causality in the real world.

All samples must refer to one exact clock profile and one uninterrupted epoch. The
profile must cover suspend, VM pause/migration, rate adjustment, clock replacement,
counter reset and reboot. It must bound reading error by e nanoseconds and clock rate
by 1-rho through 1+rho throughout the interval. A clock API name or advertised resolution
does not prove these bounds. The continuous POSIX-time window excludes leap/smear
discontinuities; a real profile must establish that exclusion or supply a different model.
The evaluator accepts declared assumptions, not evidence that they hold.

The trace binds policy identity, attempt identity, exact query and response SHA-256
digests, and the three samples. Each sample carries clock-profile and epoch identities.
Reconstruct exact types before asynchronous validation; refuse subclasses, malformed
records, policy substitution, mixed profiles/epochs, regressing counters, excessive
elapsed time and byte substitutions. No field can assert kernel authority.

## Integer interval calculation

Use B = 10^9 and integer rate error p in parts per billion, rho = p/B. For a
nonnegative measured difference d nanoseconds, the physical elapsed interval is bounded by

```text
D_min(d) = max(0, d - 2e) * B / (B + p)
D_max(d) =        (d + 2e) * B / (B - p)
```

The factor 2e covers the two sample errors. For authenticated issuance interval [L,U]
in integer microseconds, project outward without floating point:

```text
receipt = [L, U + ceil(D_max(r-s) / 1000)]
use     = [L + floor(D_min(c-r) / 1000),
           U + ceil(D_max(c-s) / 1000)]
```

Proof: issuance precedes receipt, so c-i >= c-r; issuance follows first challenge
disclosure, so c-i <= c-s. Combine those inequalities with the elapsed bounds and
the source's complete issuance interval. Network symmetry is unnecessary. In particular,
neither half the round-trip delay nor a midpoint estimate bounds adversarial delay.

The acquisition ceiling applies to ceil(D_max(r-s)) and the total ceiling to
ceil(D_max(c-s)), both in nanoseconds. Width is measured after outward microsecond
projection. Require window_start <= lower(use) <= upper(use) < window_end. A point
estimate inside a window cannot override an endpoint outside it. Integer-second output
also rounds outward. The proposed acquisition limit remains at most 30 seconds and
the total at most 60 seconds; these are evaluator ceilings, not a measured host guarantee.

## Retention and refusals

Retain the native validator's entire dossier, canonical policy and trace bytes, the
evaluation window and both projected intervals. The observation identity binds all of
them. Results explicitly remain conditional offline observations: no clock, fresh
challenge, current revocation, provider, authority or legal qualification is established.
The native certificate/CRL checks still cover issuance, not the later use interval.
Current revocation at use and full-roster evidence are separate prerequisites.

The declared c is a recorded instant, not the evaluator's return time. Asynchronous
validation can finish later. A live consumer must bind its actual consequential point
(including any wait before commit) or prove a deadline that bounds it. Replaying an old
trace must never refresh c. This evaluator performs neither clock sampling nor that
live enforcement; its result cannot authorize an append.

Known-bads cover complete-hull expiry, delay after receipt, drift and quantization,
asymmetric network timing, altered query/response and native signatures, clock reset and
epoch/profile substitution, constructor bypass, oversized/noncanonical records, mutable
caller state across awaits, foreign native contexts, and unsupported CRL roles. An exact
rational reference and a grid of physically constructed timelines check the inequalities
independently of the implementation formula. Tests with network and ambient-clock access
disabled prove replay independence. Existing native codecs, corpora and dependencies stay
unchanged.

Reproduce the focused proof with the existing locked environment:

```bash
.venv/bin/python -m pytest -q tests/test_native_time_elapsed_v1.py
```

The suite contains `129` tests, including `180` exact rational comparisons and `5832`
physically constructed timing cases. These are deterministic finite checks, not a formal
proof over every input or measured clock reliability. The first run's case-count assertion
incorrectly expected `17496`; the grid actually contains `5832` accepted timelines.
All interval containment assertions passed in that run. The count was corrected before
release validation, without changing the grid or the interval calculation.

## Acquisition dependency and research, inspected 2026-10-10

The public-material inspection remains historical. The current endpoint signer/CMS is
unobserved. Sectigo's disclosure v1.0.5 allows possible fees and refers to applicable
agreements; the public legal index does not resolve the terms for this particular
synthetic request. No agreement is accepted and no timestamp POST is sent in this tranche.
The next acquisition dossier still needs an exact scoped grant, applicable terms/cost,
request-before-send retention, a non-retryable request debit and bounded capture/parser
containment. A lost response is indeterminate; a restart is not permission to resend.
The earlier Google Cloud preparation grant remains usable within its existing scope.

Primary sources inspected (source text, not redistributed or newly byte-pinned):

- [RFC 3161, August 2001](https://www.rfc-editor.org/rfc/rfc3161.html), sections 2.2,
  2.4.1 and 4 items 4/6: nonce binding and delay/replay considerations.
- [Linux 6.18 timekeeping](https://docs.kernel.org/6.18/core-api/timekeeping.html):
  suspend and adjustment distinctions among monotonic, boottime and realtime clocks.
- [Python 3.11 time documentation](https://docs.python.org/3.11/library/time.html):
  integer clock APIs and platform-dependent clock semantics. The live documentation
  identifies itself as 3.11.17; Etzio's runtime remains pinned to 3.11.15/3.14.2.
- [RFC 9110, June 2022](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2):
  automatic retry restrictions for non-idempotent methods.
- [Sectigo TSA disclosure 1.0.5, 2026-02-11](https://www.sectigo.com/uploads/files/eIDAS/Sectigo_eIDAS_TSA_DS_v1.0.5.pdf):
  fees and applicable-document references; no free-use or contractual conclusion follows.

The interval derivation is Etzio's conditional design, not a quoted standard or a
state-of-the-art performance claim. Real clock custody, causality and fresh native
evidence remain external qualification obligations.
