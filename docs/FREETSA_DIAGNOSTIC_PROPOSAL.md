# FreeTSA transport-diagnostic acquisition proposal

Status: accepted and attempted once, 2026-10-12; **spent, capture indeterminate**.

## Retained result

Daniel accepted the exact plan and finite assumptions below. One collector invocation
retained `capture_indeterminate` / `transport_error`. Its separately retained advisory
observation reports `response_read` / `tls_eof` after counting `6314` decrypted bytes.
No HTTP response bytes were retained. HTTP status, framing, timestamp content and provider
processing remain unobserved. Cold journal inspection reproduces the spent outcome, but
cannot reconstruct the advisory observation. The original October 10 journal is unchanged.
See the [result and owned counterexample](evidence/freetsa-diagnostic-result-2026-10-12.json).

On both supported runtimes, an owned loopback experiment produced that same category and
count for two different messages: one complete and one whose declared body was one byte
longer than the delivered body. Both were refused after abrupt TLS closure. The complete
message with clean TLS closure was retained. Cold state agreed and a second dispatch was
refused in all three cases. These controls do not reconstruct the external response.

[RFC 9112 section 9.8](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.8)
distinguishes explicit HTTP message completion from connection closure. Content-Length or
complete chunk framing can establish completion after an incomplete TLS close; a
close-delimited response needs a valid closure alert. Etzio's accepted profile deliberately
requires clean TLS closure for every response. It met that contract. This is a compatibility
limit, not an established service vulnerability or an implementation defect.

Do not repeat the unchanged acquisition, reset either journal, suppress TLS EOF errors,
or relabel the historical result. A separately versioned framing-aware profile is a possible
later experiment, subject to an explicit contract, bounded parsing, truncation and ambiguity
controls, and a newly accepted acquisition plan. It is neither implemented nor dispatched.
Accountable catalog/monitor commitments and the complete operating dossier remain the
native-integration dependency; this observation admits no provider or bounty target.

The [first discovery attempt](FREETSA_DISCOVERY_PROPOSAL.md) is spent and retained only
`transport_error`. The updated collector can distinguish transport phases and bounded
failure categories. One separate request could either retain material for offline
inspection or identify a more useful local failure observation. It cannot guarantee a
response, establish remote delivery from a failure, or admit a provider.

## Accepted scope, now consumed

The acceptance covered one new finite acquisition, including the explicit host/storage
assumptions documented in the first proposal. One new journal was created from the retained
intent after acceptance. Preserve both spent journals; neither may be copied, rolled back,
reset or replaced to obtain another attempt.

| Item | Boundary |
|---|---|
| Destination | One HTTPS POST to `https://freetsa.org/tsr`, fixed `192.119.76.43:443`, SNI `freetsa.org` |
| Input | Retained 93-byte RFC 3161 request for a public synthetic statement; no target or user data |
| Transport | Exact retained CA bundle; certificate and hostname verification; authenticated TLS closure |
| Budget | One durable debit, 30-second acquisition ceiling, 64 KiB raw response including HTTP framing |
| Exclusions | No runtime DNS, proxy, credential, redirect, retry, paid service or cloud resource |
| Failure | Remains spent; partial or missing response remains indeterminate |
| Diagnostic | Retain CLI stdout separately; advisory phase/category/count only, unavailable on cold inspection |

Plan identity:
`sha256:2f88665e266eef130e510324594ea3bf839449a1b41b7a2a9fd5eb539eb5d713`.
The [machine-readable proposal](evidence/freetsa-diagnostic-proposal-2026-10-10.json)
retains exact plan, request, intent, runtime binding, finite assumptions and command.
Private raw inputs, their digest/size manifest and the spent journal are in
`artifacts/acquisition-preparation/2026-10-10-freetsa-diagnostic/`. The preparation manifest
and machine-readable proposal preserve their historical pre-acceptance state. Current
acceptance, invocation and outcome evidence is in
`artifacts/checkpoints/2026-10-12-freetsa-diagnostic/`.

The nonce was generated during preparation and is publicly retained. It supports request
matching, not an unpredictable challenge at dispatch or clock causality. Transport trust
and this finite trusted-client environment establish neither timestamp trust nor hard
isolation. Physical durability, hostile same-user behavior and cross-copy budget
enforcement remain unqualified. The acquisition timer excludes final retention and cleanup.

The service and terms sources matched the retained October 10 bytes in two documentary
GETs on October 12 before acceptance. The publisher describes a free ordinary timestamp
interface. The request was ordinary material discovery, with no security or performance test.

## Historical execution instructions

The following sequence has been completed once. It is retained for review, not reuse.

Verify the exact released runtime, plan, assumptions, request, CA and source identities.
Create the new journal once with `AcquisitionJournal.create`, using retained `intent.json`
and `request.der`. Preserve the prior journal. Record the scoped decision and invoke the
prepared command once with an outer supervisor; retain stdout/stderr and operational timing
even when the result is indeterminate. Inspect the journal before any further action.
Digest possession is a substitution guard, not an authority grant.

If complete material is captured, inspect its framing and ASN.1/CMS offline without
weakening either native profile. If it fails, retain the observation and decide the next
experiment from that evidence. No automatic follow-up is included in this proposal.
