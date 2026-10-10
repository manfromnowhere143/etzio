# FreeTSA transport-diagnostic acquisition proposal

Status: prepared offline, 2026-10-10; **not accepted, no journal created, no dispatch**.

The [first discovery attempt](FREETSA_DISCOVERY_PROPOSAL.md) is spent and retained only
`transport_error`. The updated collector can distinguish transport phases and bounded
failure categories. One separate request could either retain material for offline
inspection or identify a more useful local failure observation. It cannot guarantee a
response, establish remote delivery from a failure, or admit a provider.

## Exact decision

Accept one new finite acquisition, including the same explicit host/storage assumptions
documented in the first proposal. Create one new journal from the retained intent only
after that acceptance. Preserve the original spent journal untouched; neither journal
may be copied, rolled back, reset or replaced to obtain another attempt.

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
Private raw inputs and their digest/size manifest are in
`artifacts/acquisition-preparation/2026-10-10-freetsa-diagnostic/`. No journal is present.

The nonce was generated during preparation and is publicly retained. It supports request
matching, not an unpredictable challenge at dispatch or clock causality. Transport trust
and this finite trusted-client environment establish neither timestamp trust nor hard
isolation. Physical durability, hostile same-user behavior and cross-copy budget
enforcement remain unqualified. The acquisition timer excludes final retention and cleanup.

The service and terms sources are the same retained 2026-10-10 public observations in the
first proposal: the publisher describes a free ordinary timestamp interface. This request
is ordinary material discovery and performs no security or performance test. No new
service contact was made to prepare this proposal.

## After acceptance

Verify the exact released runtime, plan, assumptions, request, CA and source identities.
Create the new journal once with `AcquisitionJournal.create`, using retained `intent.json`
and `request.der`. Preserve the prior journal. Record the scoped decision and invoke the
prepared command once with an outer supervisor; retain stdout/stderr and operational timing
even when the result is indeterminate. Inspect the journal before any further action.
Digest possession is a substitution guard, not an authority grant.

If complete material is captured, inspect its framing and ASN.1/CMS offline without
weakening either native profile. If it fails, retain the observation and decide the next
experiment from that evidence. No automatic follow-up is included in this proposal.
