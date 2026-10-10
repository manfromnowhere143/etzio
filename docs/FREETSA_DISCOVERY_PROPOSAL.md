# Proposed FreeTSA material-discovery capture

Status: prepared experiment, 2026-10-10; **not executed or accepted**. No native provider,
trusted clock, storage profile, execution environment or bounty target is admitted.

## Decision and useful outcome

Use one ordinary timestamp request to observe the service's current response format,
signer and request binding. The existing strict native profiles remain unchanged. This
discovery cannot establish independent clock accuracy, current revocation, independent
administration or kernel authority. A later native qualification request requires its
own profile and budget; this response cannot silently become that experiment.

[FreeTSA's homepage](https://freetsa.org/index_en.php) publishes a free RFC 3161 service
and the HTTPS endpoint below. Its [CPS](https://www.freetsa.org/freetsa_cps.html) describes
certificate-status availability on a best-effort basis. Neither source establishes an
independently measured accuracy guarantee or an enterprise service commitment. The
proposal uses the documented public interface with synthetic input, no account,
credentials, paid service, subscription, donation or acceptance of an additional agreement.
It performs no security or performance test of FreeTSA.

The previous passive certificate/CRL observations and pinned local OpenSSL comparisons
are retained in [PR #36](https://github.com/manfromnowhere143/etzio/pull/36). They identify
a published P-384 signer but do not show the endpoint's current key use. That evidence
is sufficient to design discovery; it is not a reason to weaken a native codec.

## Proposed scope

| Item | Exact boundary |
|---|---|
| Operation | One HTTPS POST to `https://freetsa.org/tsr` |
| Address | `192.119.76.43:443`, observed by passive DNS on 2026-10-10; no runtime DNS or fallback |
| Input | SHA-256 imprint of an Etzio-owned synthetic statement; retained 256-bit nonce; `certReq=true`; no requested policy |
| HTTP behavior | TLS-verified HTTP/1.1; no proxies, cookies, credentials, redirects, authentication negotiation or retries |
| Budget | One durable local debit; at most 30 seconds of acquisition and 64 KiB of complete raw HTTP response, including framing |
| Cost | Publisher describes the service as free; no paid account or cloud resource is used |
| Failure | Spent attempt remains spent; missing or partial response remains indeterminate |
| Output | Private retained HTTP bytes, then separate networkless HTTP extraction and native inspection |
| Authority | Operator acceptance of this exact plan and finite assumptions is still required before dispatch |

The [prepared evidence record](evidence/freetsa-discovery-proposal-2026-10-10.json) retains
the complete machine plan, exact 93-byte synthetic request and execution command. Plan:
`sha256:677d6402efee17bdd53e7596055bcd18060a2167269efa3ce57d1672554ee03d`.
The raw CA bundle and source-page captures remain in the private local
preparation directory with digest/size manifests. Transport CA trust is distinct from
the timestamping CA and does not admit FreeTSA as a source of Etzio time.

## Accepted-environment proposal

The finite experiment proposes the current owned macOS host, pinned Python executable,
controller/collector source and OpenSSL version, and the exact retained certifi CA bundle.
The host's ordinary wall clock is assumed usable for TLS certificate validity; it is not
qualified UTC. The collector runs as trusted repository code in a fresh process with
bounded pipes and a parent watchdog. It receives no database path, credentials or other
user input, and executes no received code. On macOS, no address-space resource limit is
claimed. CPU/core/file-size controls and a clean process environment are not a syscall,
filesystem or network sandbox. The ordinary OS account privileges remain available to
that trusted code and its Python/TLS dependencies.

Local custody assumes one protected-by-convention private directory, one unchanged
database, SQLite's documented atomicity, sufficient disk space and a responsive trusted
OS. No actor may copy, replace, roll back or reset the experiment journal. Same-user
attacks, physical power faults, device durability and global grant reuse are unqualified.
Acquisition timeout excludes final local retention and process cleanup; failures there
remain explicit. Nothing from this finite acceptance would qualify production storage
or the MARCELLUS/CATO execution environment.

## Execution and recovery

Only after the exact scope and assumptions are accepted, invoke the prepared command
with the recorded plan identity. The capture CLI requires `--capture`, the existing
prepared journal, exact plan and CA files, and `--acknowledged-plan-id`. The digest is a
substitution guard, not proof of permission. A failed command must be inspected before
any next action; there is no resend or automatic replacement journal.

Use `scripts/capture_timestamp_once.py --inspect --journal PATH` without network inputs
for cold status. `--body-output NEW_PATH` additionally exports a successfully framed
HTTP timestamp body to a new private file. An HTTP decoder refusal does not discard or
rewrite captured bytes. A timeout, store failure or lost acknowledgement is not evidence
that the server did nothing.

Next after capture: inspect the retained ASN.1/CMS under a separately bounded offline
diagnostic, compare named signatures and request binding with the pinned OpenSSL tool,
and record every incompatible field. Provider admission remains dependent on complete
trust, revocation, clock/causality, administration and lifecycle evidence.

## Source record

Passive HTTPS GETs on 2026-10-10 returned HTTP 200:

- Homepage: 32,360 bytes, SHA-256
  `a186263c5d4d485fda38bfcef3296357215be295ba1cf4fef39d8de15299e7bd`.
- CPS: 3,201 bytes, SHA-256
  `69ca0a04dabc1e42062dd6e944a411a215407ed479320384dc0980b10b6c393b`.

Exact captures are retained locally. These are observed webpage identities, not signed
terms, independent provider evidence or authority to execute the proposal.
