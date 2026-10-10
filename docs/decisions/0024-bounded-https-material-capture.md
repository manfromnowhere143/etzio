# ADR-0024: Bounded single-attempt HTTPS material capture

Status: implemented experiment, subject to release validation. External use remains
proposed until the exact acquisition plan and finite environment are accepted.

## Boundary

ADR-0023's journal is now composed with a separate, opt-in capture tool. This is ordinary
provider material discovery, not service security testing, provider admission or an
engine network capability. The fixture CLI and kernel do not call it. A captured HTTP
reply is opaque evidence, even when a subsequent parser extracts a timestamp body.

The operator must separately authorize the exact plan before external execution. The
plan digest acknowledgement prevents accidental substitution; it is not a signature,
grant registry, identity proof or permission inferred from possession of a digest. No
external plan is accepted by this ADR. Loopback TLS fixtures are the qualification
surface. Existing cloud preparation authority is unchanged.

## Exact plan and dispatch

A closed canonical plan binds one HTTPS origin/path, one numeric IPv4 address, service,
exact request digest/size, terms and environment-assumption references, a TLS CA bundle,
runtime identity, response ceiling and total acquisition timeout. External destinations
must be public unicast IPv4 on port 443; fixture destinations must be 127.0.0.1. The
closed path grammar deliberately excludes query, fragment, userinfo and escaped paths.
There is no DNS lookup, address fallback, proxy, cookie jar, authentication negotiation,
redirect, HTTP retry or implicit certificate/revocation fetch.

Before debit, the controller reconstructs the journal, compares every shared field,
checks the acknowledged plan digest, checks the executing Python/worker identity and
validates the exact supplied CA bundle. The journal's scope reference is the plan's raw
SHA-256 identity. The plan and referenced dossier must be retained separately; a hash
alone is not custody of their bytes. An acknowledged debit is required before starting
the collector. Preflight failures leave the attempt prepared. Every post-debit failure
leaves it spent. A second invocation never reaches the network.

The collector is a fresh isolated-mode Python process with an empty working directory,
an explicit minimal environment, closed inherited descriptors, no database path or file
inputs, and a new process group. Its stdin contains only the prepared HTTP request,
numeric destination, TLS hostname, CA bundle and bounds. TLS verifies the hostname and
chain under only that supplied bundle, requires TLS 1.2 or later and advertises HTTP/1.1.
It performs one connect and one send, then collects decrypted HTTP bytes until TLS EOF.
Truncated TLS without close-notify refuses. The CA bundle authenticates transport, not
the timestamp signer or the truth of the server's clock.

The parent concurrently pumps bounded stdin/stdout/stderr through nonblocking pipes.
Its monotonic watchdog includes process startup, connect, TLS, send and receive; a
trickling peer cannot reset it. Output is at most the plan ceiling (at most 64 KiB,
**including HTTP framing**), plus one private framing byte. Stderr is separately bounded.
The parent kills an unfinished process group and reaps its child on timeout, overflow
or interruption. It drains pipes before reaping a natural exit, and never signals a
numeric group after releasing the child's PID. The trusted collector spawns no children.
The child also applies CPU, core and file-size limits, and a
Linux address-space ceiling. These controls assume a responsive trusted OS. They are
not hard-real-time guarantees; cleanup and local journal commits are outside the
acquisition timer and may fail with their own errors.

Successful capture retains the exact HTTP bytes in ADR-0023 before HTTP interpretation.
Timeout, excessive output, transport failure and operator interruption retain the existing
indeterminate reasons. A process dying before retention leaves `attempt_indeterminate`.
Storage exceptions propagate as storage failures and never become transport refusals.
Partial output is not promoted to a complete response. There is no resend path.

## Offline interpretation

A separate bounded decoder extracts a body only from a complete HTTP/1.0 or HTTP/1.1
200 reply with the exact timestamp media type. It rejects excessive or malformed
headers, folding, duplicate fields, ambiguous Content-Length/Transfer-Encoding,
unsupported content coding, malformed/truncated/extra framing and empty bodies.
Content-length, close-delimited and a finite chunked subset are supported; chunk
extensions and nonempty trailers are refused. It performs no ASN.1 or CMS parsing and
confers no timestamp validity, trusted UTC or kernel authority.

## Finite assumptions and remaining gates

This is a bounded trusted-client experiment, not the MARCELLUS/CATO hard-isolation
profile. The OS account still has its ordinary filesystem and network privileges;
there is no syscall sandbox, network namespace or independently administered watchdog.
The child is trusted repository code, not a worker executing received code. Runtime
identity pins Python version/executable, OpenSSL version and controller/worker source; it does not
close every dynamic library, standard-library file, firmware or host dependency.
Application byte limits do not bound every TLS/kernel allocation or physical storage.
The watchdog clock is an operational timeout source, not a qualified UTC/error bound.

ADR-0023's unchanged-database/SQLite assumptions still apply. Same-user replacement,
copied journals, coherent rollback, power faults and global grant reuse remain
unqualified. A finite external experiment must explicitly accept these assumptions and
retain the operator's scoped authority; this tool cannot approve itself. Production
provider, clock, latest-head, storage and exploit-isolation qualifications remain open.

## Required counterexamples and sources

Controls include unacknowledged or substituted plans, runtime/CA/request substitutions,
private external addresses, bad TLS hostname/root, absent DNS/proxy/credential effects,
redirect/auth responses without resend, exact byte ceilings, trickle and stalled-child
timeouts, output floods, cancellation, spent attempts, lost commit acknowledgement and
capture-store failures. Real repository-owned loopback TLS exchanges complement pure
protocol fixtures. The preserved wire must survive decoder refusal and cold replay.

Primary sources reviewed 2026-10-10:

- [RFC 9110 section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2),
  June 2022, distinguishes retry authority from a failed observation.
- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), June 2022, specifies HTTP/1.1
  framing and incomplete messages; Etzio accepts a documented narrower subset.
- [Python 3.11 subprocess documentation](https://docs.python.org/3.11/library/subprocess.html)
  explains pipe deadlocks and cleanup after timeout. The bounded streaming supervisor
  avoids unbounded `communicate()` output buffering.
- [Python SSL documentation](https://docs.python.org/3.11/library/ssl.html) distinguishes
  explicit trust configuration, hostname validation and ragged EOF handling.

These sources inform the design; they do not certify its implementation or environment.
