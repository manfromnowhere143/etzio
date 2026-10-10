# Archived timestamp replay and clock preflight

Status: research diagnostic contract, 2026-10-10. No provider or host is admitted.

## Purpose and scope

Replace the preceding syntax-only archive lead with a reproducible authenticated
historical sample. The selected Microsoft response comes from Stanford's public
timestamp archive, not an Etzio request. Retain the original archive, selected response,
root, both embedded certificates and both CRLs. Compare the root with the publisher's
HTTPS certificate bytes. Archive labels and Git metadata are discovery provenance;
neither chooses a production trust root nor proves when Etzio received the token.

The diagnostic accepts a closed, size/digest-bound manifest with exactly six positional
DER artifacts: root, issuer, TSA, root-issued CRL, issuer-issued CRL and response. It
requires canonical DER, the exact pinned two-certificate CMS roster, one signer,
RSA-4096/SHA-256 CMS, SHA-256 imprint, and the selected signed-attribute roster. It
checks the CMS signer identifier and signing-certificate binding, recomputes the content
digest, and verifies the signature and a path under the explicitly supplied root using
the locked validation dependencies. No ambient roots or network retrieval are allowed.

Both signed accuracy endpoints receive fresh validation contexts, zero tolerance and
required retained revocation evidence. Each named certificate/CRL signature is checked;
the complete issuance interval must be within every certificate and half-open CRL
interval. The report distinguishes this historical interval check from current
revocation. It reports additional signed attributes without interpreting their policies
or asserting legal qualification. The expected imprint is an archive comparison input,
not a retained original request. A token nonce does not prove challenge freshness.

The selected `signer-attributes` value (RFC 5126 section 5.11.3) is parsed locally as
one explicitly tagged certified AttributeCertificateV2. Its typed tree and DER round
trip are checked without changing the ASN.1 library's global OID registry. The CMS
signature covers these bytes, but the enclosed attribute certificate's issuer, signature
and role assertions are not admitted or validated. Claimed or multiple attribute values
are outside this finite diagnostic. The existing native parser must continue to refuse
the sample; the research inspector's additional type is not a runtime profile expansion.

Malformed, oversized, substituted, duplicate-role, unknown-field, noncanonical,
wrong-imprint, wrong-signer, changed-signature, missing-CRL and expired-interval controls
must refuse. Recomputing a manifest digest cannot conceal a signature mutation. Native
codec, kernel, authority and lifecycle bytes remain unchanged. The diagnostic returns
no sealed evidence accepted by the kernel.

The archive's other entries remain discovery material. A failed forced-DER round trip
is recorded as a parser-profile mismatch, not a provider vulnerability. Do not rewrite
a signed response into a preferred encoding and treat that as acquired native bytes.

## Containment and comparison

The CLI reads at most 128 KiB of manifest. Certificates and CRLs are each at most
16 KiB, the response at most 64 KiB. Existing closed ASN.1 traversal limits apply.
The retained archive is at most 100 KiB and is not a runtime input. Offline replay uses
only the hash-locked environment. This bounded diagnostic is not exploit isolation.

A separately pinned local OpenSSL 3.6.3 timestamp verification compares the same
response, imprint, root, issuer and retained CRLs at the historical endpoints. Each
subprocess has a deadline, empty ambient configuration and explicit trust inputs.
Expected positive/refusal outcomes must be checked, not inferred from tool completion.
The executable identity and shared cryptographic ancestry are retained; this is a local
implementation comparison, not independent administration.

The `ts` command has no `-no-CApath` or `-no-CAstore` switches in this pinned
version. It receives an explicit CA file, an empty CA directory and no CA store.
The [pinned `create_cert_store` implementation](https://github.com/openssl/openssl/blob/openssl-3.6.3/apps/ts.c)
creates a fresh store and loads only the supplied locations, without default paths.
The initial probe using unsupported switches was a setup failure, not a negative control.
The retained comparison requires exit status, exact success/failure output, error-code
sequence and terminal refusal reason. A crash or unknown option cannot count as refusal.
OpenSSL's integer-second checks round the issuance endpoints outward; Python checks
the exact microsecond endpoints. These precision differences remain explicit.

## Authorized benign clock preflight

Daniel reaffirmed use of the existing Google Cloud account and project on 2026-10-10.
Use one disposable C3 VM on the exact previously inspected Ubuntu image, with no public
IP, no service account, no ingress rules, a dedicated deny-egress VPC, automatic disk
deletion and an absolute maximum 15-minute deletion deadline. Do not change unrelated
resources, IAM, synchronization configuration or host clocks. Metadata is a platform
exception to VPC filtering; the VM has no service-account credential to obtain.

Read OS/kernel/clocksource identities, load the standard `ptp_kvm` module if available,
and sample available POSIX clocks and PTP devices. Retain bracketed readings and a short
ordinary scheduling wait. A missing device or unsupported read is an observation, not
a successful qualification. Do not run guest payloads, third-party scripts or build
systems. Obtain results through the serial console and verify exact resource absence
after cleanup. The public compute estimate is about USD 0.050402 for 15 minutes before
disk/tax/account pricing; actual billed cost is a separate, unmeasured result.

These finite samples establish device availability and observed reading behavior only.
They do not bound drift, reading error, suspend/migration disruption, UTC accuracy or
adversarial behavior. C3 is a clock-preflight choice, not a replacement for the separate
Linux/KVM execution profile. No second VM or longer run is implied by a failed probe.

Serial capture can interleave ordinary boot messages with the collector record. The
offline extractor accepts at most 256 KiB, exactly one ordered begin/end frame and
exactly one JSON candidate of at most 128 KiB inside it. It refuses duplicate JSON
keys, nonfinite numbers, changed collector correspondence and an incomplete sample
roster. Finite resolution floats are observation data, not Etzio protocol JSON. It
does not authenticate the guest or elevate the record into clock evidence. Preserve
the exact frame, original full-console digest and initial extraction failure.

## Retained observations

The [source ledger](evidence/archived-timestamp-sources-2026-10-10.json) identifies the
82,957-byte original public archive and the selected Microsoft response. The
[closed manifest](evidence/archived-microsoft-timestamp-2026-10-10.json) supplies six
exact DER artifacts. The response claims issuance at 2026-10-09 12:03:20.797 UTC
with 500 ms accuracy. Its historical signature/path/retained-CRL check passes over
the claimed interval; the [comparison](evidence/archived-timestamp-comparison-2026-10-10.json)
records two positive endpoints and seven expected refusals. None of these timestamps
is an Etzio receipt-time measurement.

The [C3 observation](evidence/clock-preflight-2026-10-10.json) retains the exact serial
frame, collector digest, instance configuration, 200 samples per clock, summary
calculations and five successful cleanup readbacks. `/dev/ptp0` reports `KVM virtual PTP`
and is readable alongside five POSIX clocks. No negative bracket or sample-value
regression occurred. PTP read brackets ranged from 2030 to 5432 ns; the ordinary
two-second scheduling wait advanced that device by 2000103322 ns. These are observed
values, not guaranteed bounds. The boot identifier remained unchanged.

The initial controller joined the whole noisy frame as JSON and failed. Cleanup ran
in its `finally` path and all five resource types were confirmed absent. The exact
single record was then recovered offline from the retained frame; no second VM ran.
The controller's exit remains `1`. Actual billed cost is unmeasured. Public ephemeral
SSH host keys in the frame belong to the deleted probe and contain no private key.

Replay locally with the locked environment:

```bash
.venv/bin/python scripts/inspect_archived_timestamp.py \
  docs/evidence/archived-microsoft-timestamp-2026-10-10.json
.venv/bin/python -m pytest -q \
  tests/test_archived_timestamp.py tests/test_clock_preflight_capture.py
```

The 68 focused tests pass on both supported runtimes. The initial provenance test
mistook archived DER CRLs for PEM and failed; the corrected DER correspondence test
passes without changing any archived bytes. The serial extractor also explicitly
permits finite observation floats after the protocol JSON decoder correctly refused
the collector's resolution values. Native protocol decoding remains unchanged.

## Research basis and next experiment

- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html), sections 2.4.2 and 3.4:
  timestamp content, accuracy and HTTP encoding.
- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html), sections 5.3–5.6:
  signed-attribute encoding, message digest and signature verification.
- [RFC 5126](https://www.rfc-editor.org/rfc/rfc5126.html), section 5.11.3:
  the selected signer-attributes wire structure; no CAdES conformance claim.
- [Stanford's archive documentation](https://timestamp.stanford.edu/) and
  [snapshot 79dba6f](https://github.com/bil/timestamp-record/blob/79dba6fe135ad8a6cf887d38a60e68c47e0c842c/.timestamps.json).
- [Microsoft PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm):
  publisher route for the explicitly compared root.
- [Google accurate-time configuration](https://docs.cloud.google.com/compute/docs/instances/time-synchronization/configure-time-sync),
  updated 2026-10-08: supported C3 family, PTP-KVM and separate host/guest error metrics.
- [Google migration behavior](https://docs.cloud.google.com/compute/docs/instances/live-migration-process),
  updated 2026-10-08: clock discontinuity during migration.
- [Google general-purpose pricing](https://cloud.google.com/products/compute/pricing/general-purpose):
  C3-standard-4 public us-central1 compute estimate, USD 0.201608 per hour.
- [Linux clock API](https://man7.org/linux/man-pages/man2/clock_gettime.2.html):
  dynamic PTP clock identifiers, BOOTTIME suspend semantics and reported resolution.

The next acquisition experiment still requires an exact service/terms decision,
request-before-send retention, a single non-retryable request debit, bounded capture,
qualified clock/causality evidence and a separate compatible native profile. An archived
token cannot substitute for these. The selected generic Microsoft service and the
earlier Sectigo qualified endpoint are different service choices. No timestamp POST or
agreement acceptance follows from this diagnostic or the cloud preflight.

For a later clock experiment, retain the host-to-UTC accuracy metric and the separate
guest-to-host error observation described by Google, with measurement age, acquisition
latency and their failure states. Establish a defensible holdover/rate-error bound and
test pauses, reboot, clock changes and expiry at the actual consequential point.
Neither a 1 ns reported resolution nor 200 quiet samples supplies those guarantees.
Cloud telemetry remains a provider assertion until its provenance and administration
are qualified. The next experiment needs these inputs, not simply a longer quiet run.
