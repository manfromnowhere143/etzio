# Provider and host qualification next steps

Status: research and preparation, 2026-10-10. No native provider, storage profile,
execution profile or bounty target is admitted by this record.

The next useful result is one reproducible native-provider observation carried through
retained lifecycle recovery, followed by an external latest-head recovery experiment.
More fixture gates alone cannot establish independent administration. Cloud access is
available for qualification work; hardware procurement is not the immediate dependency.

## Provider evidence and a corrected assumption

Follow-up, 2026-10-10: the operator accepted the exact FreeTSA discovery plan and its
finite assumptions. One acquisition ended `capture_indeterminate` / `transport_error`,
with no retained response; request delivery and underlying cause are unknown. The
[result](evidence/freetsa-discovery-result-2026-10-10.json) preserves the spent attempt.
ADR-0024 now adds bounded advisory phase/category observations without changing custody,
TLS closure or retry rules. A [separate diagnostic proposal](FREETSA_DIAGNOSTIC_PROPOSAL.md)
is prepared offline, with no new journal or dispatch; its one-request scope needs a new
decision. No provider, clock or execution profile is admitted.

Historical preparation, preceding that attempt:

Follow-up, 2026-10-10: [ADR-0024](decisions/0024-bounded-https-material-capture.md)
implements a bounded, opt-in HTTPS collector with exact plan/CA/runtime binding, a parent
watchdog, one durable debit and opaque HTTP retention before interpretation. Owned
loopback TLS controls exercise the transport. The [FreeTSA discovery proposal](FREETSA_DISCOVERY_PROPOSAL.md)
now identifies one free ordinary synthetic request and explicit finite environment
assumptions. It still requires exact scoped operator acceptance before external dispatch.
It is distinct from the unresolved qualified Sectigo service choice below and admits
neither service as an Etzio provider. No timestamp POST has been sent.

Follow-up, 2026-10-10: [ADR-0023](decisions/0023-offline-acquisition-custody.md)
implements the offline custody prerequisite: exact request retention, one committed
attempt, immutable opaque or indeterminate capture, cold reconstruction and controls for
concurrent callers and interrupted commits. Its scope/terms references are documentary;
a debit grants no network permission. There is no transport or native-provider connection.
The next acquisition tranche must resolve the exact service/terms, pin a scoped grant and
accept a finite capture environment with explicit storage assumptions. Cross-copy budget
enforcement and production storage qualification remain separate dependencies.

Follow-up, 2026-10-10: [archived timestamp replay and clock preflight](ARCHIVED_TIMESTAMP_REPLAY.md)
now authenticates one real historical Microsoft timestamp under its supplied root,
including the retained CRLs across the whole claimed accuracy interval. A pinned
OpenSSL comparison agrees at two outward-rounded endpoints and refuses seven controls.
The original request is absent; the additional signed attribute is handled only by the
offline inspector. Native codecs still refuse this sample. Microsoft's generic service
is a distinct service choice from the proposed Sectigo qualified endpoint.

A disposable C3 probe observed a readable KVM PTP device and 200 bracketed samples
from six clocks. The serial frame contained boot-log interleaving; the exact JSON line
was recovered after the initial parser failed. All five resource types are verified
absent. Device availability does not qualify clock error, drift, suspend/migration or
UTC. The next clock experiment needs retained host-to-UTC and guest-to-host error
observations, a defensible holdover bound and failures at the consequential instant.
No new hardware or cloud login is needed for preparation.

Follow-up, 2026-10-10: [ADR-0022](decisions/0022-native-time-consumption-bounds.md)
now implements the offline elapsed-time prerequisite for both native codecs. It binds an
exact query/response trace, accounts for declared clock rate and sample error, and checks
the full projected consumption interval. The actual host clock, fresh challenge and
consequential consumption point remain unqualified. Public terms research still does not
establish which agreement and fees apply to the proposed one-request experiment; no
timestamp POST has been sent.

Follow-up, 2026-10-09: a [published-material replay](PUBLISHED_TSA_MATERIAL.md) now retains
signer #3 and the intermediate-issued CRL. All five named signatures verify and a pinned
OpenSSL timestamp-purpose path check passes at one stated diagnostic instant, with eight
refusal controls. The historical signer is not evidence of the endpoint's current key;
no timestamp request, trust enrollment or native profile acceptance follows.

The earlier provider comparison described a whole RSA-4096 hierarchy. The policy says
the service issues RSA-4096 timestamps; that does not specify every CA key. Read-only
inspection of the publisher's listed certificates found a 4096-bit root and a 3072-bit
intermediate. Both certificate signatures use SHA-384. The intermediate signature
verifies under the downloaded root, and both DER hashes match the publisher's HTTPS
listing. This establishes an artifact relationship, not independent root trust or the
chain currently returned by the timestamp endpoint.

The [retained observations](evidence/provider-preparation-2026-10-09.json) include exact
public certificate and root-issued CRL bytes. The existing ADR-0021 algorithm gate
refuses the intermediate. Its complete profile also differs from these certificates:
the root lacks AKI, both CAs permit digital signatures, and the intermediate contains a
timestamp EKU outside the profile's CA extension set. These are compatibility limits,
not vulnerabilities in Sectigo. Preserve the current codec and its released corpus;
design a separately versioned profile only after obtaining the complete intended chain.
[Publisher certificate repository](https://secure.sectigo.com/products/PubliclyDisclosedSubCACerts).

One explicit public CRL GET resolved the root-to-intermediate revocation route. The
retained CRL authenticates under the downloaded root and contains no revoked entries.
Its issuer-declared interval is retained without claiming current revocation. The endpoint
response and current signer remain unobserved; published historical signer material and
its issuer CRL are now available in the follow-up above. The root CRL also carries
noncritical OID `2.5.29.60`, outside the current codec's closed AKI/CRL-number extension
set; obtaining a signed CRL does not establish codec compatibility. The disclosure statement
also identifies CRLs as a validation route, correcting the earlier OCSP-only documentary
lead. [TSA disclosure v1.0.5](https://www.sectigo.com/uploads/files/eIDAS/Sectigo_eIDAS_TSA_DS_v1.0.5.pdf).

| Acquisition prerequisite | Evidence now | Remaining decision |
|---|---|---|
| Exact service | Qualified endpoint identified in TSPPS 1.1.4 | No timestamp request has been sent; generic endpoints are different services |
| Applicable use and price | Public disclosure, ET terms v1.1 and United Terms v1.1 inspected | Determine which agreement covers one synthetic timestamp and whether access or fees apply; do not infer that enterprise terms automatically govern the public endpoint |
| Trust and rotation | Two publisher-listed certificates, exact hashes and one signed CRL retained | Independent bootstrap authentication, current TSA, complete revocation and rotation policy |
| Wire compatibility | Published CA bytes falsify the all-4096 assumption | Separate profile after full evidence; retain strict nonce, imprint, policy and full-hull checks |
| Request fields | TSPPS and ETSI wording differs for reqPolicy/certReq | Observe exact behavior in a bounded admitted interoperability experiment |
| Containment and custody | ADR-0023 offline request/debit/capture journal and interruption controls | Accepted finite storage/parser/resource assumptions, exact acquisition grant and contained transport |

The [ET terms](https://www.sectigo.com/uploads/backgrounds/ET-Terms-of-Use-v1.1.pdf)
exclude performance/security testing from their evaluation-use provision. This
preparation does not test the service for vulnerabilities or assert that provision's
applicability. Keep ordinary timestamp acquisition distinct from service security testing.
Raw downloads of those legal PDFs returned HTTP 403 in this session; web text was
inspectable, but their exact byte identities have not been retained. Do not label those
sources byte-pinned.

Proposed acquisition: one POST to the exact qualified endpoint, zero automatic retries,
synthetic non-sensitive input only, no credentials, and no assumed paid service. Retain
the complete request, fresh nonce, profile, applicable authority and request debit before
send. Bound response to 64 KiB, total time to 30 seconds, and redirects to zero; require
the expected response type. Fetch no AIA/CRL implicitly. Lost responses remain
indeterminate. Parse retained bytes in the accepted environment, preserve refusal reasons,
and keep the result outside kernel authority until native lifecycle qualification passes.
These are proposed limits, not a sent request or an admitted grant.

If the provider publishes no current TSA certificate, avoid a circular bootstrap: a
separately authorized material-discovery capture may collect one bounded response as
untrusted bytes. It has no Etzio time authority and cannot satisfy the exact-profile
request contract. Inspect its chain under the independently selected trust procedure,
then pin the complete profile before a later qualification request. Each experiment
needs its own single-request budget; neither permits silent retries or promotion of the
discovery token. Also specify trusted elapsed-time and acquisition bounds before native
observations become decision time: issuance time plus accuracy does not describe an
arbitrarily later receipt or commit.

Spain's [official publication page](https://digital.sede.gob.es/pagina?id=Lista-de-confianza-de-prestadores-cualificados-de-servicios-electr%C3%B3nicos-de-confianza)
links the current trust-list location. The downloaded XML contains the same R35
intermediate fingerprint under the Sectigo timestamp-service entry; it does not supply
the missing current TSA leaf. Its XML signature and EU list-of-lists bootstrap have not
been locally validated. This is a second publication lead, not an admission or legal-status
conclusion. The obsolete ministry PDF URL redirects to a general services page and must
not be used as current evidence.

## Acceptance experiments

| Dependency | Smallest decisive experiment | Required adversarial control | Evidence that permits progression |
|---|---|---|---|
| Native providers | One pinned complete roster, exact native packages, cold reconstruction at every retained phase | Wrong source/nonce, expired or revoked credentials, missing source, conflicting floor, changed trust root | Same authenticated request and byte closure on replay; independent custody and shared dependencies documented |
| External latest head | Publish H0 then H1; remove disposable local DB/cache/staging; recover using separately held bootstrap identity | Restore a coherent H0 database; replay a valid old checkpoint; withhold or split witnesses | H1 recovered or explicit block; H0 never treated as current; governed recovery barrier preserved |
| Storage | Deterministic VFS error/crash schedule against exact SQLite/FS/device configuration | Short/torn/reordered writes, failed sync, ENOSPC, recovery-time errors, path replacement and stale backup | Exact allowed transaction state plus complete evidence mappings and external-head agreement; every fault and recovery retained |
| Isolation | Repository-owned benign probes on exact Linux/KVM host and image | Denied egress, metadata/credential access, writable-input substitution, resource exhaustion, stale lease, controller death | Mechanically enforced separation, bounded output, independent kill and teardown, no cross-worker state; measured profile explicitly accepted |
| EVM discovery | Frozen licensed tasks, static/model/hybrid baselines with equal information and budgets | Patched/clean/near-miss contracts, leaked-label and grader-tampering controls | Independent effect replay, all attempted task outcomes and costs retained; no superiority claim from a fixture pass |

These are proposed experiments. The gates retain their existing order; preparation of
later experiments is not their execution or acceptance.

### Provider mathematics and independence

For required intervals I_i = [l_i, u_i], require max(l_i) <= min(u_i), then retain
H = [min(l_i), max(u_i)]. Do not substitute the intersection for Etzio's conservative
hull. Require thisUpdate <= lower(H) <= upper(H) < nextUpdate and enforce the age ceiling
at upper(H). Every configured source remains required. A missing source is a block;
availability does not justify silently changing the roster or quorum.

A countersigned append-only log can establish consistency while presenting an old head.
Latest-head recovery needs fresh, scope-bound authority and independently retained
bootstrap state. Two processes, two keys or two cloud projects under the same
administrator do not establish independent administration. Record shared CA parents,
cloud credentials, clocks, infrastructure and recovery operators. The pinned
[witness design](https://github.com/transparency-dev/witness/blob/b4c9458d9b14e5789285c5b68a7535d152c98de9/README.md)
is a consistency building block; its optional first-use bootstrap does not satisfy
Etzio's local-loss gate by itself.

### Storage failure model

Follow SQLite's distinction between one-shot and persistent I/O faults and crashes that
reorder or damage unsynchronized writes. Inject faults during recovery as well as normal
commit. A killed process is not a power-cut experiment.
[SQLite testing](https://sqlite.org/testing.html).

Pin SQLite source ID, binary and VFS, compile options, journal/sync mode, filesystem and
mount options, kernel, device/cache semantics, capacity and backup tooling. Keep
DELETE/EXTRA until a separately qualified change. For a transaction interrupted before
acknowledgment, check the specifically permitted old/new state; after durable success,
require the new state under the accepted device assumptions. `integrity_check` alone
does not detect a coherent stale database or valid but wrong event/BLOB mappings.
[SQLite atomic-commit assumptions](https://sqlite.org/atomiccommit.html).

Prefer a dedicated vault service identity and protected mount as the first candidate for
closing the documented same-user pathname boundary. A worker must not own the database
directory or connect to its SQLite file. This still requires a specified service API,
concurrency/credential tests and external rollback protection; permissions alone do not
solve coherent offline rewrite. Physical pages, journals, temporary files, backups and
logs need separate hard quotas and finality reserve tests. Exercise restore with missing
keys, wrong keys, stale snapshots and externally newer heads. Pin evidence access,
encryption-key custody, retention and deletion policy before sensitive material.

### Isolation and hardware

Google Cloud inventory confirms access to a billing-enabled project. Existing E2 machines
are unsuitable for nested KVM. A stopped N2 engineering machine has unrelated disks and
workload labels, so the candidate is a dedicated disposable N2 host. Google supports
nested KVM on selected families; its current documentation also lists N4D as an AMD
exception. Family support is a prerequisite, not an isolation result.
[Nested virtualization](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview).

The benign preflight uses n2-standard-4, 16 GiB RAM, one visible thread per core, an exact
Ubuntu image, a dedicated network, no public IP, no service account and a VPC deny-egress rule.
An absolute termination time and auto-delete boot disk bound its lifetime. Read host
facts through the control-plane serial-output API; no project SSH key is installed.
The guest checks KVM API availability and creates/closes an empty VM descriptor; it
loads no guest payload. This does not instantiate MARCELLUS or CATO.

The [measured result](evidence/host-preflight-2026-10-09.json) reports Ubuntu 24.04.5,
Linux `7.0.0-1011-gcp`, Intel Cascade Lake, two guest-visible CPUs, KVM API `12` and
successful creation/closure of an empty VM descriptor. The guest reports KSM and SMT
inactive and exposes cgroup v2. Its MMIO-stale-data and TSX-async-abort diagnostics
report unresolved microcode and physical-host SMT state. Retain these as open profile
issues; they do not establish a vulnerability in Google Cloud. The collector and exact
guest JSON are retained with hashes; raw cloud identifiers remain local. No external
workload, jailer, seccomp, egress-denial probe, storage-fault test or power test ran.

The next execution profile must pin host/guest kernels, VMM/jailer build, seccomp policy,
microcode evidence, cgroup hierarchy, protected paths, read-only inputs and bounded
serial/log/artifact export. Test accounting of kernel-created work and controller failure,
not just guest processes. The pinned
[Firecracker host guidance](https://github.com/firecracker-microvm/firecracker/blob/fd9fc7a9f164b73002d22065d17c150d8c262d91/docs/prod-host-setup.md)
identifies host configuration and kernel-thread accounting as relevant boundaries.
Do not copy version-specific mitigation switches without testing their tradeoffs.

Nested-cloud observations cannot measure the physical host's firmware, power-fault
behavior or complete tenancy. Preserve these as provider assumptions or require a
different accepted host profile. Guest-reported SMT state does not prove physical-host
SMT policy. A successful KVM ioctl is not proof of confinement, independent verifier
administration or durable storage.

The published us-central1 n2-standard-4 compute rate is USD 0.194236/hour: 15 minutes is
USD 0.048559 before disk, taxes and account-specific pricing. This is an estimate, not a
billing receipt. Automatic termination can begin later than its requested deadline;
confirm deletion of the VM, boot disk and temporary network resources after collection.
[Compute pricing](https://cloud.google.com/products/compute/pricing/general-purpose),
[VM runtime limits](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime).

Cleanup completed: exact-name control-plane queries found no remaining VM, boot disk,
firewall, subnet or VPC for this experiment. The observation time is the controller's
clock, not qualified UTC; actual billing remains unmeasured.

### Measured EVM discovery

Freeze task revisions, licenses, vulnerability families, information regime, build closure,
models, prompts, tools and budgets before evaluation. Keep tuning targets separate from
final targets; repeated seeds on one target are not new independent targets. Evaluate
static analysis, model-only and hybrid search under matched limits, then ablate symbolic
execution, property fuzzing and semantic guidance to measure their incremental value.

Grade detection, exploit effect and patch correctness separately. Freeze a mechanical
oracle outside generator control; replay from a clean snapshot with an independent
verifier. Report permitted asset deltas/invariants, exploit failure on the patched
version, regression results, duplicates and reviewer minutes. Post-release incidents
and multiple scaffolds matter because contest performance need not transfer to new
incidents. [ReEVMBench v1, 2026-03-11](https://arxiv.org/abs/2603.10795v1).

Publish TP, FP, TN, FN and every blocked/invalid/unsupported/timeout result with task
coverage. Precision = TP/(TP+FP) and recall = TP/(TP+FN) are undefined at zero
denominators. Use target-level paired uncertainty estimates for comparisons. Even with
zero observed failures in n independent Bernoulli trials, the one-sided 95% upper
failure bound is 1 - 0.05^(1/n); shared targets and adaptive selection invalidate a naive
independence claim. Do not infer real-target reliability from synthetic refusals.

Bounty income is measured only from accepted, paid outcomes, net of compute and review
costs. Program maxima are not expected revenue. The immediate economic milestone is one
authorized, independently reproduced, nonduplicate finding; breadth and continuous
operation must earn expansion from that evidence.

## Next concrete work

Finish the current TSA and leaf-CRL material/terms dossier, then specify the separate
compatible native profile with known-bads. Use the retained preflight to define the next
host experiment, including the unresolved CPU mitigation evidence.
Keep native acquisition, lifecycle integration and local-loss recovery as separately
measured stages. No additional hardware information is required from the operator now.
Any future procurement request should name the exact missing capability, configuration,
bounded cost and experiment it enables.
