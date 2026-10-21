# Fixture scan report v1

The supported `etzio` command analyzes only the two repository fixtures. Its JSON
report lets a local integration distinguish a completed candidate scan from missing
analysis. This is an unsigned presentation of the validated retained lifecycle. It
does not establish current external authority, native finality, independent
execution, target safety or a finding.

Invoke `etzio --fixture clean --format json` or
`etzio --fixture vulnerable --format json`. The default format remains `text`.
`--state-dir` retains the existing private local state; omission uses an ephemeral
directory. No arbitrary source path, remote target or network listener is added.

The report discriminator is `etzio.fixture_scan_report.v1`. JSON stdout contains
one complete object followed by a newline. Operational errors use stderr and do
not emit a result object. Argument errors retain argparse behavior. Callers must
check the process exit status as well as `status`; empty or truncated output is
not an empty successful scan.

| Exit | Meaning |
|---|---|
| `0` | The static fixture mission closed with status `completed` and no parse failures. Candidates may be present. This is not a security verdict. |
| `3` | A validated mission result exists, but analysis was refused, failed, cancelled, timed out, exhausted its budget or remained incomplete. |
| `2` | Invalid arguments or an operational failure prevented a report. |

Interruptions such as `KeyboardInterrupt` and `SystemExit` continue to propagate.
They are never converted to successful reports. A failed write to stdout can leave
partial output and must be treated as a failed delivery by the caller.

The CLI previously returned `0` for retained analyzer failure and for closure with
parse failures. That behavior is corrected in both text and JSON modes and with
both state retention choices. Existing successful clean and vulnerable fixture
commands keep their success exit status.

The report includes mission, authority, target and retained event head identities;
the observed kernel phase and distinct report status; a reason code when analysis
is incomplete; candidate identities, source digests and locations; explicit parse
failures; and the state retention choice. It omits source snippets, literal values,
private local paths, signing keys and raw provider packages. Candidate severity is
the analyzer's label, not independently established impact.

`completed` requires the existing static completion event, the `closed` phase and
zero parse failures. A closed mission containing a parse failure is `incomplete`.
Other incomplete phases remain visible in `phase`. Refusal, failure, cancellation,
timeout and budget exhaustion retain distinct statuses and their retained reason.
Every report states `claim_level: static_candidates` and
`verification_status: not_performed`. No report field is an authority grant.

The installed schema is `etzio/schemas/fixture_scan_report.v1.schema.json`.
Consumers should reject unsupported report versions and validate the whole object.
Schema validation establishes shape only. It does not authenticate the producer,
verify the database BLOBs, prove freshness or qualify a native provider.

This is a CLI output contract. The Python kernel functions remain internal service
APIs with their existing trust assumptions. A separately supported SDK, HTTP
service and MCP server are proposed interfaces, not implemented by this change.
