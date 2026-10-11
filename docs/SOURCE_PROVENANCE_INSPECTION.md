# Offline source provenance inspection

Status: implementation contract, 2026-10-11. This is a documentary inspection tool outside
the kernel and target-admission path. It does not run, compile or import inspected code.

## Problem and decision

The CoW dossier exposed distinct source references in a program brief, audit reports and
publisher deployment records. An address match or an audit title cannot establish source
equivalence. Add one bounded, networkless inspector that compares exact source bytes from
retained file bundles and literal-source Hardhat deployment metadata. This is preparation
under the existing mission order, not a finder, an EVM execution pack or a new authority.

## Input contract

`scripts/inspect_source_provenance.py` accepts one UTF-8 JSON manifest with exactly:
`schema`, `scope`, `left`, `right`. Schema is `etzio.source-provenance-inspection.v1`.
Scope is a nonempty list of at most 128 distinct, exact relative ASCII source paths.
Absolute paths, empty/dot/parent segments, backslashes and ambiguous spellings are refused;
paths are identifiers, never filesystem instructions. No case folding or normalization
is performed.

Each side has a bounded ASCII `label` and one of two forms:

- `kind: source_bundle`, with `sources`: a list of unique source records. Each record has
  `path`, `size_bytes`, lowercase `sha256`, and canonical `bytes_base64`.
- `kind: hardhat_deployment`, with `document`: a record containing `size_bytes`, `sha256`
  and `bytes_base64`. The decoded JSON must contain a string `metadata`, itself JSON with
  a `sources` object. A source entry with string `content` supplies its exact UTF-8 bytes.
  A source entry without literal content remains unavailable, even if it contains URLs.

The manifest is at most 4 MiB; a bound artifact is at most 2 MiB; one source is at most
256 KiB; each side contains at most 128 sources. JSON nesting is capped at 32, decoded
nodes at 100,000. Duplicate JSON keys, invalid Unicode, floats, non-finite numbers,
malformed shapes, wrong sizes/hashes and noncanonical base64 refuse the inspection.
Zero-byte source content is valid evidence and remains distinct from missing content.

Ordinary protocol canonicalization must not be applied to opaque source text: NFC and
line-ending changes can alter program bytes. Decode JSON strings without normalization,
then encode literal source content as UTF-8 exactly. Preserve comments and whitespace.

## Output and limits

Every requested path receives left/right availability, byte length, SHA-256 and one of
`equal`, `different`, `unknown`. Equality additionally compares the bytes directly.
Missing source entries and entries lacking literal content are distinct availability states.
Unknown rows never count as equal. The report retains the manifest digest, input identities,
scope, labels, counts and explicit false flags for kernel authority, reproduced bytecode,
verified chain state and established audit coverage. Scope omissions are visible; agreement
over a subset is never described as complete build closure.

CLI exit 0 means a valid documentary comparison was produced, including differences or
unknowns. Exit 2 means malformed or inconsistent input. Neither exit code is a target grant.
Reports are deterministic and have no ambient timestamp. The CLI reads only its explicitly
named manifest and writes JSON to stdout. It does not fetch content-addressed URLs.

Matching embedded text establishes agreement between retained publisher records. It does
not authenticate the publisher, validate Git ancestry or audit coverage, verify metadata's
declared Keccak hash, compile a contract, bind runtime bytecode/immutables, query a chain,
prove non-equivocation or resolve legal/program eligibility. Those remain separate gates.

## Required controls

Owned synthetic records must distinguish a changed source, CRLF/LF, Unicode canonical
equivalents, empty/missing content, URL-only content, changed scope and changed input
identity. Refuse modified bytes under an old hash, duplicate/aliased paths and JSON keys,
malformed UTF-8/base64/types, excessive sizes/nesting/counts and empty scope. Disable network,
subprocess and ambient time during replay. CLI and replay must agree, including an honest
`different` or `unknown` result. No control executes third-party source.
