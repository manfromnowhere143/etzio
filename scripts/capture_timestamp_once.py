#!/usr/bin/env python3
"""Opt-in ADR-0024 capture after scoped acceptance, or networkless custody inspection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from etzio.qualification.acquisition_custody_v1 import AcquisitionJournal  # noqa: E402
from etzio.qualification.https_capture_v1 import (  # noqa: E402
    MAX_CA,
    MAX_PLAN,
    CaptureError,
    capture_once,
    timestamp_body,
)


def bounded_file(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise CaptureError("input_file_size")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--capture", action="store_true")
    mode.add_argument("--inspect", action="store_true")
    parser.add_argument("--journal", required=True)
    parser.add_argument("--plan")
    parser.add_argument("--ca")
    parser.add_argument(
        "--acknowledged-plan-id", help="Exact separately accepted plan identity; not an authority grant",
    )
    parser.add_argument("--body-output", help="New private output path; inspection mode only")
    args = parser.parse_args(argv)
    journal = AcquisitionJournal(args.journal)
    if args.capture:
        if not args.plan or not args.ca or not args.acknowledged_plan_id or args.body_output:
            parser.error("capture requires --plan, --ca and --acknowledged-plan-id; body export uses --inspect")
        state = capture_once(
            journal, bounded_file(args.plan, MAX_PLAN), bounded_file(args.ca, MAX_CA),
            acknowledged_plan_id=args.acknowledged_plan_id,
        )
    else:
        if args.plan or args.ca or args.acknowledged_plan_id:
            parser.error("inspection accepts no transport inputs")
        state = journal.inspect()
    report = {"status": state.status, "intent_id": state.intent_id, "attempt_id": state.attempt_id}
    if state.status == "response_captured":
        try:
            body = timestamp_body(state.response_wire)
        except CaptureError as error:
            report["http_refusal"] = str(error)
            if args.body_output:
                raise
        else:
            report["opaque_timestamp_body"] = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            if args.body_output:
                descriptor = os.open(args.body_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
    elif args.body_output:
        raise CaptureError("no_complete_response")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
