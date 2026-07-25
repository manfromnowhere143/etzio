"""Run SCIPIO (recon) + VELITES (static finders) over a REAL Python path.

    python -m etzio.scan                       # scans the planted vulnerable fixture
    python -m etzio.scan <path/to/repo>        # scans any authorized local path
    python -m etzio.scan --self                # scans Etzio's own source (false-positive control)

Output is honest: VELITES emits *execution-pending candidates*, not confirmed findings.
Confirmation requires MARCELLUS to build a PoC and CATO to reproduce it in isolation.
"""

from __future__ import annotations

import os
import sys

from .engines import Scipio, Velites
from .fixtures_code import FIXTURES_DIR


def _resolve_target(argv: list[str]) -> str:
    if "--self" in argv:
        return os.path.dirname(__file__)                       # the etzio/ package
    args = [a for a in argv if not a.startswith("-")]
    if args:
        return args[0]
    return os.path.join(FIXTURES_DIR, "vulnerable_app.py")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    target = _resolve_target(argv)
    if not os.path.exists(target):
        print(f"error: path not found: {target}")
        return 2

    scipio, velites = Scipio(), Velites()
    surface = scipio.map_repo(target)
    candidates = velites.scan_repo(target)

    print("=" * 78)
    print(f"ETZIO scan · target = {target}")
    print("=" * 78)
    s = surface.summary()
    print(f"SCIPIO surface : {s['files']} files, {s['entrypoints']} entrypoints, "
          f"{s['distinct_imports']} distinct imports, {s['parse_errors']} parse errors")
    print(f"VELITES        : {len(candidates)} execution-pending candidate(s)")
    print("-" * 78)
    if not candidates:
        print("no candidates — surface is clean under the current detectors")
    for c in candidates:
        print(f"  {c.id}  {c.note}")
    print("-" * 78)
    print("state: EXECUTION_PENDING — not confirmed. A candidate becomes a finding only when")
    print("       MARCELLUS builds a PoC and CATO reproduces it in isolation (Linux/KVM).")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
