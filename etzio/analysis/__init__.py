"""Real static-analysis engines. SCIPIO maps a repo's attack surface; VELITES's first
finder capability detects genuine vulnerability classes in Python source via the `ast`
module — deterministic, dependency-free, and honest about its boundary: a static hit is an
*execution-pending candidate*, never a confirmed finding. Confirmation requires a reproduced
PoC (CATO, Linux isolation)."""

from .python_sast import (
    AttackSurface,
    StaticFinding,
    find_findings,
    scan_surface,
)

__all__ = ["AttackSurface", "StaticFinding", "find_findings", "scan_surface"]
