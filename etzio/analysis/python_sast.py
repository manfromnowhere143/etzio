"""Deterministic byte-in/static-observation-out Python analysis.

This module deliberately owns no filesystem walker. The governed mission kernel resolves
an admitted target snapshot from content-addressed evidence and supplies exact bytes here.
That keeps target access, authorization, and retention outside the detector. A detector
match is a candidate observation, never a confirmed vulnerability.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

PYTHON_SAST_VERSION = "python_ast.v1"


# --------------------------------------------------------------------------- data model
@dataclass(frozen=True)
class StaticFinding:
    rule_id: str
    severity: str          # low | medium | high | critical
    message: str
    file: str
    line: int
    column: int
    symbol: str            # the offending call/name
    snippet: str


@dataclass(frozen=True, slots=True)
class SourceParseFailureV1:
    """Stable, non-source-bearing account of a Python source admission failure."""

    relative_path: str
    reason_code: str
    line: int
    column: int

    def to_dict(self) -> dict[str, object]:
        return {
            "column": self.column,
            "line": self.line,
            "reason_code": self.reason_code,
            "relative_path": self.relative_path,
        }


@dataclass(frozen=True, slots=True)
class SourceAnalysisV1:
    """One byte-bound analyzer result.

    A parse failure and findings are mutually exclusive. Source snippets are intentionally
    excluded from this protocol-facing result because they can contain credentials or other
    sensitive literals.
    """

    relative_path: str
    findings: tuple[StaticFinding, ...]
    parse_failure: SourceParseFailureV1 | None

    def __post_init__(self) -> None:
        if self.findings and self.parse_failure is not None:
            raise ValueError("a source analysis cannot contain findings and a parse failure")


def _call_name(func: ast.AST) -> str | None:
    """Best-effort dotted name for a call target: os.system, subprocess.run, cur.execute."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        inner = _call_name(func.value)
        return f"{inner}.{func.attr}" if inner else func.attr
    return None


def _is_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _looks_dynamic_sql(arg: ast.AST) -> bool:
    """A query argument built by interpolation/concatenation rather than a static literal."""
    if isinstance(arg, ast.JoinedStr):                       # f"... {x} ..."
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):   # "..." + x  or  "..." % x
        return True
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
        return True
    return False


_SECRET_NAMES = ("password", "passwd", "secret", "api_key", "apikey", "token", "private_key", "access_key")


# --------------------------------------------------------------------------- VELITES detectors
def _scan_source(path: str, src: str) -> list[StaticFinding]:
    """Detectors for one already-parsed file. Kept as its own function so the `add`/`snip`
    closures bind function parameters, not loop variables (no B023 foot-gun)."""
    out: list[StaticFinding] = []
    lines = src.splitlines()
    tree = ast.parse(src, filename=path)

    def snip(node: ast.AST) -> str:
        i = getattr(node, "lineno", 0) - 1
        return lines[i].strip() if 0 <= i < len(lines) else ""

    def add(rule: str, sev: str, msg: str, node: ast.AST, symbol: str) -> None:
        out.append(
            StaticFinding(
                rule,
                sev,
                msg,
                path,
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                symbol,
                snip(node),
            )
        )

    _SUBPROCESS = {"subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_output"}
    for node in ast.walk(tree):
        # --- calls ---
        if isinstance(node, ast.Call):
            name = _call_name(node.func) or ""
            first = node.args[0] if node.args else None
            is_execute = name == "execute" or name.endswith(".execute")

            # code injection: eval/exec/compile on a non-literal
            if name in {"eval", "exec", "compile"} and first is not None and not _is_literal(first):
                add("PY-CODE-INJECTION", "critical",
                    f"{name}() on a non-literal expression enables code injection", node, name)

            # command injection: os.system / os.popen
            elif name in {"os.system", "os.popen"} and first is not None and not _is_literal(first):
                add("PY-CMD-INJECTION", "high",
                    f"{name}() on a dynamic string enables command injection", node, name)

            # command injection: subprocess with shell=True
            elif name.startswith("subprocess.") or name in _SUBPROCESS:
                if any(isinstance(k.value, ast.Constant) and k.value.value is True
                       for k in node.keywords if k.arg == "shell"):
                    add("PY-CMD-INJECTION", "high",
                        f"{name}(..., shell=True) enables command injection", node, name)

            # unsafe deserialization
            elif name in {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads"}:
                add("PY-UNSAFE-DESERIALIZE", "high",
                    f"{name}() deserializes untrusted data into live objects", node, name)
            elif name == "yaml.load":
                if not any(k.arg == "Loader" for k in node.keywords):
                    add("PY-UNSAFE-DESERIALIZE", "high",
                        "yaml.load() without a SafeLoader executes arbitrary tags", node, name)

            # SQL injection: dynamic query into .execute()
            elif is_execute and first is not None and _looks_dynamic_sql(first):
                add("PY-SQL-INJECTION", "high",
                    f"{name}() runs a dynamically built query; use parameters", node, name)

            # weak crypto
            elif name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                add("PY-WEAK-CRYPTO", "medium", f"{name}() is cryptographically weak", node, name)

        # --- hardcoded secrets ---
        elif isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and any(s in tgt.id.lower() for s in _SECRET_NAMES):
                        add("PY-HARDCODED-SECRET", "medium",
                            f"'{tgt.id}' is assigned a hardcoded string literal", node, tgt.id)
    return out


def analyze_python_bytes(relative_path: str, source_bytes: bytes) -> SourceAnalysisV1:
    """Analyze exact UTF-8 bytes and make every admission/parse failure explicit.

    The governed protocol-v1 caller retains ``source_bytes`` separately and binds the
    resulting observations to that artifact digest.
    """
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("relative_path must be a nonempty string")
    if not isinstance(source_bytes, bytes):
        raise TypeError("source_bytes must be bytes")
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return SourceAnalysisV1(
            relative_path,
            (),
            SourceParseFailureV1(relative_path, "invalid_utf8", 0, exc.start),
        )
    try:
        findings = tuple(_scan_source(relative_path, source))
    except SyntaxError as exc:
        return SourceAnalysisV1(
            relative_path,
            (),
            SourceParseFailureV1(
                relative_path,
                "python_syntax_error",
                exc.lineno or 0,
                exc.offset or 0,
            ),
        )
    return SourceAnalysisV1(relative_path, findings, None)
