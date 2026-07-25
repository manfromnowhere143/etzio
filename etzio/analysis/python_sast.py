"""Python static analysis via the standard-library `ast`. Real, deterministic, no deps.

Two capabilities:
  * scan_surface(root)  -> AttackSurface   (SCIPIO: files, functions/entrypoints, imports)
  * find_findings(root) -> [StaticFinding]  (VELITES: real vulnerability-class detectors)

Design bias: PRECISION over recall (the estate rule). A detector fires only on a concrete,
dangerous syntactic shape — e.g. `os.system(x)` with a non-literal argument — so that clean
code stays silent. Every finding carries file:line and the exact symbol, so a human (and,
later, MARCELLUS) can act on it. A finding here is a *candidate*, not a confirmed bug.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- data model
@dataclass(frozen=True)
class StaticFinding:
    rule_id: str
    severity: str          # low | medium | high | critical
    message: str
    file: str
    line: int
    symbol: str            # the offending call/name
    snippet: str


@dataclass
class AttackSurface:
    root: str
    files: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)   # "path::function"
    imports: set[str] = field(default_factory=set)
    parse_errors: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "files": len(self.files),
            "entrypoints": len(self.entrypoints),
            "distinct_imports": len(self.imports),
            "parse_errors": len(self.parse_errors),
        }


# --------------------------------------------------------------------------- helpers
def _iter_py_files(root: str):
    if os.path.isfile(root):
        if root.endswith(".py"):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {
            ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
            ".ruff_cache", "node_modules", "build", "dist",
        }]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


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


# --------------------------------------------------------------------------- SCIPIO
def scan_surface(root: str) -> AttackSurface:
    surface = AttackSurface(root=root)
    for path in _iter_py_files(root):
        try:
            src = open(path, encoding="utf-8").read()
            tree = ast.parse(src, filename=path)
        except (OSError, SyntaxError) as exc:
            surface.parse_errors.append(f"{path}: {exc}")
            continue
        surface.files.append(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                surface.entrypoints.append(f"{path}::{node.name}")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    surface.imports.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                surface.imports.add(node.module.split(".")[0])
    return surface


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
        out.append(StaticFinding(rule, sev, msg, path, getattr(node, "lineno", 0), symbol, snip(node)))

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


def find_findings(root: str) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    for path in _iter_py_files(root):
        try:
            src = open(path, encoding="utf-8").read()
            findings.extend(_scan_source(path, src))
        except (OSError, SyntaxError):
            continue
    findings.sort(key=lambda f: (f.file, f.line))
    return findings
