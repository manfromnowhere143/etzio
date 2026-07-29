#!/usr/bin/env bash
set -euo pipefail

etzio_python="${ETZIO_PYTHON:-python3}"

unset BASH_ENV ENV PYTHONHOME PYTHONOPTIMIZE PYTHONPATH PYTEST_ADDOPTS PYTEST_PLUGINS
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONNOUSERSITE=1

etzio_python_version="$(
  "${etzio_python}" -I -c 'import sys; print("%s:%s.%s.%s" % (sys.implementation.name, *sys.version_info[:3]))'
)"
if [[ "${etzio_python_version}" != "cpython:3.11.15" && "${etzio_python_version}" != "cpython:3.14.2" ]]; then
  printf 'Etzio verification requires CPython 3.11.15 or 3.14.2; got %s\n' "${etzio_python_version:-no implementation/version}" >&2
  exit 2
fi

etzio_sqlite_identity="$(
  "${etzio_python}" -I -c 'import sqlite3; connection = sqlite3.connect(":memory:"); source_id = connection.execute("SELECT sqlite_source_id()").fetchone(); connection.close(); print(f"{sqlite3.sqlite_version}:{source_id[0]}")'
)"
etzio_repository_sqlite_identity="$(
  "${etzio_python}" -c 'import sqlite3; connection = sqlite3.connect(":memory:"); source_id = connection.execute("SELECT sqlite_source_id()").fetchone(); connection.close(); print(f"{sqlite3.sqlite_version}:{source_id[0]}")'
)"
if [[ "${etzio_repository_sqlite_identity}" != "${etzio_sqlite_identity}" ]]; then
  printf 'Etzio SQLite identity changed under repository import context: isolated=%s repository=%s\n' "${etzio_sqlite_identity}" "${etzio_repository_sqlite_identity}" >&2
  exit 2
fi
printf 'Etzio verification runtime: %s SQLite:%s\n' "${etzio_python_version}" "${etzio_sqlite_identity}"

"${etzio_python}" scripts/validate_repository.py
"${etzio_python}" -m ruff check --config pyproject.toml etzio tests scripts
"${etzio_python}" -m pytest -q -c pyproject.toml --verify-mission-evidence tests
"${etzio_python}" -m etzio.cli
"${etzio_python}" -m etzio.harness.fpr
"${etzio_python}" -m etzio.scan --fixture vulnerable
"${etzio_python}" -m etzio.scan --fixture clean
