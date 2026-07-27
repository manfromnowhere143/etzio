#!/usr/bin/env bash
set -euo pipefail

etzio_python="${ETZIO_PYTHON:-python3}"

"${etzio_python}" -m ruff check etzio tests scripts
"${etzio_python}" -m pytest -q
"${etzio_python}" scripts/validate_repository.py
"${etzio_python}" -m etzio.cli
"${etzio_python}" -m etzio.harness.fpr
"${etzio_python}" -m etzio.scan --fixture vulnerable
"${etzio_python}" -m etzio.scan --fixture clean
