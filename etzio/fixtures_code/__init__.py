"""Benchmark code fixtures for the SCIPIO/VELITES static-analysis slice. These files are
data, parsed but NEVER executed. `vulnerable_app.py` carries seven intentional planted
vulnerabilities; `clean_app.py` carries none (the false-positive control)."""

import os

FIXTURES_DIR = os.path.dirname(__file__)
