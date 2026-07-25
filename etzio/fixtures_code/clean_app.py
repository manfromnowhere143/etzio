"""CLEAN benchmark fixture — the false-positive control. VELITES must report ZERO findings
here. Same libraries as the vulnerable file, used safely."""

import hashlib
import json
import subprocess


def safe_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()            # strong hash, not flagged


def load(text: str):
    return json.loads(text)                            # json, not pickle/yaml


def list_dir(path: str):
    return subprocess.run(["ls", path], capture_output=True)   # no shell=True, arg list


def query(conn, name: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # parameterized, safe
    return cur.fetchall()


def add(a: int, b: int) -> int:
    return a + b
