"""INTENTIONALLY VULNERABLE benchmark fixture. Parsed by VELITES, never executed.
Seven planted vulnerabilities, one per dangerous pattern. Do not import or run this."""

import hashlib
import os
import pickle
import subprocess


def run_cmd(user_input):
    os.system("ls " + user_input)                      # PY-CMD-INJECTION


def echo(user_input):
    subprocess.run(f"echo {user_input}", shell=True)   # PY-CMD-INJECTION


def deserialize(blob):
    return pickle.loads(blob)                          # PY-UNSAFE-DESERIALIZE


def calc(expr):
    return eval(expr)                                  # PY-CODE-INJECTION


def weak_hash(data):
    return hashlib.md5(data).hexdigest()               # PY-WEAK-CRYPTO


def get_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")   # PY-SQL-INJECTION
    return cur.fetchall()


API_KEY = "hunter2-not-real"                           # PY-HARDCODED-SECRET
