"""Deliberately vulnerable Python file for SAST QA fixtures.

Each function below triggers a known Semgrep rule. Do NOT fix them —
they are the test signal.
"""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/eval")
def dangerous_eval():
    # Triggers: python.lang.security.audit.eval-detected.eval-detected
    user_input = request.args.get("expr", "")
    return str(eval(user_input))  # noqa: S307


@app.route("/cmd")
def command_injection():
    # Triggers: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
    user_input = request.args.get("host", "")
    return subprocess.check_output(f"ping -c 1 {user_input}", shell=True)


@app.route("/sql")
def sql_injection():
    # Triggers: python.sqlalchemy.security.audit.formatted-sql-query
    import sqlite3
    name = request.args.get("name", "")
    conn = sqlite3.connect(":memory:")
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


# Hardcoded fake credentials — for the SECRET scanner test.
# NOTE: TruffleHog filters out the well-known "AKIAIOSFODNN7EXAMPLE" docs sample,
# so we use a non-example AKIA pattern. Still fake — does not authenticate.
AWS_ACCESS_KEY_ID     = "AKIA2E0A8F3B244C9986QA"                          # nosec - QA fixture
AWS_SECRET_ACCESS_KEY = "Xb7QKp9NfRzL4YwT3mEa8VsHcGdJ2BkFvU6oIqWP"        # nosec - QA fixture
# GitHub personal access token (fake) — TruffleHog has a dedicated detector for `ghp_`
GITHUB_TOKEN          = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"        # nosec - QA fixture
