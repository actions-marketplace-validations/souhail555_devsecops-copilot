import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import subprocess

import requests
from flask import Flask, abort, request

app = Flask(__name__)
# Secrets come from the environment, never from source code.
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
API_KEY = os.environ.get("API_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall())


@app.route("/user2")
def user2():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall())  # safe


def _valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not _valid_host(host):
        abort(400, "invalid host")
    # Argument list, no shell: the host can't inject extra commands.
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=10)
    return result.stdout


@app.route("/load", methods=["POST"])
def load():
    # JSON only carries data; pickle can execute code on load.
    return str(json.loads(request.data))


def hash_password(pw, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + digest.hex()


def fetch_partner():
    return requests.get("https://partner.example.com/api", timeout=10).json()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
