import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # fake example key
API_KEY = "demo_9f8a7b6c5d4e3f2a1b0c"
DB_PASSWORD = "SuperSecret123"


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM users WHERE id = " + uid).fetchall())


@app.route("/user2")
def user2():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall())  # safe


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def fetch_partner():
    return requests.get("https://partner.example.com/api", verify=False).json()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
