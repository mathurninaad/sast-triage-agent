"""Demo app: a tiny user directory with a few admin tools."""

import hashlib
import os
import pickle
import re
import shlex
import subprocess

from flask import Flask, Response, abort, render_template_string, request

import db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("DEMO_SECRET_KEY", "")

BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
CACHE_FILE = os.path.join(BASE_DIR, "cache", "stats.pkl")
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


# Users


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    return {"users": db.find_users_by_name(name)}


@app.route("/users/<user_id>")
def get_user(user_id):
    uid = int(user_id)
    return {"user": db.get_user_by_id(uid)}


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    password_hash = hashlib.md5(password.encode()).hexdigest()
    db.create_user(username, password_hash)
    return {"ok": True}


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string(f"<h1>Hello {name}!</h1>")


# Admin tools


@app.route("/tools/dns")
def dns_lookup():
    domain = request.args.get("domain", "")
    result = subprocess.run(
        f"nslookup {domain}", shell=True, capture_output=True, text=True
    )
    return {"output": result.stdout}


@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "")
    if not HOSTNAME_RE.match(host):
        abort(400)
    result = subprocess.run(
        f"ping -c 1 {shlex.quote(host)}", shell=True, capture_output=True, text=True
    )
    return {"output": result.stdout}


# Files and sessions


@app.route("/files/<path:filename>")
def download(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "rb") as f:
        return Response(f.read(), mimetype="application/octet-stream")


@app.route("/session/restore", methods=["POST"])
def restore_session():
    state = pickle.loads(request.get_data())
    return {"restored": sorted(state.keys())}


# Stats


def save_stats(stats: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "wb") as f:
        pickle.dump(stats, f)


def load_stats() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE, "rb") as f:
        return pickle.load(f)


@app.route("/stats")
def stats():
    return load_stats()


@app.route("/about")
def about():
    body = "Demo user directory, version 1.0"
    resp = Response(body, mimetype="text/plain")
    resp.headers["ETag"] = hashlib.md5(body.encode()).hexdigest()
    return resp


if __name__ == "__main__":
    app.run()
