import os
import secrets
import time
import requests
import hashlib

import db

from functools import wraps
from flask import Flask, request, redirect, session, url_for, render_template, abort, jsonify
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv


app = Flask(__name__)
Talisman(app, content_security_policy=None)

load_dotenv()
db.init_db()

data = {
    "interfaces": {},
    "notes": {}
}

app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is not loaded")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "https://localhost/callback")



#----------------------------------------------
# Decorators and helper functions
#----------------------------------------------
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        return func(*args, **kwargs)
    return wrapper

def api_key_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("ApiKey "):
            abort(401, description="Missing API key")

        raw_key = auth.removeprefix("ApiKey ").strip()
        hashed = hash_key(raw_key)

        username = db.get_username_by_api_key(hashed)

        if not username:
            abort(401, description="Invalid API key")

        request.api_user = username
        return func(*args, **kwargs)

    return wrapper



#------------------------------
# Simple hashing for API keys.
#------------------------------
def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

@app.before_request
def before():
    request.start = time.time()
    ua = request.headers.get("User-Agent", "unknown")
    ip = request.remote_addr
    print(f"[REQ] {request.method} {request.path} from {ip} UA={ua}")


@app.after_request
def after(resp):
    start = getattr(request, "start", None)

    if start is not None:
        dur = (time.time() - start) * 1000
        print(f"[DONE] {request.method} {request.path} {resp.status_code} in {dur:.2f}ms")
    else:
        print(f"[DONE] {request.method} {request.path} {resp.status_code}")

    return resp


#----------------------------------------------
# Web routes
#----------------------------------------------
@app.route("/")
def login_page():
    """
    Shows login page.

    Example:
      Open in browser:
        http://localhost:8000/
    """
    return render_template("login.html")

@app.route("/api/resources")
@api_key_required
def api_resources():
    return jsonify({
        "user": request.api_user,
        "resources": sorted(data.keys())
    })

@app.route("/login")
def login():
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        abort(500, description="Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET env vars")

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    print("CREATED STATE:", state)
    print("SESSION AFTER LOGIN:", dict(session))

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user",
        "state": state,
        "allow_signup": "true",
    }

    url = "https://github.com/login/oauth/authorize"
    req = requests.Request("GET", url, params=params).prepare()
    return redirect(req.url)

@app.route("/password-login", methods=["POST"])
def password_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    user = db.get_user(username)

    if not user:
        return render_template("login.html", error="Invalid Credentials"), 401

    if not check_password_hash(user["password_hash"] or "", password):
        return render_template("login.html", error="Invalid Credentials"), 401

    session["user"] = {
        "login": username,
        "id": None,
    }

    return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if request.method == "GET":
        return render_template("signup.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        abort(400, description="Username and password are required")

    if db.get_user(username):
        abort(400, description="Username already exists")

    db.create_user(
        username=username,
        role="user",
        password_hash=generate_password_hash(password)
    )

    session["user"] = {
        "login": username,
        "id": None,
    }

    return redirect(url_for("dashboard"))

@app.route("/callback")
def callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")

    print("STATE FROM GITHUB:", state)
    print("EXPECTED STATE:", expected_state)
    print("SESSION IN CALLBACK:", dict(session))

    if not code:
        abort(400, description="Missing code")
    if not state or state != expected_state:
        abort(400, description="Invalid state")

    token_url = "https://github.com/login/oauth/access_token"
    token_resp = requests.post(
        token_url,
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_REDIRECT_URI,
        },
        timeout=10,
    )
    token_resp.raise_for_status()
    token_json = token_resp.json()
    access_token = token_json.get("access_token")

    if not access_token:
        abort(401, description="Failed to obtain access token")

    user_resp = requests.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10,
    )
    user_resp.raise_for_status()
    user = user_resp.json()
    username = user.get("login")

    if not username:
        abort(401, description="GitHub user did not include a login")

    if not db.get_user(username):
        db.create_user(username=username, role="user")

    session["user"] = {
        "login": username,
        "id": user.get("id"),
    }


    return redirect(url_for("dashboard"))

def get_api_keys_for_user(username):
    return db.get_api_keys_for_user(username)


@app.route("/dashboard")
@login_required
def dashboard():
    username = session["user"]["login"]
    new_api_key = session.pop("new_api_key", None)

    return render_template(
        "dashboard.html",
        username=username,
        role=db.get_user(username)["role"],
        api_keys=get_api_keys_for_user(username),
        resources=sorted(data.keys()),
        new_api_key=new_api_key,
    )

@app.route("/dashboard/api-keys/create", methods=["POST"])
@login_required
def create_api_key_from_dashboard():
    username = session["user"]["login"]

    label = request.form.get("label", "Unnamed key")
    permission = request.form.get("permissions", "read")

    raw_key = secrets.token_urlsafe(32)
    key_id = secrets.token_hex(8)

    db.create_api_key(
        key_id=key_id,
        username=username,
        label=label,
        permissions=[permission],
        key_hash=hash_key(raw_key)
    )

    session["new_api_key"] = raw_key
    
    return redirect(url_for("dashboard"))

@app.route("/dashboard/api-keys/delete/<key_id>", methods=["POST"])
@login_required
def delete_api_key_from_dashboard(key_id):
    username = session["user"]["login"]

    db.delete_api_key(username, key_id)

    return render_template(
        "dashboard.html",
        username=username,
        role=db.get_user(username)["role"],
        api_keys=get_api_keys_for_user(username),
        resources=sorted(data.keys()),
        revoked=True,
    )

@app.route("/logout")
def logout():
    """
    Logs user out by clearing session.

    Example:
      Open in browser:
        http://localhost:8000/logout
    """
    session.clear()
    return redirect(url_for("login_page"))


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(500)
def handle_error(e):
    # For a web lab, keep it simple and readable.
    return f"{e.code} {e.name}: {e.description}", e.code


if __name__ == "__main__":
    app.run(host="localhost", port=8000, debug=True, use_reloader=False)