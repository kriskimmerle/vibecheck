"""Example of AI-generated code with common security issues.

This is what a typical vibe-coded Flask app looks like before review.
"""

import os
import pickle
import hashlib
import random
import yaml
import requests
from flask import Flask, request, make_response

app = Flask(__name__)

# VC08: Debug mode
DEBUG = True
SECRET_KEY = "changeme"

# VC05: Hardcoded secrets
OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"


@app.route("/admin/users")
def list_users():
    """VC07: Sensitive route without auth."""
    db = get_db()
    # VC01: SQL injection
    query = f"SELECT * FROM users WHERE role = '{request.args.get('role')}'"
    cursor = db.cursor()
    cursor.execute(query)
    return {"users": cursor.fetchall()}


@app.route("/api/users/<user_id>")
def get_user(user_id):
    """Multiple issues in one handler."""
    db = get_db()
    # VC01: SQL injection via f-string
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()

    # VC04: XSS via f-string HTML response
    return make_response(f"<html><body><h1>User: {user['name']}</h1></body></html>")


@app.route("/api/files")
def get_file():
    """VC03: Path traversal."""
    filename = request.args.get("filename")
    # Path traversal — user controls the filename
    filepath = f"/data/uploads/{filename}"
    f = open(filepath)  # VC11: No with statement
    content = f.read()
    return content


@app.route("/admin/settings", methods=["POST"])
def update_settings():
    """VC07: Another sensitive route without auth."""
    data = request.json
    # VC09: Unsafe deserialization
    config = pickle.loads(data["config"])
    return {"status": "updated"}


@app.route("/api/search")
def search():
    """VC13: SSRF via user-controlled URL."""
    target_url = request.args.get("url")
    # VC13: SSRF + VC12: Missing timeout
    response = requests.get(f"http://{target_url}/api/data")
    return response.json()


@app.route("/api/execute")
def execute_command():
    """VC02: Command injection."""
    cmd = request.args.get("cmd")
    # Direct command injection
    os.system(f"echo {cmd}")
    return {"status": "done"}


@app.route("/api/render")
def render_template_unsafe():
    """VC04: XSS."""
    name = request.args.get("name")
    return f"<html><div class='greeting'>Hello, {name}!</div></html>"


def generate_token():
    """VC06: Insecure random for security token."""
    token = random.randint(100000, 999999)
    return str(token)


def hash_password(password):
    """VC06: Weak hash."""
    return hashlib.md5(password.encode()).hexdigest()


def load_config(path):
    """VC09: Unsafe YAML."""
    with open(path) as f:
        return yaml.load(f.read())


def process_data(data_bytes):
    """VC09: Unsafe pickle."""
    return pickle.loads(data_bytes)


def run_user_code(code_str):
    """VC09: eval with user input."""
    result = eval(code_str)
    return result


def fetch_data(host):
    """VC12: Missing timeout + VC15: SSL disabled."""
    return requests.get(f"https://{host}/data", verify=False)


def handle_error():
    """VC10: Silent error swallowing."""
    try:
        do_something_dangerous()
    except Exception:
        pass

    try:
        another_thing()
    except:
        "this error is lost"


# VC15: CORS wildcard
allow_origins = ["*"]

if __name__ == "__main__":
    app.run(debug=True)
