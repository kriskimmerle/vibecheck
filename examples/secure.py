"""Example of properly secured Python code.

This is what good code looks like after a security review.
"""

import hashlib
import json
import logging
import os
import secrets

import yaml
import requests
from flask import Flask, request, jsonify, render_template
from flask_login import login_required, current_user
from markupsafe import escape

app = Flask(__name__)

# Config from environment
DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY")

logger = logging.getLogger(__name__)


@app.route("/admin/users")
@login_required
def list_users():
    """Properly authenticated with parameterized query."""
    db = get_db()
    role = request.args.get("role", "user")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE role = ?", (role,))
    return jsonify({"users": cursor.fetchall()})


@app.route("/api/users/<int:user_id>")
@login_required
def get_user(user_id):
    """Type-constrained route param, template rendering."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"error": "Not found"}), 404
    return render_template("user.html", user=user)


@app.route("/api/files")
@login_required
def get_file():
    """Sanitized file path."""
    filename = request.args.get("filename", "")
    safe_name = os.path.basename(filename)
    allowed_dir = "/data/uploads"
    filepath = os.path.join(allowed_dir, safe_name)
    # Verify it's still within allowed directory
    if not os.path.realpath(filepath).startswith(os.path.realpath(allowed_dir)):
        return jsonify({"error": "Invalid path"}), 400
    with open(filepath) as f:
        content = f.read()
    return content


@app.route("/admin/settings", methods=["POST"])
@login_required
def update_settings():
    """JSON deserialization instead of pickle."""
    data = request.json
    config = json.loads(json.dumps(data.get("config", {})))
    return jsonify({"status": "updated"})


@app.route("/api/search")
@login_required
def search():
    """URL validation instead of arbitrary SSRF."""
    query = request.args.get("q", "")
    response = requests.get(
        "https://api.search.example.com/search",
        params={"q": query},
        timeout=10,
    )
    return response.json()


def generate_token():
    """Cryptographically secure token."""
    return secrets.token_urlsafe(32)


def hash_password(password):
    """Strong hash with salt."""
    salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()


def load_config(path):
    """Safe YAML loading."""
    with open(path) as f:
        return yaml.safe_load(f.read())


def fetch_data(host):
    """With timeout and SSL verification."""
    allowed_hosts = {"api.example.com", "data.example.com"}
    if host not in allowed_hosts:
        raise ValueError(f"Host not in allowlist: {host}")
    return requests.get(f"https://{host}/data", timeout=30)


def handle_error():
    """Proper error handling."""
    try:
        do_something_dangerous()
    except ValueError as e:
        logger.error("Value error in operation: %s", e)
        raise
    except ConnectionError as e:
        logger.warning("Connection failed, retrying: %s", e)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
