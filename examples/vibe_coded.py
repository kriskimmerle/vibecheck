#!/usr/bin/env python3
"""
Typical AI-generated application with all anti-patterns.
This code demonstrates what NOT to do.
DO NOT USE IN PRODUCTION.
"""

# VC007: Deprecated imports
import optparse
import cgi
from imp import reload

# VC003: Random for security
import random
import pickle  # VC004
import os
import hashlib  # VC009
import subprocess
import tempfile
from flask import Flask, request

app = Flask(__name__)

# VC002: Insecure defaults
DEBUG = True
SECRET_KEY = "secret"  # VC002: Weak secret
ALLOWED_HOSTS = ["*"]  # VC002: Overly permissive
CORS_ALLOW_ALL = True

# VC001: Placeholder credentials
API_KEY = "your-api-key-here"
OPENAI_KEY = "sk-xxxxxxxxxxxx"
DATABASE_PASSWORD = "TODO: replace with real password"
AWS_SECRET = "CHANGEME"
STRIPE_KEY = "example-key-here"
TOKEN = "test123"

# VC005: Hardcoded URLs
API_ENDPOINT = "https://api.production-service.com/v1/users"
PAYMENT_URL = "https://payments.stripe.com/process"
WEBHOOK_URL = "https://myapp.com/webhooks/callback"


# VC006: Missing error handling on network call
def fetch_user_data(user_id):
    """No try/except around requests"""
    import requests
    response = requests.get(f"{API_ENDPOINT}/{user_id}", verify=False)  # VC002: verify=False
    return response.json()


# VC006: Missing error handling on file I/O
def read_config(filename):
    """No try/except around file operations"""
    with open(filename) as f:
        return f.read()


# VC003: Using random for tokens (multiple times)
def generate_session_token():
    """AI copy-paste pattern"""
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(32))


def generate_api_key():
    """AI copy-paste pattern"""
    return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(40))


def generate_password_reset_token():
    """AI copy-paste pattern"""
    return str(random.randint(100000, 999999))


# VC008: SQL string formatting
def get_user_by_email(email):
    """F-string SQL injection"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE email = '{email}'"  # VC008
    cursor.execute(query)
    return cursor.fetchone()


def update_user_status(user_id, status):
    """Format string SQL"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "UPDATE users SET status = '{}' WHERE id = {}".format(status, user_id)  # VC008
    cursor.execute(query)
    conn.commit()


def delete_user(email):
    """Percent formatting SQL"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "DELETE FROM users WHERE email = '%s'" % email  # VC008
    cursor.execute(query)
    conn.commit()


# VC009: Weak hashing for passwords
def hash_password(password):
    """Using MD5 for passwords"""
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, hash_value):
    """Using SHA1 for passwords"""
    return hashlib.sha1(password.encode()).hexdigest() == hash_value


# VC010: Unrestricted file operations
def delete_user_file(user_id, filename):
    """No path validation"""
    filepath = f"/uploads/{user_id}/{filename}"
    os.remove(filepath)  # VC010: User-controlled path


def read_user_file(filepath):
    """Direct user input to open()"""
    with open(filepath, 'r') as f:  # VC010
        return f.read()


# VC012: Missing input validation in Flask route
@app.route('/api/users', methods=['POST'])
def create_user():
    """No validation on request.json"""
    data = request.json  # VC012: No validation
    user_email = data['email']
    user_name = data['name']
    # Direct use without validation...
    return {"status": "created"}


@app.route('/api/profile', methods=['PUT'])
def update_profile():
    """Using form data without validation"""
    email = request.form['email']  # VC012
    bio = request.form['bio']  # VC012
    return {"status": "updated"}


# VC013: Subprocess with shell=True
def process_image(filename):
    """Shell injection risk"""
    subprocess.run(f"convert {filename} output.png", shell=True)  # VC013


def backup_database(db_name):
    """Another shell=True"""
    subprocess.call(f"pg_dump {db_name} > backup.sql", shell=True)  # VC013


def compress_logs(log_dir):
    """Yet another shell=True"""
    subprocess.Popen(f"tar -czf logs.tar.gz {log_dir}", shell=True)  # VC013


# VC014: Broad exception suppression
def load_config():
    """Silently swallows all errors"""
    try:
        with open('config.json') as f:
            return f.read()
    except:  # VC014
        pass


def fetch_api_data(url):
    """Swallows Exception"""
    import requests
    try:
        return requests.get(url).json()
    except Exception:  # VC014
        pass


def parse_user_input(data):
    """Another broad except"""
    try:
        return int(data)
    except:  # VC014
        pass


# VC015: Insecure temp files
def create_temp_file():
    """Race condition vulnerability"""
    temp_path = tempfile.mktemp()  # VC015: Use mkstemp instead
    return temp_path


def write_temp_data(data):
    """Another mktemp usage"""
    tmp = tempfile.mktemp()  # VC015
    with open(tmp, 'w') as f:
        f.write(data)
    return tmp


# VC004: Unsafe deserialization
def load_session(session_data):
    """Pickle on untrusted data"""
    return pickle.loads(session_data)  # VC004


def save_session(session_obj):
    """Pickle for serialization"""
    return pickle.dumps(session_obj)


def load_yaml_config(yaml_string):
    """Unsafe YAML load"""
    import yaml
    return yaml.load(yaml_string)  # VC004: Should use safe_load


def execute_user_code(code_string):
    """eval() on user input"""
    result = eval(code_string)  # VC004: Extremely dangerous
    return result


if __name__ == "__main__":
    # Run with debug mode on
    app.run(debug=True, host="0.0.0.0")  # VC002
