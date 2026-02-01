#!/usr/bin/env python3
"""
Well-written, secure Python application.
Demonstrates security best practices.
"""

import argparse
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any

import requests
from flask import Flask, request, jsonify
from pydantic import BaseModel, EmailStr, validator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Security: Load from environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['DEBUG'] = os.environ.get('DEBUG', 'False').lower() == 'true'
app.config['ALLOWED_HOSTS'] = os.environ.get('ALLOWED_HOSTS', 'localhost').split(',')

# API configuration from environment
API_ENDPOINT = os.environ.get('API_ENDPOINT', 'https://api.example.com')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')


class UserCreate(BaseModel):
    """Pydantic model for input validation"""
    email: EmailStr
    name: str
    age: int

    @validator('name')
    def name_must_be_valid(cls, v):
        if len(v) < 2 or len(v) > 100:
            raise ValueError('Name must be 2-100 characters')
        return v

    @validator('age')
    def age_must_be_valid(cls, v):
        if v < 0 or v > 150:
            raise ValueError('Age must be 0-150')
        return v


class ProfileUpdate(BaseModel):
    """Validated profile update"""
    email: EmailStr
    bio: str

    @validator('bio')
    def bio_length(cls, v):
        if len(v) > 500:
            raise ValueError('Bio too long')
        return v


def fetch_user_data(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetch user data with proper error handling"""
    try:
        response = requests.get(
            f"{API_ENDPOINT}/users/{user_id}",
            timeout=10,
            verify=True  # Always verify SSL
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch user {user_id}: {e}")
        return None


def read_config(filename: str) -> Optional[str]:
    """Read config with error handling"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except IOError as e:
        logger.error(f"Failed to read config {filename}: {e}")
        return None


def generate_session_token() -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(32)


def generate_api_key() -> str:
    """Generate secure API key"""
    return secrets.token_hex(20)


def generate_password_reset_token() -> str:
    """Generate secure reset token"""
    return secrets.token_urlsafe(16)


def get_user_by_email(email: str) -> Optional[tuple]:
    """Parameterized SQL query - safe from injection"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # Use parameterized query
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return None
    finally:
        conn.close()


def update_user_status(user_id: int, status: str) -> bool:
    """Safe parameterized update"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET status = ? WHERE id = ?",
            (status, user_id)
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Update failed: {e}")
        return False
    finally:
        conn.close()


def delete_user(email: str) -> bool:
    """Safe parameterized delete"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Delete failed: {e}")
        return False
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """
    Hash password with SHA-256 (in production, use bcrypt/scrypt/argon2)
    This is acceptable for demonstration - not MD5/SHA1
    """
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    return f"{salt.hex()}${pwd_hash}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password hash"""
    try:
        salt_hex, pwd_hash = stored_hash.split('$')
        salt = bytes.fromhex(salt_hex)
        computed = hashlib.sha256(salt + password.encode()).hexdigest()
        return computed == pwd_hash
    except ValueError:
        return False


def validate_file_path(user_id: int, filename: str) -> Optional[Path]:
    """Validate and sanitize file paths"""
    # Remove directory traversal attempts
    clean_filename = Path(filename).name
    
    # Construct safe path
    base_dir = Path("/uploads") / str(user_id)
    filepath = base_dir / clean_filename
    
    # Ensure path is within allowed directory
    try:
        filepath = filepath.resolve()
        base_dir = base_dir.resolve()
        if not str(filepath).startswith(str(base_dir)):
            logger.warning(f"Path traversal attempt: {filename}")
            return None
        return filepath
    except (ValueError, OSError):
        return None


def delete_user_file(user_id: int, filename: str) -> bool:
    """Delete file with path validation"""
    filepath = validate_file_path(user_id, filename)
    if not filepath:
        return False
    
    try:
        filepath.unlink()
        return True
    except OSError as e:
        logger.error(f"Failed to delete {filepath}: {e}")
        return False


def read_user_file(user_id: int, filename: str) -> Optional[str]:
    """Read file with validation"""
    filepath = validate_file_path(user_id, filename)
    if not filepath:
        return None
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except IOError as e:
        logger.error(f"Failed to read {filepath}: {e}")
        return None


@app.route('/api/users', methods=['POST'])
def create_user():
    """Create user with input validation"""
    try:
        # Validate with Pydantic
        user_data = UserCreate(**request.json)
        
        # Process validated data
        logger.info(f"Creating user: {user_data.email}")
        
        return jsonify({"status": "created", "email": user_data.email}), 201
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/profile', methods=['PUT'])
def update_profile():
    """Update profile with validation"""
    try:
        # Validate input
        profile = ProfileUpdate(**request.form.to_dict())
        
        logger.info(f"Updating profile: {profile.email}")
        
        return jsonify({"status": "updated"}), 200
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


def process_image(filename: str) -> bool:
    """Process image safely without shell=True"""
    # Validate filename
    if not filename.endswith(('.png', '.jpg', '.jpeg')):
        logger.warning(f"Invalid image format: {filename}")
        return False
    
    try:
        # Use array form - no shell injection possible
        subprocess.run(
            ['convert', filename, 'output.png'],
            check=True,
            timeout=30,
            capture_output=True
        )
        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Image processing failed: {e}")
        return False


def backup_database(db_name: str) -> bool:
    """Backup database safely"""
    # Validate db name (alphanumeric only)
    if not db_name.isalnum():
        logger.warning(f"Invalid database name: {db_name}")
        return False
    
    try:
        subprocess.run(
            ['pg_dump', db_name, '-f', 'backup.sql'],
            check=True,
            timeout=300,
            capture_output=True
        )
        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Backup failed: {e}")
        return False


def load_config() -> Optional[Dict]:
    """Load config with specific exception handling"""
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("Config file not found, using defaults")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config: {e}")
        return None
    except IOError as e:
        logger.error(f"IO error reading config: {e}")
        return None


def fetch_api_data(url: str) -> Optional[Dict]:
    """Fetch API data with error handling"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API request failed: {e}")
        return None


def create_temp_file() -> Optional[str]:
    """Create temp file securely"""
    try:
        # Use NamedTemporaryFile or mkstemp - no race condition
        fd, temp_path = tempfile.mkstemp(suffix='.tmp')
        os.close(fd)
        return temp_path
    except OSError as e:
        logger.error(f"Failed to create temp file: {e}")
        return None


def write_temp_data(data: str) -> Optional[str]:
    """Write to temp file securely"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(data)
            return f.name
    except IOError as e:
        logger.error(f"Failed to write temp data: {e}")
        return None


def load_session(session_json: str) -> Optional[Dict]:
    """Load session data from JSON (not pickle)"""
    try:
        return json.loads(session_json)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid session data: {e}")
        return None


def save_session(session_obj: Dict) -> str:
    """Save session as JSON (safe serialization)"""
    return json.dumps(session_obj)


def load_yaml_config(yaml_string: str) -> Optional[Dict]:
    """Load YAML safely"""
    try:
        import yaml
        # Use safe_load, not load
        return yaml.safe_load(yaml_string)
    except yaml.YAMLError as e:
        logger.error(f"YAML parse error: {e}")
        return None


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Secure Flask application")
    parser.add_argument('--port', type=int, default=5000, help='Port to run on')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    args = parser.parse_args()
    
    # Only run on localhost by default, not 0.0.0.0
    app.run(
        host=args.host,
        port=args.port,
        debug=app.config['DEBUG']
    )


if __name__ == "__main__":
    main()
