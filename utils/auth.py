"""RBAC: Admin / Operator with salted passwords."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from utils.crypto import load_json_encrypted, encrypt_json

USERS_FILE = Path("sentinel_users.json")
ROLES = {"admin": {"can_block": True, "can_config": True},
         "operator": {"can_block": True, "can_config": False},
         "user": {"can_block": False, "can_config": False}}


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    if "$" in stored:
        salt, _ = stored.split("$", 1)
        return hash_password(password, salt).split("$", 1)[1] == stored.split("$", 1)[1]
    return hashlib.sha256(password.encode()).hexdigest() == stored


def upgrade_password_on_login(username: str, password: str, users: dict):
    if "$" not in users.get(username, {}).get("password", ""):
        users[username]["password"] = hash_password(password)
        save_users(users)


def load_users() -> dict:
    users_enc_path = USERS_FILE.with_suffix(USERS_FILE.suffix + ".enc")
    if users_enc_path.exists():
        try:
            return load_json_encrypted(USERS_FILE, {})
        except Exception:
            pass
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    users = {"admin": {"password": hash_password("admin123"), "role": "admin",
                        "created": str(datetime.now())}}
    save_users(users)
    return users


def save_users(users: dict):
    try:
        if encrypt_json(USERS_FILE, users):
            return
    except Exception:
        pass
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def authenticate(username: str, password: str, users: dict) -> Optional[Tuple[str, str]]:
    data = users.get(username)
    if not data or not verify_password(password, data.get("password", "")):
        return None
    return username, data.get("role", "user")


def register_user(username: str, password: str, users: dict, role: str = "operator") -> bool:
    if username in users or len(password) < 6:
        return False
    users[username] = {"password": hash_password(password), "role": role,
                       "created": str(datetime.now())}
    save_users(users)
    return True


def can(role: str, action: str) -> bool:
    return ROLES.get(role, ROLES["user"]).get(action, False)
