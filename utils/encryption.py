"""
Secure encryption utilities for SOC Sentinel.
Uses Fernet (AES-128-CBC with HMAC-SHA256) for symmetric encryption.
"""

import base64
import json
import logging
import os
import secrets
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    logging.warning("cryptography library not found. Encryption will not work.")
    Fernet = None
    InvalidToken = None

KEY_FILE = Path(__file__).resolve().parent.parent / "sentinel_key.key"
FALLBACK_KEY_FILE = Path.home() / ".soc_sentinel_key.key"

def _resolve_key_file() -> Path:
    if KEY_FILE.exists():
        return KEY_FILE
    if FALLBACK_KEY_FILE.exists():
        return FALLBACK_KEY_FILE
    return KEY_FILE

def generate_key() -> bytes:
    """Generate a new encryption key and save it to key file."""
    key_path = _resolve_key_file()
    if key_path.exists():
        logging.warning("Key file already exists. Not overwriting.")
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except Exception:
            logging.exception("Failed to read existing key file")
    if Fernet is None:
        key = os.urandom(32)
    else:
        key = Fernet.generate_key()
    try:
        with open(key_path, "wb") as f:
            f.write(key)
        try:
            key_path.chmod(0o600)
        except Exception:
            pass
        return key
    except Exception:
        logging.exception("Failed to write key file")
        try:
            FALLBACK_KEY_FILE.write_bytes(key)
            try:
                FALLBACK_KEY_FILE.chmod(0o600)
            except Exception:
                pass
            return key
        except Exception:
            logging.exception("Failed to write fallback key file")
            return key

def get_or_create_key() -> bytes:
    """Get existing key or create new one."""
    key_path = _resolve_key_file()
    if key_path.exists():
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except Exception:
            logging.exception("Failed to read existing key file")
    return generate_key()

def encrypt(data: str, key: bytes) -> str:
    """Encrypt string data."""
    if Fernet is None:
        logging.error("Encryption library not available")
        return data
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt(encrypted: str, key: bytes) -> str:
    """Decrypt string data."""
    if Fernet is None or not encrypted or not encrypted.startswith("gAAAAA"):
        return encrypted
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        logging.error("Invalid encryption token")
        return encrypted

SENSITIVE_CONFIG_KEYS = [
    "tg_token",
    "email_password",
    "virustotal_api",
    "abuseipdb_api",
    "ai_api_key",
    "gemini_api_key",
    "openai_api_key",
]

def encrypt_config_values(config: dict, key: bytes) -> dict:
    """Encrypt sensitive values in config dict."""
    if Fernet is None:
        if config.get("encrypt_config"):
            config["encrypt_config"] = False
        return config
    for key_name in SENSITIVE_CONFIG_KEYS:
        if key_name in config and config[key_name]:
            if not str(config[key_name]).startswith("gAAAAA"):
                config[key_name] = encrypt(str(config[key_name]), key)
    return config

def decrypt_config_values(config: dict, key: bytes) -> dict:
    """Decrypt sensitive values in config dict."""
    if Fernet is None:
        return config
    for key_name in SENSITIVE_CONFIG_KEYS:
        if key_name in config and config[key_name]:
            config[key_name] = decrypt(str(config[key_name]), key)
    return config
