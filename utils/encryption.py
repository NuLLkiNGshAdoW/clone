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

KEY_FILE = Path("sentinel_key.key")

def generate_key() -> bytes:
    """Generate a new encryption key and save it to key file."""
    if KEY_FILE.exists():
        logging.warning("Key file already exists. Not overwriting.")
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    KEY_FILE.chmod(0o600)  # Restrict permissions
    return key

def get_or_create_key() -> bytes:
    """Get existing key or create new one."""
    if KEY_FILE.exists():
        with open(KEY_FILE, "rb") as f:
            return f.read()
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
