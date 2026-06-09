"""Fernet encryption for config and database."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

KEY_FILE = Path(".sentinel_key")


def _get_fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(Fernet.generate_key())
    return Fernet(KEY_FILE.read_bytes().strip())


def encrypt_json(path: Path, data: dict) -> bool:
    f = _get_fernet()
    if not f:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return False
    enc = path.with_suffix(path.suffix + ".enc")
    enc.write_bytes(f.encrypt(json.dumps(data, indent=2).encode()))
    return True


def load_json_encrypted(path: Path, default: Optional[dict] = None) -> dict:
    f = _get_fernet()
    enc = path.with_suffix(path.suffix + ".enc")
    if f and enc.exists():
        try:
            return json.loads(f.decrypt(enc.read_bytes()).decode())
        except Exception:
            logging.exception("[Crypto] decrypt failed")
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return dict(default or {})


def decrypt_db_if_needed(db_path: Path = Path("sentinel_data.db")) -> bool:
    enc = db_path.with_suffix(db_path.suffix + ".enc")
    f = _get_fernet()
    if f and enc.exists() and not db_path.exists():
        db_path.write_bytes(f.decrypt(enc.read_bytes()))
        return True
    return True


def encrypt_db(db_path: Path = Path("sentinel_data.db")) -> bool:
    f = _get_fernet()
    if not f or not db_path.exists():
        return False
    enc = db_path.with_suffix(db_path.suffix + ".enc")
    enc.write_bytes(f.encrypt(db_path.read_bytes()))
    return True
