"""Fernet encryption for config and database."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

KEY_FILE = Path(__file__).resolve().parent.parent / "sentinel_key.key"
FALLBACK_KEY_FILE = Path.home() / ".soc_sentinel_key.key"


def _resolve_key_file() -> Path:
    if KEY_FILE.exists():
        return KEY_FILE
    if FALLBACK_KEY_FILE.exists():
        return FALLBACK_KEY_FILE
    return KEY_FILE


def _get_fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None

    key_path = _resolve_key_file()
    if not key_path.exists():
        try:
            key_path.write_bytes(Fernet.generate_key())
            try:
                key_path.chmod(0o600)
            except Exception:
                pass
        except Exception:
            try:
                FALLBACK_KEY_FILE.write_bytes(Fernet.generate_key())
                try:
                    FALLBACK_KEY_FILE.chmod(0o600)
                except Exception:
                    pass
                key_path = FALLBACK_KEY_FILE
            except Exception:
                logging.exception("[Crypto] Failed to create key file")
                return None
    try:
        return Fernet(key_path.read_bytes().strip())
    except Exception:
        logging.exception("[Crypto] Failed to load Fernet key")
        return None


def encrypt_json(path: Path, data: dict) -> bool:
    f = _get_fernet()
    if not f:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return False
    enc = path.with_suffix(path.suffix + ".enc")
    try:
        enc.write_bytes(f.encrypt(json.dumps(data, indent=2).encode()))
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass
        return True
    except Exception:
        logging.exception("[Crypto] encrypt_json failed")
        return False


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
