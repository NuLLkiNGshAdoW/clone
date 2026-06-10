import json
import threading
from pathlib import Path
from typing import List, Dict

WHITELIST_FILE = Path("sentinel_whitelist.json")
_lock = threading.Lock()

def _load() -> List[Dict]:
    if not WHITELIST_FILE.exists():
        return []
    try:
        return json.loads(WHITELIST_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

def _save(data: List[Dict]):
    tmp = WHITELIST_FILE.with_suffix(".tmp")
    WHITELIST_FILE.parent.mkdir(exist_ok=True)
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(WHITELIST_FILE)

def get_whitelist() -> List[Dict]:
    with _lock:
        return _load()

def is_whitelisted(identifier: str) -> bool:
    if not identifier:
        return False
    with _lock:
        data = _load()
        ids = {entry.get("id", "").strip().lower() for entry in data}
        return identifier.strip().lower() in ids

def add_whitelist_entry(identifier: str, name: str = "") -> List[Dict]:
    identifier = identifier.strip()
    with _lock:
        data = _load()
        for e in data:
            if e.get("id", "").strip().lower() == identifier.lower():
                e["name"] = name or e.get("name", "")
                _save(data)
                return data
        data.append({"id": identifier, "name": name})
        _save(data)
        return data

def remove_whitelist_entry(identifier: str) -> List[Dict]:
    identifier = identifier.strip()
    with _lock:
        data = _load()
        data = [e for e in data if e.get("id", "").strip().lower() != identifier.lower()]
        _save(data)
        return data
