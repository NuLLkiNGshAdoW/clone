import json
from pathlib import Path

CONFIG_FILE = Path("sentinel_config.json")
DEFAULT = {
    "adapter": "", "theme": "dark", "accent": "cyan",
    "max_table_rows": 200, "alert_sound": False,
    "auto_block": False, "auto_block_firewall": False,
    "auto_block_thresh": 5, "log_to_file": True,
    "data_exfil_kb": 8, "syn_thresh": 100,
    "scan_thresh": 15, "icmp_thresh": 50,
    "ai_api_key": "", "gemini_api_key": "", "openai_api_key": "",
    "demo_mode": True,
    "pps_thresh": 200,
    "tg_token": "",
    "tg_chat_id": "",
    "web_port": 5000,
    "web_enabled": True,
    "web_firewall": True,
    "device_fingerprint_enabled": True,
    "behavior_score_threshold": 70,
    "encrypt_config": True,
    "encrypt_db": False,
    "web_api_key": "",
}

def load_config():
    cfg = None
    # First, try loading with crypto.py for backwards compatibility
    try:
        from utils.crypto import load_json_encrypted
        cfg = load_json_encrypted(CONFIG_FILE, DEFAULT)
    except Exception:
        pass
    # If that didn't work, load plain JSON
    if cfg is None:
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    cfg = json.load(f)
            except Exception:
                pass
    # If still None, use defaults
    if cfg is None:
        cfg = dict(DEFAULT)
    
    # Now, set defaults for missing keys
    for k, v in DEFAULT.items():
        cfg.setdefault(k, v)
    
    # Now decrypt sensitive values using utils/encryption.py
    try:
        from utils.encryption import get_or_create_key, decrypt_config_values
        key = get_or_create_key()
        cfg = decrypt_config_values(cfg, key)
    except Exception as e:
        import logging
        logging.exception("Failed to decrypt config values")
        
    return cfg

def save_config(cfg):
    # First, encrypt sensitive values using utils/encryption.py
    try:
        from utils.encryption import get_or_create_key, encrypt_config_values
        key = get_or_create_key()
        cfg = encrypt_config_values(cfg.copy(), key)
    except Exception as e:
        import logging
        logging.exception("Failed to encrypt config values")
        
    # Now save
    try:
        if cfg.get("encrypt_config"):
            from utils.crypto import encrypt_json
            encrypt_json(CONFIG_FILE, cfg)
        else:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
    except Exception:
        pass
