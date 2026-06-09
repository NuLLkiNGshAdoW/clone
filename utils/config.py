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
    "encrypt_config": False,
    "encrypt_db": False,
}

def load_config():
    try:
        from utils.crypto import load_json_encrypted
        cfg = load_json_encrypted(CONFIG_FILE, DEFAULT)
        for k, v in DEFAULT.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        pass
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return dict(DEFAULT)

def save_config(cfg):
    try:
        if cfg.get("encrypt_config"):
            from utils.crypto import encrypt_json
            encrypt_json(CONFIG_FILE, cfg)
        else:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
    except Exception:
        pass
