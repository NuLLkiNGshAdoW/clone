import json
from pathlib import Path

from utils.crypto import load_json_encrypted

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
    config_enc_path = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".enc")

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = None

    if cfg is None and config_enc_path.exists():
        try:
            cfg = load_json_encrypted(CONFIG_FILE, DEFAULT)
        except Exception:
            cfg = None

    if cfg is None:
        cfg = dict(DEFAULT)

    for k, v in DEFAULT.items():
        cfg.setdefault(k, v)

    try:
        from utils.encryption import get_or_create_key, decrypt_config_values
        key = get_or_create_key()
        cfg = decrypt_config_values(cfg, key)
    except Exception:
        import logging
        logging.exception("Failed to decrypt config values")

    # Auto-detect WiFi interface on Linux/Kali
    import sys
    if sys.platform.startswith('linux') and cfg.get('adapter') == 'Беспроводная сеть':
        cfg['adapter'] = 'wlan0'
        import logging
        logging.info("[Config] Auto-detected WiFi interface on Linux: wlan0")

    return cfg


def save_config(cfg):
    try:
        from utils.encryption import get_or_create_key, encrypt_config_values, decrypt_config_values
        key = get_or_create_key()
        if cfg.get("encrypt_config"):
            cfg = encrypt_config_values(cfg.copy(), key)
        else:
            cfg = decrypt_config_values(cfg.copy(), key)
    except Exception:
        import logging
        logging.exception("Failed to prepare config values for saving")

    try:
        config_enc_path = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".enc")
        if cfg.get("encrypt_config"):
            from utils.crypto import encrypt_json
            if encrypt_json(CONFIG_FILE, cfg):
                return
        else:
            if config_enc_path.exists():
                try:
                    config_enc_path.unlink()
                except Exception:
                    pass
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass
