
import requests
from utils.config import load_config

# Load config using our fixed function
cfg = load_config()
TOKEN = cfg.get("tg_token", "")
CHAT_ID = cfg.get("tg_chat_id", "")

def test_telegram():
    if not TOKEN or not CHAT_ID:
        print("[ERROR] Token or chat ID not found in config!")
        return
        
    print("[DEBUG] Testing Telegram credentials...")
    print(f"[DEBUG] Token: {TOKEN[:20]}...")
    print(f"[DEBUG] Chat ID: {CHAT_ID}")
    
    # First, test getMe
    getme_url = f"https://api.telegram.org/bot{TOKEN}/getMe"
    print(f"[DEBUG] Testing getMe at: {getme_url}")
    try:
        r = requests.get(getme_url, timeout=10)
        print(f"[DEBUG] getMe status: {r.status_code}")
        print(f"[DEBUG] getMe response: {r.text}")
    except Exception as e:
        print(f"[ERROR] getMe failed: {e}")
        return

    if r.status_code == 200:
        print("[SUCCESS] Bot token is valid!")
    else:
        print("[ERROR] Bot token is invalid! Check your token!")
        return
    
    # Now test sending a message
    send_url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": "Test message from SOC Sentinel!"
    }
    print(f"[DEBUG] Sending test message to {CHAT_ID}...")
    try:
        r = requests.post(send_url, json=payload, timeout=10)
        print(f"[DEBUG] sendMessage status: {r.status_code}")
        print(f"[DEBUG] sendMessage response: {r.text}")
    except Exception as e:
        print(f"[ERROR] sendMessage failed: {e}")
        return

    if r.status_code == 200:
        print("[SUCCESS] Test message sent successfully!")
    else:
        print("[ERROR] Failed to send test message!")

if __name__ == "__main__":
    test_telegram()
