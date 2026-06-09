import threading
import logging
import requests
from datetime import datetime

class TelegramBot:
    def __init__(self, token: str, chat_id: str, engine=None):
        self.token = token
        self.chat_id = chat_id
        self.engine = engine
        self._base = f"https://api.telegram.org/bot{token}"
        self._last_update_id = 0
        self._running = False
        self._thread = None
        self._sev_filter = {"CRITICAL", "HIGH"}

    def start(self):
        if not self.token or not self.chat_id:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="TgPoll")
        self._thread.start()

    def stop(self):
        self._running = False

    def send_alert(self, alert: dict):
        sev = alert.get("severity", "LOW")
        if sev not in self._sev_filter:
            return
        actor = alert.get("actor", "?")
        if self.engine and hasattr(self.engine, "_ips") and self.engine._ips.is_ignored(actor):
            return
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
        text = (f"{icons.get(sev,'⚪')} *SOC SENTINEL ALERT*\n"
                f"*Тип:* `{alert.get('type','?')}`\n*Источник:* `{actor}`\n"
                f"*Уровень:* `{sev}`\n*Время:* `{alert.get('time', datetime.now().strftime('%H:%M:%S'))}`")
        keyboard = {"inline_keyboard": [[
            {"text": "🚫 Заблокировать", "callback_data": f"block:{actor}"},
            {"text": "✅ Игнорировать", "callback_data": f"ignore:{actor}"}
        ]]}
        self._send(text, keyboard)

    def _send(self, text: str, reply_markup: dict = None):
        if not self.token or not self.chat_id:
            return
        try:
            payload = {"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"}
            if reply_markup:
                import json
                payload["reply_markup"] = json.dumps(reply_markup)
            requests.post(f"{self._base}/sendMessage", json=payload, timeout=5)
        except Exception as e:
            logging.warning("[TelegramBot] send failed: %s", e)

    def _poll_loop(self):
        while self._running:
            try:
                r = requests.get(f"{self._base}/getUpdates",
                    params={"timeout": 10, "offset": self._last_update_id + 1}, timeout=15)
                if r.status_code == 200:
                    for upd in r.json().get("result", []):
                        self._last_update_id = upd["update_id"]
                        self._handle_update(upd)
            except Exception as e:
                logging.warning("[TelegramBot] poll error: %s", e)
            threading.Event().wait(1)

    def _handle_update(self, upd: dict):
        cb = upd.get("callback_query")
        if not cb:
            return
        data, cb_id = cb.get("data", ""), cb.get("id")
        if data.startswith("block:"):
            target = data.split("block:", 1)[1]
            if self.engine and hasattr(self.engine, "block_attacker"):
                res = self.engine.block_attacker(target, reason="Telegram block", threat_type="TG_BLOCK")
                self._answer_callback(cb_id, f"🚫 {target} ({res.get('kind','')})")
            elif self.engine:
                self.engine.block_ip(target)
                self._answer_callback(cb_id, f"🚫 {target}")
        elif data.startswith("ignore:"):
            target = data.split("ignore:", 1)[1]
            if self.engine and hasattr(self.engine, "_ips"):
                self.engine._ips.ignore_target(target)
            self._answer_callback(cb_id, f"✅ {target} проигнорирован")

    def _answer_callback(self, cb_id: str, text: str):
        try:
            requests.post(f"{self._base}/answerCallbackQuery",
                json={"callback_query_id": cb_id, "text": text}, timeout=5)
        except Exception:
            pass
