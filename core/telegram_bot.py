import threading
import logging
import requests
import time
from collections import deque
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
        self._stop_event = threading.Event()  # Для правильной остановки
        # rate limiting
        self._actor_last_sent: dict = {}
        self._recent_timestamps: deque = deque()
        self._max_per_minute = 12
        self._actor_cooldown = 30  # seconds per-actor cooldown

    def start(self):
        if not self.token or not self.chat_id:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="TgPoll")
        self._thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def send_alert(self, alert: dict):
        if not self._running or not self.token or not self.chat_id:
            return
        try:
            # rate limiting: global and per-actor
            now = time.time()
            # prune old timestamps (older than 60s)
            while self._recent_timestamps and now - self._recent_timestamps[0] > 60:
                self._recent_timestamps.popleft()
            if len(self._recent_timestamps) >= self._max_per_minute:
                logging.warning("[TelegramBot] global rate limit reached (%d/min), dropping alert", self._max_per_minute)
                return
            actor = (alert.get("actor") or "").strip()
            if actor:
                last = self._actor_last_sent.get(actor)
                if last and now - last < self._actor_cooldown:
                    logging.debug("[TelegramBot] per-actor cooldown for %s (%.1fs remaining)", actor, self._actor_cooldown - (now - last))
                    return
                self._actor_last_sent[actor] = now
            self._recent_timestamps.append(now)
            threading.Thread(target=self._send_alert_async, args=(alert,), daemon=True, name="TgAlert").start()
        except Exception as e:
            logging.warning("[TelegramBot] send_alert failed: %s", e)

    def _send_alert_async(self, alert: dict):
        """Асинхронная отправка алерта в отдельном потоке"""
        try:
            sev = alert.get("severity", "LOW")
            if sev not in self._sev_filter:
                return
            actor = alert.get("actor", "?")
            if self.engine and hasattr(self.engine, "_ips") and actor in self.engine._ips.ignored:
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
        except Exception as e:
            logging.warning("[TelegramBot] send_alert_async error: %s", e)

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
        """Основной цикл опроса Telegram API с корректной обработкой ошибок"""
        while self._running:
            try:
                r = requests.get(f"{self._base}/getUpdates",
                    params={"timeout": 10, "offset": self._last_update_id + 1}, timeout=15)
                if r.status_code == 200:
                    updates = r.json().get("result", [])
                    for upd in updates:
                        try:
                            self._last_update_id = upd.get("update_id", self._last_update_id)
                            self._handle_update(upd)
                        except Exception as e:
                            logging.warning("[TelegramBot] handle_update error: %s", e)
                    if not updates:
                        # Если нет обновлений, подождём немного
                        if self._stop_event.wait(1):
                            break
            except requests.Timeout:
                logging.debug("[TelegramBot] poll timeout (normal)")
            except Exception as e:
                logging.warning("[TelegramBot] poll error: %s", e)
                if self._stop_event.wait(2):
                    break

    def _handle_update(self, upd: dict):
        """Обработка обновления в отдельном потоке"""
        try:
            cb = upd.get("callback_query")
            if not cb:
                return
            # Запустим обработку в отдельном потоке чтобы не блокировать poll_loop
            threading.Thread(target=self._handle_callback, args=(cb,), daemon=True, name="TgCallback").start()
        except Exception as e:
            logging.warning("[TelegramBot] handle_update error: %s", e)

    def _handle_callback(self, cb: dict):
        """Обработка callback запроса"""
        logging.info(f"[TelegramBot] _handle_callback вызван: cb=%s", cb)
        try:
            data, cb_id = cb.get("data", ""), cb.get("id")
            logging.info(f"[TelegramBot] data=%s, cb_id=%s", data, cb_id)
            if data.startswith("block:"):
                target = data.split("block:", 1)[1].strip()
                logging.info(f"[TelegramBot] target=%s, self.engine exists=%s", target, self.engine is not None)
                if target and self.engine:
                    if hasattr(self.engine, "block_attacker"):
                        logging.info(f"[TelegramBot] Вызываем engine.block_attacker для target=%s", target)
                        res = self.engine.block_attacker(target, reason="Telegram block", threat_type="TG_BLOCK")
                        logging.info(f"[TelegramBot] Результат block_attacker=%s", res)
                        msg = f"🚫 {target} ({res.get('kind', 'unknown')})"
                    elif hasattr(self.engine, "block_ip"):
                        logging.info(f"[TelegramBot] Вызываем engine.block_ip для target=%s", target)
                        self.engine.block_ip(target)
                        msg = f"🚫 {target}"
                    else:
                        logging.warning(f"[TelegramBot] engine не имеет block_attacker или block_ip!")
                        msg = f"❌ block_attacker not available"
                    self._answer_callback(cb_id, msg)
            elif data.startswith("ignore:"):
                target = data.split("ignore:", 1)[1].strip()
                if target and self.engine and hasattr(self.engine, "_ips"):
                    logging.info(f"[TelegramBot] Вызываем engine._ips.ignore_target для target=%s", target)
                    self.engine._ips.ignore_target(target)
                    self._answer_callback(cb_id, f"✅ {target} проигнорирован")
                else:
                    self._answer_callback(cb_id, f"❌ ignore failed")
        except Exception as e:
            logging.exception("[TelegramBot] handle_callback error")

    def _answer_callback(self, cb_id: str, text: str):
        """Ответить на callback запрос"""
        try:
            if not cb_id:
                return
            requests.post(f"{self._base}/answerCallbackQuery",
                json={"callback_query_id": cb_id, "text": text}, timeout=5)
        except Exception as e:
            logging.debug("[TelegramBot] answer_callback error: %s", e)
