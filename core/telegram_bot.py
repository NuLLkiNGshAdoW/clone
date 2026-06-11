import threading
import logging
import requests
import re
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
        self._max_per_minute = 60
        self._actor_cooldown = 1  # 1 second cooldown for testing, adjust as needed!

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
            logging.info(f"[TelegramBot] _send_alert_async called with alert: {alert}")
            sev = alert.get("severity", "LOW")
            logging.info(f"[TelegramBot] sev={sev}, _sev_filter={self._sev_filter}")
            if sev not in self._sev_filter:
                logging.info(f"[TelegramBot] sev {sev} not in filter, skipping")
                return
            actor = alert.get("actor", "?")
            logging.info(f"[TelegramBot] actor={actor}")
            
            # Проверим, игнорируется ли этот actor
            is_ignored = False
            if self.engine and hasattr(self.engine, "_ips") and hasattr(self.engine._ips, "ignored"):
                is_ignored = actor in self.engine._ips.ignored
                logging.info(f"[TelegramBot] actor {actor} is_ignored={is_ignored}")
            
            if is_ignored:
                logging.info(f"[TelegramBot] actor {actor} in ignored list, skipping alert")
                return
            
            icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
            text = (f"{icons.get(sev,'⚪')} *SOC SENTINEL ALERT*\n"
                    f"*Тип:* `{alert.get('type','?')}`\n*Источник:* `{actor}`\n"
                    f"*Уровень:* `{sev}`\n*Время:* `{alert.get('time', datetime.now().strftime('%H:%M:%S'))}`")
            
            # Кнопки для действий: Заблокировать, Игнорировать, Разблокировать и Игнорировать
            keyboard = {"inline_keyboard": [[
                {"text": "🚫 Заблокировать", "callback_data": f"block:{actor}"},
                {"text": "✅ Игнорировать", "callback_data": f"ignore:{actor}"},
                {"text": "🔓 Разбл. и Игнор.", "callback_data": f"unblock_ignore:{actor}"}
            ]]}
            logging.info(f"[TelegramBot] Отправляем alert с текстом: {text[:50]}...")
            self._send(text, keyboard)
        except Exception as e:
            logging.exception("[TelegramBot] send_alert_async error")

    def _send(self, text: str, reply_markup: dict = None):
        logging.info(f"[TelegramBot] _send called with text: {text}")
        if not self.token or not self.chat_id:
            logging.warning("[TelegramBot] missing token or chat_id")
            return
        try:
            payload = {"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"}
            if reply_markup:
                import json
                payload["reply_markup"] = json.dumps(reply_markup)
            logging.info(f"[TelegramBot] sending payload: {payload}")
            r = requests.post(f"{self._base}/sendMessage", json=payload, timeout=5)
            logging.info(f"[TelegramBot] send status: {r.status_code}, response: {r.text}")
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

    def _normalize_target(self, target: str) -> str:
        if not target:
            return ""
        target = target.strip()
        # Extract IPv4 address if target contains port or CIDR suffix
        ipv4_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", target)
        if ipv4_match:
            return ipv4_match.group(1)
        # Normalize MAC addresses
        mac = target.upper().replace("-", ":")
        if re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            return mac
        return target

    def _handle_callback(self, cb: dict):
        """Обработка callback запроса"""
        logging.info(f"[TelegramBot] _handle_callback вызван: cb=%s", cb)
        try:
            data, cb_id = cb.get("data", ""), cb.get("id")
            logging.info(f"[TelegramBot] data=%s, cb_id=%s", data, cb_id)
            msg = None
            
            if data.startswith("block:"):
                raw_target = data.split("block:", 1)[1].strip()
                target = self._normalize_target(raw_target)
                logging.info(f"[TelegramBot] raw_target=%s normalized target=%s self.engine exists=%s", raw_target, target, self.engine is not None)
                if target and self.engine and hasattr(self.engine, "block_ip"):
                    try:
                        logging.info(f"[TelegramBot] Вызываем engine.block_ip для target=%s", target)
                        self.engine.block_ip(target)
                        msg = f"🚫 {target} заблокирован (как в веб-дэшборде)"
                    except Exception as e:
                        logging.exception(f"[TelegramBot] Ошибка при блокировании {target}")
                        msg = f"❌ ошибка: {str(e)[:50]}"
                elif target and self.engine and hasattr(self.engine, "block_attacker"):
                    try:
                        logging.info(f"[TelegramBot] Вызываем engine.block_attacker для target=%s с firewall", target)
                        res = self.engine.block_attacker(target, reason="Telegram block",
                                                         threat_type="TG_BLOCK", severity="CRITICAL", use_firewall=True)
                        logging.info(f"[TelegramBot] Результат engine.block_attacker=%s", res)
                        if not res.get("ok") and res.get("reason") == "firewall_failed":
                            logging.warning(f"[TelegramBot] firewall failed for {target}, fallback невозможно")
                            msg = f"❌ {target} firewall failed"
                        else:
                            msg = f"🚫 {target} ({res.get('kind', 'unknown')}) [FW: {res.get('firewall', False)}]"
                    except Exception as e:
                        logging.exception(f"[TelegramBot] Ошибка при блокировании {target}")
                        msg = f"❌ ошибка: {str(e)[:50]}"
                else:
                    logging.warning(f"[TelegramBot] ignore block failed - engine или block_ip/block_attacker не доступны")
                    msg = f"❌ не удалось выполнить блокировку"
                    if not raw_target:
                        msg = "❌ цель не указана"
            elif data.startswith("ignore:"):
                raw_target = data.split("ignore:", 1)[1].strip()
                target = self._normalize_target(raw_target)
                if target and self.engine and hasattr(self.engine, "_ips"):
                    logging.info(f"[TelegramBot] Вызываем engine._ips.ignore_target для target=%s", target)
                    self.engine._ips.ignore_target(target)
                    logging.info(f"[TelegramBot] Успешно проигнорирован target=%s", target)
                    msg = f"✅ {target} проигнорирован"
                else:
                    logging.warning(f"[TelegramBot] ignore failed - engine или _ips не доступны")
                    msg = f"❌ ignore failed"
            elif data.startswith("unblock_ignore:"):
                raw_target = data.split("unblock_ignore:", 1)[1].strip()
                target = self._normalize_target(raw_target)
                logging.info(f"[TelegramBot] unblock_ignore для raw_target=%s normalized target=%s", raw_target, target)
                if target and self.engine and hasattr(self.engine, "_ips"):
                    try:
                        logging.info(f"[TelegramBot] Разблокируем target=%s", target)
                        if hasattr(self.engine._ips, "unblock_target"):
                            unblock_res = self.engine._ips.unblock_target(target)
                            logging.info(f"[TelegramBot] unblock_target результат: {unblock_res}")
                        logging.info(f"[TelegramBot] Игнорируем target=%s", target)
                        self.engine._ips.ignore_target(target)
                        logging.info(f"[TelegramBot] ignore_target вызван успешно")
                        msg = f"🔓 {target} разблокирован и проигнорирован"
                    except Exception as e:
                        logging.exception(f"[TelegramBot] unblock_ignore error для target={target}")
                        msg = f"❌ ошибка: {str(e)[:30]}"
                else:
                    logging.warning(f"[TelegramBot] unblock_ignore failed - engine или _ips не доступны")
                    msg = f"❌ не удалось разблокировать и проигнорировать"
            else:
                logging.warning(f"[TelegramBot] Неизвестный callback data: {data}")
                msg = "❌ Неизвестная команда"

            if cb_id and msg is not None:
                self._answer_callback(cb_id, msg)
            elif cb_id:
                self._answer_callback(cb_id, "✅ Выполнено")
        except Exception as e:
            logging.exception("[TelegramBot] handle_callback error")
            if cb and cb.get("id"):
                self._answer_callback(cb.get("id"), "❌ Ошибка обработки callback")

    def _answer_callback(self, cb_id: str, text: str):
        """Ответить на callback запрос"""
        try:
            if not cb_id:
                return
            payload = {"callback_query_id": cb_id, "text": text, "show_alert": False}
            logging.info(f"[TelegramBot] answerCallbackQuery payload: {payload}")
            requests.post(f"{self._base}/answerCallbackQuery",
                json=payload, timeout=5)
        except Exception as e:
            logging.debug("[TelegramBot] answer_callback error: %s", e)
