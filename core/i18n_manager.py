import threading
from datetime import datetime

# Minimal translations for EN/RU/KK — keys mirror used in UI
TRANSLATIONS = {
    "en": {
        # navigation / pages
        "dash": "DASHBOARD", "analyzer": "PACKET ANALYZER", "threats": "THREATS & ALERTS",
        "web": "WEB ACCESS", "topology": "NETWORK MAP", "logs": "SYSTEM LOGS", "settings": "SETTINGS",
        "menu": "MENU", "assistant": "ASSISTANT",
        # common actions / labels
        "clear": "CLEAR", "export": "EXPORT", "filter": "FILTER:", "regex": "Regex",
        "pause": "PAUSE", "block": "BLOCK", "unblock": "UNBLOCK",
        "apply_and_restart": "APPLY & RESTART CAPTURE",
        "idle": "IDLE", "monitoring": "MONITORING",
        "waiting_for_arp": "Waiting for ARP traffic…",
        "sign_in": "SIGN IN", "register": "REGISTER", "username": "Username",
        "password": "Password", "confirm_password": "Confirm Password",
        "fill_fields": "⚠ Fill all fields",
        "simulation_mode": "SIMULATION MODE — synthetic data",
        "live_mode": "LIVE MODE — real traffic",
        "apply_theme": "APPLY THEME (restart app)",
        "capture_mode": "CAPTURE MODE",
        "appearance": "APPEARANCE",
        "language": "Language",
        "save_all": "💾  SAVE ALL SETTINGS",
        "packet_inspector": "⬡ PACKET INSPECTOR",
        "hex_dump": "HEX DUMP",
        "threats": "THREATS",
        "filter_placeholder": "ip / tcp / udp / port…",
        "ask_anything": "Ask anything…",
        "layers": "LAYERS",
        # KPI / dashboard labels
        "total_packets": "TOTAL PACKETS",
        "blocked_ips": "BLOCKED IPs",
        "net_speed": "NET SPEED",
        "alerts_min": "ALERTS/MIN",
        "conns": "CONNS",
        "dns": "DNS",
        "arp_hosts": "ARP HOSTS",
        "cpu_pct": "CPU %",
        "mem_pct": "MEM %",
        # sections & charts
        "bandwidth": "BANDWIDTH",
        "bandwidth_sub": "KB/s — 60s window",
        "packet_rate": "PACKET RATE",
        "packet_rate_sub": "packets/s",
        "protocol_rate": "PROTOCOL RATE",
        "protocol_rate_sub": "TCP · UDP · ICMP  per second",
        "threat_rate": "THREAT RATE",
        "protocols": "PROTOCOLS",
        "top_apps": "TOP APPS",
        "recent_connections": "RECENT CONNECTIONS",
        "live_threat_feed": "LIVE THREAT FEED",
        "ip_control": "IP CONTROL",
        "network_topology": "NETWORK TOPOLOGY",
        "discovered_hosts": "DISCOVERED HOSTS",
        "click_a_row_above": "click a row above",
        "manual_block_unblock": "manual block / unblock",
        # AI panel
        "ai_soc_analyst": "🤖  AI SOC ANALYST",
        "ai_ready_message": "👋 SOC AI Analyst ready.\n\nI analyze ONLY real data from your network — no invented numbers.\n\n• ⬡ Claude  · ◈ Gemini  · ◉ OpenAI\nAuto-fallback enabled — if one fails, next provider is tried.",
        "captured": "captured",
        "detected": "detected",
        "blocks": "blocks",
        "in+out": "in+out",
        "last_60s": "last 60s",
        "active": "active",
        "queries": "queries",
        "found": "found",
        "usage": "usage",
        "used": "used",
        "analyzing": "⏳ Analyzing data…",
        "chat_cleared": "Chat cleared. Ready for analysis.",
        # auth / errors
        "invalid_credentials": "✖ Invalid credentials",
        "username_taken": "✖ Username taken",
        "pw_mismatch": "✖ Passwords do not match",
        "pw_minlen": "✖ Min 6 characters",
        # UI controls
        "menu": "MENU",
        "assistant": "ASSISTANT",
        "filter": "FILTER:",
        "regex": "Regex",
        "pause": "PAUSE",
        "clear": "CLEAR",
        "export": "EXPORT",
        # Threat / topology / logs
        "realtime_events": "real-time attack events",
        "current_session": "CURRENT SESSION",
        "ai_assistant": "AI ASSISTANT",
        "network_interface": "NETWORK INTERFACE",
        "detection_thresholds": "DETECTION THRESHOLDS",
        "user_management": "USER MANAGEMENT",
        "behaviour": "BEHAVIOUR",
        "theme": "Theme:",
        "accent": "Accent:",
        "max_table_rows": "Max table rows:",
        "ip_address_placeholder": "IP address…",
        "click_to_block": "➜ click to block",
        "no_blocked_ips": "No blocked IPs",
        "blocked_status": " BLOCKED",
        "active_status": " ACTIVE",
        "saved_restart": "Saved! Restart to apply.",
    },
    "ru": {
        "dash": "ПАНЕЛЬ", "analyzer": "АНАЛИЗ ПАКЕТОВ", "threats": "УГРОЗЫ И ОПОВЕЩЕНИЯ",
        "web": "ВЕБ-ДОСТУП", "topology": "КАРТА СЕТИ", "logs": "СИСТЕМНЫЕ ЛОГИ", "settings": "НАСТРОЙКИ",
        "menu": "МЕНЮ", "assistant": "АССИСТЕНТ",
        "clear": "ОЧИСТИТЬ", "export": "ЭКСПОРТ", "filter": "ФИЛЬТР:", "regex": "Регекс",
        "pause": "ПАУЗА", "block": "ЗАБЛОКИРОВАТЬ", "unblock": "РАЗБЛОКИРОВАТЬ",
        "apply_and_restart": "ПРИМЕНИТЬ И ПЕРЕЗАПУСТИТЬ ЗАХВАТ",
        "idle": "БЕЗ ДЕЙСТВИЙ", "monitoring": "МОНИТОРИНГ",
        "waiting_for_arp": "Ожидание ARP трафика…",
        "sign_in": "ВХОД", "register": "РЕГИСТРАЦИЯ", "username": "Имя пользователя",
        "password": "Пароль", "confirm_password": "Подтвердите пароль",
        "fill_fields": "⚠ Заполните все поля",
        "simulation_mode": "РЕЖИМ СИМУЛЯЦИИ — синтетические данные",
        "live_mode": "РЕЖИМ ОНЛАЙН — реальный трафик",
        "apply_theme": "ПРИМЕНИТЬ ТЕМУ (перезапустите приложение)",
        "capture_mode": "РЕЖИМ ЗАХВАТА",
        "appearance": "ВНЕШНИЙ ВИД",
        "language": "Язык",
        "save_all": "💾  СОХРАНИТЬ НАСТРОЙКИ",
        "packet_inspector": "⬡ ИНСПЕКТОР ПАКЕТОВ",
        "hex_dump": "HEX ДАМП",
        "threats": "УГРОЗЫ",
        "filter_placeholder": "ip / tcp / udp / порт…",
        # KPI / dashboard labels
        "total_packets": "ВСЕГО ПАКЕТОВ",
        "blocked_ips": "ЗАБЛОКИРОВАННЫЕ IP",
        "net_speed": "СКОРОСТЬ СЕТИ",
        "alerts_min": "ОПОВЕЩ./МИН",
        "conns": "КОННЕКЦИИ",
        "dns": "DNS",
        "arp_hosts": "ARP ХОСТЫ",
        "cpu_pct": "CPU %",
        "mem_pct": "ПАМЯТЬ %",
        # sections & charts
        "bandwidth": "ПОЛОСА ПРОПУСКАНИЯ",
        "bandwidth_sub": "КБ/с — окно 60с",
        "packet_rate": "ЧАСТОТА ПАКЕТОВ",
        "packet_rate_sub": "пакетов/с",
        "protocol_rate": "ПОТОКИ ПРОТОКОЛОВ",
        "protocol_rate_sub": "TCP · UDP · ICMP  в секунду",
        "threat_rate": "ЧАСТОТА УГРОЗ",
        "protocols": "ПРОТОКОЛЫ",
        "top_apps": "ТОП ПРИЛОЖЕНИЙ",
        "recent_connections": "ПОСЛЕДНИЕ СОЕДИНЕНИЯ",
        "live_threat_feed": "ЖИВАЯ ЛЕНТА УГРОЗ",
        "ip_control": "УПРАВЛЕНИЕ IP",
        "network_topology": "ТОПОЛОГИЯ СЕТИ",
        "discovered_hosts": "ОБНАРУЖЕННЫЕ HOST'Ы",
        "click_a_row_above": "кликните строку выше",
        "manual_block_unblock": "ручная блокировка / разблокировка",
        # AI panel
        "ai_soc_analyst": "🤖  AI SOC АНАЛИТИК",
        "ai_ready_message": "👋 SOC AI Аналитик готов.\n\nЯ анализирую ТОЛЬКО реальные данные вашей сети — без выдуманных чисел.\n\n• ⬡ Claude  · ◈ Gemini  · ◉ OpenAI\nАвто-переключение включено — при ошибке пробую следующего провайдера.",
        "captured": "захвачено",
        "detected": "обнаружено",
        "blocks": "блоки",
        "in+out": "вход+выход",
        "last_60s": "последние 60с",
        "active": "активно",
        "queries": "запросы",
        "found": "найдено",
        "usage": "использование",
        "used": "использовано",
        "analyzing": "⏳ Анализирую данные…",
        "chat_cleared": "Чат очищен. Готов к анализу.",
        "invalid_credentials": "✖ Неверные учётные данные",
        "username_taken": "✖ Имя пользователя занято",
        "pw_mismatch": "✖ Пароли не совпадают",
        "pw_minlen": "✖ Мин 6 символов",
        "menu": "МЕНЮ",
        "assistant": "АССИСТЕНТ",
        "filter": "ФИЛЬТР:",
        "regex": "Регекс",
        "pause": "ПАУЗА",
        "clear": "ОЧИСТИТЬ",
        "export": "ЭКСПОРТ",
        "realtime_events": "события атак в реальном времени",
        "current_session": "ТЕКУЩАЯ СЕССИЯ",
        "ai_assistant": "AI ASSISTENT",
        "network_interface": "СЕТЕВЫЙ ИНТЕРФЕЙС",
        "detection_thresholds": "ПОРОГИ ОБНАРУЖЕНИЯ",
        "user_management": "УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ",
        "behaviour": "ПОВЕДЕНИЕ",
        "theme": "Тема:",
        "accent": "Акцент:",
        "max_table_rows": "Макс. строк в таблице:",
        "ip_address_placeholder": "IP адрес…",
        "click_to_block": "➜ нажмите, чтобы заблокировать",
        "no_blocked_ips": "Нет заблокированных IP",
        "blocked_status": " ЗАБЛОКИРОВАНО",
        "active_status": " АКТИВНО",
        "saved_restart": "Сохранено! Перезапустите для применения.",
    },
    "kk": {
        "dash": "БАСҚАРУ ТАҚТАСЫ", "analyzer": "ПАКЕТ АНАЛИЗАТОРЫ", "threats": "ҚАУІПТЕР ЖӘНЕ ЕСКЕРТУЛЕР",
        "topology": "ЖЕЛІ КАРТАСЫ", "logs": "ЖҮЙЕ ЛОГТАРЫ", "settings": "ПАРАМЕТРЛЕР",
        "menu": "МЕНЮ", "assistant": "АСИСТЕНТ",
        "clear": "ТАЗАЛАУ", "export": "ЭКСПОРТ", "filter": "ФИЛЬТР:", "regex": "Регекс",
        "pause": "ТОҚТАТУ", "block": "БЛОКТАУ", "unblock": "БЛОКТАН ШЫҒАРУ",
        "apply_and_restart": "ҚОЛДАНУ ЖӘНЕ ҚАЙТА БАСТАУ",
        "idle": "БОШАҒАН", "monitoring": "БАҚЫЛАУ",
        "waiting_for_arp": "ARP трафигін күту…",
        "sign_in": "КІРУ", "register": "ТІРКЕУ", "username": "Пайдаланушы аты",
        "password": "Құпия сөз", "confirm_password": "Құпия сөзді растайтын",
        "fill_fields": "⚠ Барлық өрістерді толтырыңыз",
        "simulation_mode": "СИМУЛЯЦИЯ РЕЖИМІ — синтетикалық деректер",
        "live_mode": "ТАПСЫРЫС РЕЖИМІ — нақты трафик",
        "apply_theme": "ТАҢДАМАНЫ ҚОЛДАНУ (қосымшаны қайта іске қосыңыз)",
        "capture_mode": "ҚАБЫЛДАУ РЕЖИМІ",
        "appearance": "ДИЗАЙН",
        "language": "Тіл",
        "save_all": "💾  БАРЛЫҚ ПАРАМЕТРЛЕРДІ САҚТАУ",
        "packet_inspector": "⬡ ПАКЕТТЕРДІ ТЕКСЕРУ",
        "hex_dump": "HEX DUMP",
        "threats": "ҚАУІПТЕР",
        "filter_placeholder": "ip / tcp / udp / порт…",
        # KPI / dashboard labels
        "total_packets": "ЖАЛПЫ ПАКЕТТЕР",
        "blocked_ips": "БЛОКТЕЛГЕН IP",
        "net_speed": "ЖЕЛІ ЖЫЛДЫҒЫ",
        "alerts_min": "ХАБАРЛАМ./МИН",
        "conns": "ҚОСЫЛЫСТАР",
        "dns": "DNS",
        "arp_hosts": "ARP ХОСТТАРЫ",
        "cpu_pct": "CPU %",
        "mem_pct": "ЖАД %",
        # sections & charts
        "bandwidth": "ӨТКІЗУ ҚАБІЛЕТІ",
        "bandwidth_sub": "KB/с — 60с терезе",
        "packet_rate": "ПАКЕТТЕР СЫЙЫМДЫҒЫ",
        "packet_rate_sub": "пакет/с",
        "protocol_rate": "ПРОТОКОЛ СЫЙЫМДЫҒЫ",
        "protocol_rate_sub": "TCP · UDP · ICMP  секундта",
        "threat_rate": "ҚАУІПТЕР ТОҚТАУЫ",
        "protocols": "ПРОТОКОЛДАР",
        "top_apps": "ЖОҒАРЫ ҚОЛДАНБАЛАР",
        "recent_connections": "Соңғы байланыстар",
        "live_threat_feed": "ТІКЕЛЕЙ ҚАУІП ТІЗІМІ",
        "ip_control": "IP БАСҚАРУ",
        "network_topology": "ЖЕЛІ ТОПОЛОГИЯСЫ",
        "discovered_hosts": "ТАПҚАН HOST-ТАР",
        "click_a_row_above": "жоғарғы жолды басыңыз",
        "manual_block_unblock": "қолмен блоктау / босату",
        # AI panel
        "ai_soc_analyst": "🤖  AI SOC ТАЛДАУШЫСЫ",
        "ai_ready_message": "👋 SOC AI Аналитигі дайын.\n\nМен тек Сіздің желідегі нақты деректерді талдаймын — ойдан шығарылған сандар жоқ.\n\n• ⬡ Claude  · ◈ Gemini  · ◉ OpenAI\nАвто-ауыстыру қосылған — бір провайдер сәтсіз болса, келесісы қолданылады.",
        "captured": "түсірілді",
        "detected": "анықталды",
        "blocks": "блоктар",
        "in+out": "кіріс+шығыс",
        "last_60s": "соңғы 60с",
        "active": "белсенді",
        "queries": "сұраулар",
        "found": "табылған",
        "usage": "пайдалану",
        "used": "пайдаланылды",
        "analyzing": "⏳ Деректер талданып жатыр…",
        "chat_cleared": "Чат тазаланды. Талдауға дайын.",
        "invalid_credentials": "✖ Қате тіркелгі деректері",
        "username_taken": "✖ Пайдаланушы аты алынған",
        "pw_mismatch": "✖ Құпия сөздер сәйкес келмейді",
        "pw_minlen": "✖ Мин 6 таңба",
        "menu": "МЕНЮ",
        "assistant": "АСИСТЕНТ",
        "filter": "ФИЛЬТР:",
        "regex": "Регекс",
        "pause": "ТОҚТАТУ",
        "clear": "ТАЗАЛАУ",
        "export": "ЭКСПОРТ",
        "realtime_events": "шынайы уақыттағы шабуыл оқиғалары",
        "current_session": "АҒЫМДЫ СЕАНС",
        "ai_assistant": "AI ASSISTANT",
        "network_interface": "ЖЕЛІ ҚОСЫЛҒЫСЫ",
        "detection_thresholds": "ТАҢБАЛАР ШЕКТЕРІ",
        "user_management": "ПАЙДАЛАНУШЫЛАРДЫ БАСҚАРУ",
        "behaviour": "ІС-ҚИМЫЛ",
        "theme": "Тақырып:",
        "accent": "Аксент:",
        "max_table_rows": "Кестенің ең көбі жолдар:",
        "ip_address_placeholder": "IP мекенжай…",
        "click_to_block": "➜ блокқа басыңыз",
        "no_blocked_ips": "Блокталған IP жоқ",
        "blocked_status": " БЛОКТАЛДЫ",
        "active_status": " БЕЛСЕНДІ",
        "saved_restart": "Сақталды! Қолдану үшін қайта іске қосыңыз.",
    }
}

class I18NManager:
    def __init__(self, default_lang: str = "en"):
        self._lock = threading.Lock()
        self._callbacks = []
        self._root = None
        self._lang = default_lang

    def set_root(self, root_widget):
        self._root = root_widget

    def register(self, cb):
        with self._lock:
            if cb not in self._callbacks:
                self._callbacks.append(cb)

    def unregister(self, cb):
        with self._lock:
            try: self._callbacks.remove(cb)
            except ValueError: pass

    def change_language(self, lang_code: str):
        with self._lock:
            self._lang = lang_code
            cbs = list(self._callbacks)
        for cb in cbs:
            try:
                if self._root is not None and hasattr(self._root, 'after'):
                    try: self._root.after(0, cb)
                    except Exception: cb()
                else:
                    cb()
            except Exception:
                # don't raise — UI should handle failures
                pass

    def get_language(self) -> str:
        return self._lang

# singleton
i18n = I18NManager()


def tr(key: str) -> str:
    lang = i18n.get_language() or 'en'
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, key)
