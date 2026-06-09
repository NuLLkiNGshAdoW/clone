# SOC Sentinel v2 — Портирование Windows → Kali Linux

## Структура изменений

| Компонент | Windows | Linux (Kali) | Файл |
|---|---|---|---|
| Привилегии | `ctypes.windll.IsUserAnAdmin` | `os.geteuid() == 0` | `WifiSecuritySystem.py` |
| DPI-awareness | `shcore.SetProcessDpiAwareness` | убирается (не нужно) | `WifiSecuritySystem.py` |
| Захват пакетов | Npcap + WinPcap | **libpcap** (встроен в Kali) | — |
| Блокировка IP | `netsh advfirewall` | **iptables** / nftables | `core/threat_engine.py` |
| Уведомления | `WinNotifier` / messagebox | **notify-send** | `utils/helpers.py` |
| Шрифты | Segoe UI, Consolas, Inter | **DejaVu Sans**, DejaVu Mono | `WifiSecuritySystem.py` |
| Запуск | двойной клик / .exe | `sudo python WifiSecuritySystem.py` | — |

---

## Шаг 1 — Установка системных пакетов

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-tk \
    libpcap-dev \
    libnotify-bin \
    fonts-dejavu \
    tcl-dev tk-dev \
    python3-scapy
```

---

## Шаг 2 — Установка Python-зависимостей

```bash
pip install -r requirements_linux.txt --break-system-packages
```

Если появится ошибка про `tkinter`:
```bash
sudo apt install python3-tk
```

Если customtkinter не находит Tk:
```bash
sudo apt install python3-dev tk-dev tcl-dev
pip install customtkinter --break-system-packages --force-reinstall
```

---

## Шаг 3 — Применить патч (автоматически)

```bash
# Скопируй linux_patch.py в корень проекта (рядом с WifiSecuritySystem.py)
python3 linux_patch.py
```

Патч делает следующее автоматически:
- Удаляет `ctypes.windll`-вызовы
- Заменяет Windows-шрифты на DejaVu
- Заменяет `IsUserAnAdmin` на проверку `geteuid()`
- Обновляет `utils/helpers.py` для `notify-send`

---

## Шаг 4 — Ручные правки (если нужно)

### 4.1 Блокировка IP через iptables

В файле `core/threat_engine.py` найди метод `block_ip()` и замени на:

```python
def block_ip(self, ip: str):
    with self.lock:
        self.blocked_ips.add(ip)
    # Linux firewall
    import sys, subprocess
    if sys.platform != "win32":
        try:
            from linux_firewall import block_ip_linux
            block_ip_linux(ip)
        except Exception:
            pass
    # алерт
    a = {"time": datetime.now().strftime("%H:%M:%S"),
         "type": "BLOCKED", "actor": ip, "severity": "INFO", "size": 0}
    self.alerts.append(a)
    for cb in self.alert_callbacks:
        try: cb(a)
        except Exception: pass
```

Аналогично для `unblock_ip()`:

```python
def unblock_ip(self, ip: str):
    with self.lock:
        self.blocked_ips.discard(ip)
    import sys
    if sys.platform != "win32":
        try:
            from linux_firewall import unblock_ip_linux
            unblock_ip_linux(ip)
        except Exception:
            pass
```

### 4.2 Выбор сетевого интерфейса

На Kali интерфейс Wi-Fi обычно называется `wlan0` (не "Беспроводная сеть").

В `sentinel_config.json` измени:
```json
"adapter": "wlan0"
```

Проверить доступные интерфейсы:
```bash
ip link show
# или
iwconfig
```

Для мониторинга в режиме захвата достаточно обычного `wlan0`.
Если нужен monitor mode (полный Wi-Fi перехват):
```bash
sudo airmon-ng start wlan0
# интерфейс станет wlan0mon
```

### 4.3 Шрифты emoji в matplotlib

На Kali установи Noto Color Emoji:
```bash
sudo apt install fonts-noto-color-emoji
fc-cache -fv
```

В `WifiSecuritySystem.py` строка уже верная после патча:
```python
matplotlib.rcParams["font.family"] = ["DejaVu Sans", "Noto Color Emoji", "Apple Color Emoji"]
```

---

## Шаг 5 — Запуск

```bash
# Всегда с root (нужен для pcap)
sudo python3 WifiSecuritySystem.py
```

Или через скрипт:
```bash
chmod +x run.sh
sudo ./run.sh
```

Содержимое `run.sh`:
```bash
#!/bin/bash
cd "$(dirname "$0")"
python3 WifiSecuritySystem.py 2>&1 | tee run_log.txt
```

---

## Шаг 6 — Если scapy не видит интерфейс

```bash
# Проверить что libpcap работает
sudo python3 -c "import scapy.all as s; print(s.get_if_list())"

# Дать python права на pcap без sudo (опционально)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

---

## Шаг 7 — Исправление бага из run_log.txt

Ошибка `AttributeError: 'AnalyzerPage' object has no attribute '_export'` уже
исправлена в текущей версии кода — метод `_export` определён до использования.
Никаких дополнительных правок не требуется.

---

## Известные отличия после портирования

| Функция | Windows | Linux |
|---|---|---|
| Уведомления | Balloon-tip (системный трей) | notify-send (GNOME/KDE toast) |
| Блокировка IP | Брандмауэр Windows (netsh) | iptables (требует sudo) |
| Интерфейс Wi-Fi | "Беспроводная сеть" | wlan0 / wlan1 |
| Захват пакетов | Npcap | libpcap (уже в Kali) |
| Шрифты | Segoe UI / Consolas | DejaVu Sans / Mono |
| Emoji | Segoe UI Emoji | Noto Color Emoji |

---

## Быстрая проверка после запуска

1. Войди как `admin` / пароль `admin123` (стандартный)
2. Зайди в **Settings → Network Interface** — выбери `wlan0`
3. Переключи режим `SIMULATION → LIVE`
4. Зайди в **Dashboard** — должны появляться пакеты

Если пакеты не появляются в LIVE режиме — проверь:
```bash
sudo tcpdump -i wlan0 -c 5
```

Если `tcpdump` работает, а Scapy нет:
```bash
sudo python3 -c "from scapy.all import sniff; sniff(iface='wlan0', count=3, prn=print)"
```
