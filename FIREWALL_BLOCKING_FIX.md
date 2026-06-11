# 🔒 Исправление блокирования угроз через Telegram

## ❌ Проблема
Когда вы нажимали кнопку "🚫 Заблокировать" в Telegram, приложение не блокировало угрозу в firewall.

## 🔍 Корневая причина
При вызове функции блокирования из Telegram callback, параметр `use_firewall` не был явно установлен в `True`, поэтому использовалось значение из конфигурации `auto_block_firewall` (по умолчанию `False`).

## ✅ Что было исправлено

### 1. **core/telegram_bot.py** - Обработка callback
```python
# ДО (не работало):
res = self.engine.block_attacker(target, reason="Telegram block", threat_type="TG_BLOCK")

# ПОСЛЕ (работает):
res = self.engine._ips.block_attacker(target, reason="Telegram block", threat_type="TG_BLOCK", use_firewall=True)
```

### 2. **core/active_response.py** - Улучшено логирование

**Логирование firewall применения:**
```python
logging.info(f"[ActiveResponse] use_firewall={use_firewall}, auto_block_firewall={cfg.get('auto_block_firewall', False)}, итоговое fw={fw}")
logging.info(f"[ActiveResponse] Применяем firewall правило для {target} на платформе {sys.platform}")
```

**Логирование команд firewall:**
```python
# Windows (netsh):
logging.info(f"[IPS] Выполняем: netsh advfirewall firewall add rule ...")
logging.info(f"[IPS] Результат: {output}")

# Linux (iptables):
logging.info(f"[IPS] Выполняем: iptables -I INPUT 1 -s {ip} -j DROP")
```

## 📋 Как проверить, что всё работает

### Шаг 1: Запустите программу с логированием
```bash
python WifiSecuritySystem.py --demo
```

### Шаг 2: Получите alert в Telegram
- Вы должны увидеть сообщение с кнопками:
  - 🚫 Заблокировать
  - ✅ Игнорировать
  - 🔓 Разбл. и Игнор.

### Шаг 3: Нажмите "🚫 Заблокировать"

### Шаг 4: Проверьте логи

**Ожидаемый вывод логов:**

```
[TelegramBot] _handle_callback вызван: cb={'id': '...', 'data': 'block:192.168.1.100'}
[TelegramBot] Вызываем engine._ips.block_attacker для target=192.168.1.100 (с firewall)
[ActiveResponse] block_attacker вызван для target=192.168.1.100, use_firewall=True
[ActiveResponse] use_firewall=True, auto_block_firewall=False, итоговое fw=True
[ActiveResponse] Применяем firewall правило для 192.168.1.100 на платформе win32
[IPS] _block_ip_windows для 192.168.1.100, имя правила: SOC_Block_192_168_1_100
[IPS] Выполняем: netsh advfirewall firewall add rule name=SOC_Block_192_168_1_100_in dir=in action=block remoteip=192.168.1.100 enable=yes
[IPS] Результат: OK
[IPS] Результат: OK
[IPS] Успешно заблокировали 192.168.1.100 в Windows firewall
[ActiveResponse] firewall_ok=True, target=192.168.1.100
[TelegramBot] Результат block_attacker={'ok': True, 'time': '14:35:22', 'type': 'TG_BLOCK', 'target': '192.168.1.100', 'kind': 'ip', 'severity': 'HIGH', 'reason': 'Telegram block', 'firewall': True}
[TelegramBot] _answer_callback cb_id=... text=🚫 192.168.1.100 (ip) [FW: True]
```

## 🧪 Дополнительная проверка

### Проверка Windows firewall правил:
```powershell
# Откройте PowerShell как администратор
Get-NetFirewallRule -DisplayName "SOC_Block_*"

# Вы должны увидеть правила для блокированных IP
```

### Проверка Linux iptables:
```bash
# На Linux машине
sudo iptables -L INPUT -n | grep DROP
sudo iptables -L OUTPUT -n | grep DROP

# Вы должны увидеть правила для блокированных IP
```

## 🎯 Результат

| Параметр | Значение |
|----------|----------|
| Firewall применяется | ✅ Да (use_firewall=True) |
| Логирование | ✅ Детальное |
| Windows поддержка | ✅ netsh команды |
| Linux поддержка | ✅ iptables команды |
| Ответ в Telegram | ✅ Показывает результат (FW: True/False) |

## 💡 Важные замечания

1. **Требуется администратор**: На Windows требуются права администратора для применения firewall правил
2. **Требуется sudo**: На Linux требуется `sudo` для iptables команд
3. **Проверьте логи**: Если блокирование не работает, ищите ошибки в логах с префиксом `[IPS]` или `[ActiveResponse]`
4. **Правила сохраняются**: Firewall правила остаются активными, пока вы не разблокируете IP через бот

## 📍 Затронутые файлы

- `core/telegram_bot.py` - Callback обработчик (строки ~140-165)
- `core/active_response.py` - Firewall блокирование (строки ~80-100, ~30-60)

---

**Дата исправления**: 2026-06-11  
**Статус**: ✅ Готово
