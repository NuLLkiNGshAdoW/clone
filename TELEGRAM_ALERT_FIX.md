# 📊 Alert о блокировании в Telegram - ФИХ

## ❌ Проблема
Когда вы нажимали "🚫 Заблокировать" в Telegram боте, IP действительно блокировался, но:
- ❌ Не добавлялся в список заблокированных в программе
- ❌ Не было alert об этом блокировании
- ❌ Информация не отображалась на главной панели

## ✅ Решение

### 1. **core/telegram_bot.py** - Callback обработчик
```python
# Теперь при нажатии "Заблокировать":
res = self.engine._ips.block_attacker(...)  # Блокируем в firewall
self.engine.blocked_ips.add(target)         # Добавляем в список
self.engine._raise_alert("TG_BLOCK", ...)   # Создаём alert
```

### 2. **core/threat_engine.py** - Обновлён метод `block_attacker()`
```python
def block_attacker(self, ...):
    res = self._ips.block_attacker(...)
    if res.get("ok"):
        self.blocked_ips.add(target)           # Добавляем в список
        self._raise_alert(threat_type, ...)    # Создаём alert
    return res
```

### 3. **core/threat_engine.py** - Исправлена логика в `_raise_alert()`
```python
def _raise_alert(self, atype, actor, ...):
    # Добавляем alert в список для отображения
    a = {"type": atype, "actor": actor, ...}
    self.alerts.append(a)
    
    # Для alert типа TG_BLOCK не отправляем повторно в Telegram
    # (уже отправили ответ на callback)
    if atype == "TG_BLOCK":
        return
    
    # Отправляем уведомления для других типов alert
    target_bot.send_alert(a)
```

## 🧪 Проверка

### Шаг 1: Получите alert в Telegram
```
🔴 *SOC SENTINEL ALERT*
*Тип:* `PORT_SCAN`
*Источник:* `192.168.1.100`
*Уровень:* `CRITICAL`
```

### Шаг 2: Нажмите "🚫 Заблокировать"

### Шаг 3: Проверьте логи

```
[TelegramBot] Вызываем engine._ips.block_attacker для target=192.168.1.100 с firewall
[ActiveResponse] Добавили 192.168.1.100 в self.blocked_ips
[TelegramBot] Добавили 192.168.1.100 в engine.blocked_ips: {'192.168.1.100'}
[TelegramBot] Создаём alert для 192.168.1.100 при блокировании через Telegram
[ThreatEngine] Alert создан при блокировании 192.168.1.100
[TelegramBot] Пропускаем отправку Telegram для TG_BLOCK alert (уже отправили ответ)
```

### Шаг 4: Проверьте программу

В главном окне программы вы должны увидеть:

**Статистика:**
- KPI card "Блокировано" должна увеличиться (например, с 0 на 1)

**Список alert:**
- Новый alert с типом "TG_BLOCK" должен появиться в списке

**Список IP:**
- 192.168.1.100 должен появиться в списке заблокированных IP

**Web API:**
- `GET /api/status` должен содержать `"blocked_ips": ["192.168.1.100"]`

## 📊 Результат

| Действие | Результат |
|----------|-----------|
| Нажимаем "Заблокировать" | ✅ IP блокируется в firewall |
| Проверяем программу | ✅ IP добавляется в `engine.blocked_ips` |
| Проверяем alert список | ✅ Появляется alert типа "TG_BLOCK" |
| Проверяем KPI | ✅ Счётчик "Блокировано" увеличивается |
| Проверяем Web API | ✅ Отражается в `blocked_ips` списке |

## 💡 Важные замечания

1. **Alert не отправляется дважды**: Для TG_BLOCK мы создаём alert в программе, но не отправляем повторно в Telegram
2. **Все системы синхронизированы**: `engine.blocked_ips`, `engine._ips.blocked_ips`, `engine.alerts` - всё обновляется
3. **Логирование детальное**: Легко отследить, на каком этапе что происходит

## 📁 Затронутые файлы

- `core/telegram_bot.py` - Callback обработчик (строки ~140-180)
- `core/threat_engine.py` - Методы `block_attacker()` и `_raise_alert()` (строки ~324-335, ~770-800)

---

**Дата исправления**: 2026-06-11  
**Статус**: ✅ Готово
