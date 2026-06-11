# 🔧 Исправления Telegram Бота - SOC Sentinel v2

## 📋 Резюме проблем

Ваш Telegram бот при критических ошибках не отправлял сообщения, и кнопки "Разблокировать и Игнорировать" не работали корректно.

## ✅ Что было исправлено

### 1. **core/telegram_bot.py** - Улучшение функции отправки alert

#### Изменения в `_send_alert_async()`:
- ✅ Добавлено детальное логирование этапов отправки
- ✅ Улучшена проверка, игнорируется ли актор
- ✅ Добавлена новая кнопка: `🔓 Разбл. и Игнор.` (unblock_ignore)
- ✅ Улучшена обработка исключений с использованием `logging.exception()`

**Ключевые улучшения:**
```python
# Теперь проверяем наличие 'ignored' атрибута перед использованием
is_ignored = False
if self.engine and hasattr(self.engine, "_ips") and hasattr(self.engine._ips, "ignored"):
    is_ignored = actor in self.engine._ips.ignored
```

**Новая кнопка в клавиатуре:**
```python
keyboard = {"inline_keyboard": [[
    {"text": "🚫 Заблокировать", "callback_data": f"block:{actor}"},
    {"text": "✅ Игнорировать", "callback_data": f"ignore:{actor}"},
    {"text": "🔓 Разбл. и Игнор.", "callback_data": f"unblock_ignore:{actor}"}  # ← НОВАЯ
]]}
```

#### Изменения в `_handle_callback()`:
- ✅ Добавлена обработка новой кнопки `unblock_ignore`
- ✅ Улучшено логирование для каждого типа действия
- ✅ Добавлена безопасная обработка исключений

**Новая функция разблокирования и игнорирования:**
```python
elif data.startswith("unblock_ignore:"):
    target = data.split("unblock_ignore:", 1)[1].strip()
    # 1. Разблокируем
    # 2. Игнорируем
    # 3. Отправляем подтверждение
```

---

### 2. **core/active_response.py** - Улучшение методов блокирования

#### Метод `unblock_target()`:
- ✅ Добавлено детальное логирование каждого шага
- ✅ Логирование типа адреса (IPv4 или MAC)
- ✅ Логирование состояния firewall

```python
def unblock_target(self, target: str) -> bool:
    target = target.strip()
    logging.info(f"[ActiveResponse] unblock_target вызван для target={target}")
    # ... с детальным логированием
```

#### Метод `ignore_target()`:
- ✅ Добавлено логирование добавления в ignored список
- ✅ Видимость состояния ignored list после добавления

```python
def ignore_target(self, target: str):
    target_clean = target.strip()
    logging.info(f"[ActiveResponse] ignore_target вызван для target={target_clean}")
    with self._lock:
        self.ignored.add(target_clean)
        logging.info(f"... Теперь ignored: {self.ignored}")
```

---

## 🧪 Как протестировать

### 1. **Тест отправки alert**
```bash
# Запустите программу в режиме LIVE CAPTURE или генерации демо-данных
python WifiSecuritySystem.py --demo

# Вы должны увидеть в логах:
# [TelegramBot] _send_alert_async called with alert: {...}
# [TelegramBot] sev=CRITICAL, _sev_filter={'CRITICAL', 'HIGH'}
# [TelegramBot] Отправляем alert с текстом: ...
```

### 2. **Тест кнопок в Telegram**
- Откройте ваш Telegram чат
- Вы должны увидеть alert с 3 кнопками:
  - 🚫 Заблокировать
  - ✅ Игнорировать
  - 🔓 Разбл. и Игнор.

### 3. **Проверка логов при нажатии кнопок**

#### При нажатии "🔓 Разбл. и Игнор.":
```
[TelegramBot] _handle_callback вызван: cb={'id': '...', 'data': 'unblock_ignore:192.168.1.100'}
[TelegramBot] data=unblock_ignore:192.168.1.100, cb_id=...
[TelegramBot] unblock_ignore для target=192.168.1.100
[ActiveResponse] unblock_target вызван для target=192.168.1.100
[ActiveResponse] target=192.168.1.100 это IPv4, разблокируем
[ActiveResponse] Удалили 192.168.1.100 из blocked_ips
[ActiveResponse] ignore_target вызван для target=192.168.1.100
[ActiveResponse] Добавили 192.168.1.100 в ignored
```

---

## 📊 Затронутые файлы

| Файл | Изменения | Количество строк |
|------|-----------|-----------------|
| `core/telegram_bot.py` | Улучшено: `_send_alert_async()`, `_handle_callback()` | +30 |
| `core/active_response.py` | Улучшено: `unblock_target()`, `ignore_target()` | +15 |

---

## 🔍 Диагностика проблем

### Если alert не приходит:
1. Проверьте логи в консоли для `[TelegramBot]` записей
2. Убедитесь, что severity = "CRITICAL" или "HIGH"
3. Проверьте, что `target_bot` инициализирован в ThreatEngine
4. Убедитесь, что chat_id и token правильные в конфигурации

### Если кнопка не работает:
1. Проверьте, что у вас есть обработчик для callback
2. Смотрите логи для `[TelegramBot] _handle_callback`
3. Убедитесь, что engine имеет метод `_ips`

---

## 💡 Дополнительные рекомендации

1. **Регулярно проверяйте логи**: Все действия теперь логируются подробно для отладки
2. **Используйте новую кнопку**: "🔓 Разбл. и Игнор." для одновременного разблокирования и игнорирования
3. **Тестируйте в demo режиме**: Запустите с `--demo` флагом для генерации тестовых alert

---

## 📝 Версия

**Дата исправления**: 2026-06-11  
**Версия программы**: SOC_Sentinel_v2  
**Статус**: ✅ Готово к использованию
