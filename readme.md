# TimewebReverseProxy — заметки по новым правилам клиентов и моделей

В этом форке добавлена проверка допустимых моделей для приватных клиентских токенов (те, что начинаются с monitel:), передаваемых в заголовке Authorization или в заголовке x-api-key.

Файлы:
- Пример файла клиентов: [`clients.json`](clients.json:1)
- Основной код: [`src/main.py`](src/main.py:1)

Новый формат `clients.json`
- Поддерживается расширенный формат — список объектов вида:
```json
[
  {
    "token": "monitel:example_token",
    "models": ["gpt-4", "gpt-3.5-turbo"]
  }
]
```
- Сохраняется обратная совместимость:
  - старый формат `{"tokens":["monitel:..."]}` и список строк `["monitel:..."]` по-прежнему читаются, но в них не указываются разрешённые модели (в этом случае модель не проверяется).
  - альтернативный формат словаря token -> models также поддерживается (например {"monitel:...": ["gpt-4"]}).

Поведение прокси по проверке модели
- Параметр model читается из query-параметра запроса (request.query_params.get("model")).
- Если client token начинается с `monitel:` и присутствует в расширенном списке с указанием models, то при попытке вызвать модель, не входящую в список разрешённых (сравнение нечувствительно к регистру), прокси вернёт 403 и тело с detail = Model not allowed.
- Если token монительный, но в clients.json для него нет поля models (наследие), проверка не применяется.

Перезагрузка клиентов
- Чтобы перечитать `clients.json` без перезапуска, используйте админ-эндпоинт:
  - POST /admin/reload-clients
  - Заголовок `x-admin-token` должен содержать значение переменной окружения ADMIN_TOKEN.

Примеры curl для ручного тестирования
- Перезагрузка клиентов:
```bash
curl -X POST http://localhost:8000/admin/reload-clients -H "x-admin-token: SECRET_ADMIN_TOKEN"
```

- Разрешённый запрос (пример):
```bash
curl -X POST "http://localhost:8000/v1/chat/completions?model=gpt-4" \
  -H "Authorization: Bearer monitel:tyanrl_93119092025" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Hello"}]}'
```

- Запрос с запрещённой моделью (вернёт 403):
```bash
curl -X POST "http://localhost:8000/v1/chat/completions?model=gpt-4o" \
  -H "Authorization: Bearer monitel:tyanrl_93119092025" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Hello"}]}'
```

Замечания для операторов
- Сохраняйте резервную копию `clients.json` перед изменениями.
- Если нужно временно отключить проверку моделей — можно удалить поле models для токена или использовать старый формат списка токенов.
- Логирование отказов происходит в том же JSONL логе запросов (см. настройку LOG_JSONL_PATH в [`src/main.py`](src/main.py:1)).

Если хотите, могу запустить быстрые проверки синтаксиса и линтер сейчас и пометить оставшиеся пункты todo как выполненные.