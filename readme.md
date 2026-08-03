# TimewebReverseProxy — заметки

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
- При `AUTH_ENABLED=true` по умолчанию используется `CLIENT_TOKEN_MODE=strict`: каждый клиентский токен должен быть указан в `clients.json` или переменных окружения. Старый режим передачи произвольного upstream-ключа включается явно через `CLIENT_TOKEN_MODE=pass_through`.

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

## Запуск на VPS через Docker Compose

VPS получает исходный код из GitHub-репозитория `https://github.com/TyanRL/TimewebReverseProxy`. В корне проекта создайте `.env` на основе [`env.example`](env.example:1) и укажите ключи upstream и `ADMIN_TOKEN`. Файл [`clients.json`](clients.json:1) требуется только при `AUTH_ENABLED=true`; он не включается в Git.

На VPS с установленными Docker и Compose Plugin выполните:

```bash
git clone https://github.com/TyanRL/TimewebReverseProxy.git /opt/TimewebReverseProxy
cd /opt/TimewebReverseProxy
cp env.example .env
# отредактируйте .env; clients.json нужен только при AUTH_ENABLED=true
./deploy/update.sh
```

Для чистого Debian/Ubuntu VPS можно выполнить один bootstrap-скрипт от root. Он установит Docker, клонирует репозиторий из GitHub и создаст необходимые конфигурационные файлы:

```bash
curl -fsSL https://raw.githubusercontent.com/TyanRL/TimewebReverseProxy/main/deploy/install-vps.sh | sudo bash
sudo nano /opt/TimewebReverseProxy/.env
sudo nano /opt/TimewebReverseProxy/clients.json # только если AUTH_ENABLED=true
sudo /opt/TimewebReverseProxy/deploy/update.sh
```

Проверка состояния:

```bash
curl http://127.0.0.1:8000/healthz
docker compose -f deploy/docker-compose.yaml logs -f reverse-proxy
```

По умолчанию сервис доступен на `127.0.0.1:8000` и не публикуется напрямую наружу. Для публикации в интернете используйте reverse proxy (например, Nginx) и настройте HTTPS.

Для обновления VPS из ветки `main` выполните:

```bash
/opt/TimewebReverseProxy/deploy/update.sh
```

Скрипт [`deploy/update.sh`](deploy/update.sh:1) получает свежий код с GitHub, не удаляет локальные `.env` и `clients.json`, пересобирает образ и перезапускает контейнер.
