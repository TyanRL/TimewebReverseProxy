import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional
import httpx
from fastapi_proxy_lib.core.http import ReverseHttpProxy
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response
from pydantic_settings import BaseSettings

from fastapi import FastAPI, Header, HTTPException, Request #type: ignore
from fastapi.middleware.cors import CORSMiddleware #type: ignore



# --------------------- Settings ---------------------
class Settings(BaseSettings):
    # Upstream
    OPENAI_BASE_URL: str = "https://api.openai.com/v1/"  # важно: слэш на конце
    OPENAI_API_KEY: Optional[str] = None  # нужен если FORWARD_CLIENT_AUTH=false

    # Client auth (твой слой)
    AUTH_ENABLED: bool = True
    CLIENTS_FILE: str = "clients.json"     # json: {"tokens":["..."]} или массив строк
    ALLOW_BEARER_FROM_AUTH_HEADER: bool = True
    CLIENT_HEADER_NAME: str = "x-api-key"   # альтернативный заголовок для клиентских токенов

    # Пробрасывать Authorization клиента как есть к OpenAI
    FORWARD_CLIENT_AUTH: bool = False

    # Логи
    LOG_JSONL_PATH: str = "logs/requests.jsonl"

    # CORS
    CORS_ALLOW_ORIGINS: str = "*"
    CORS_ALLOW_METHODS: str = "*"
    CORS_ALLOW_HEADERS: str = "*"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# --------------------- App/bootstrap ---------------------
app = FastAPI(title="OpenAI Reverse Proxy (fastapi-proxy-lib)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ALLOW_ORIGINS.split(",") if o.strip()],
    allow_methods=[m.strip() for m in settings.CORS_ALLOW_METHODS.split(",") if m.strip()],
    allow_headers=[h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",") if h.strip()],
)

Path(settings.LOG_JSONL_PATH).parent.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("proxy")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

# --------------------- Client tokens ---------------------
_client_tokens: set[str] = set()

def _load_tokens(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "tokens" in data:
            return set(map(str, data.get("tokens", [])))
        if isinstance(data, list):
            return set(map(str, data))
    except Exception as e:
        logger.error(f"clients file read failed: {e}")
    return set()

_client_tokens = _load_tokens(settings.CLIENTS_FILE)

# --------------------- Utils ---------------------

def _redact(v: Optional[str]) -> Optional[str]:
    if not v:
        return v
    if len(v) <= 8:
        return "***"
    return v[:4] + "…" + v[-2:]

async def _log(record: Dict):
    try:
        with open(settings.LOG_JSONL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"log write failed: {e}")

async def _require_client(request: Request) -> Optional[str]:
    if not settings.AUTH_ENABLED:
        return None
    token = request.headers.get(settings.CLIENT_HEADER_NAME)
    auth = request.headers.get("authorization")
    if not token and settings.ALLOW_BEARER_FROM_AUTH_HEADER and auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=401, detail="Missing client token")
    if token not in _client_tokens:
        raise HTTPException(status_code=403, detail="Invalid client token")
    return token

# --------------------- Reverse proxy core ---------------------
_httpx_timeout = httpx.Timeout(connect=10.0, read=120.0, write=120.0, pool=60.0)
_httpx_client = httpx.AsyncClient(timeout=_httpx_timeout)
reverse_proxy = ReverseHttpProxy(client=_httpx_client, base_url=settings.OPENAI_BASE_URL)

@app.on_event("shutdown")
async def _shutdown_httpx_client():
    try:
        await _httpx_client.aclose()
    except Exception:
        pass

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/admin/reload-clients")
async def reload_clients(request: Request):
    admin_token = os.getenv("ADMIN_TOKEN")
    if request.headers.get("x-admin-token") != admin_token or not admin_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    global _client_tokens
    _client_tokens = _load_tokens(settings.CLIENTS_FILE)
    return {"reloaded": len(_client_tokens)}

# Этот эндпоинт ловит всё после /v1/ и отдаёт в OpenAI, сохраняя стримы
@app.api_route("/v1/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def proxy_v1(request: Request, path: str = ""):
    start = time.perf_counter()

    # Проверим клиентскую авторизацию
    await _require_client(request)

    # Подготовим заголовок Authorization для запроса к OpenAI
    # По умолчанию используем серверный ключ (если не включен форвардинг)
    headers = list(request.scope.get("headers", []))  # list[tuple[bytes, bytes]]

    def set_header(name: str, value: str):
        lname = name.lower().encode()
        new = []
        found = False
        for k, v in headers:
            if k.lower() == lname:
                if not found:
                    new.append((k, value.encode()))
                    found = True
                # пропускаем дубликаты
            else:
                new.append((k, v))
        if not found:
            new.append((lname, value.encode()))
        return new

    if not settings.FORWARD_CLIENT_AUTH:
        if not settings.OPENAI_API_KEY:
            raise HTTPException(status_code=500, detail="Server OPENAI_API_KEY not configured")
        headers = set_header("authorization", f"Bearer {settings.OPENAI_API_KEY}")
        # Также полезно удалить любые клиентские api_key поля из тела — оставим это на апстрим

    # Создаём новый Request с модифицированными заголовками
    scope = dict(request.scope)
    scope["headers"] = headers
    patched_request = StarletteRequest(scope, request.receive)

    # Отдаём в прокси (SSE/стрим пробрасывается fastapi-proxy-lib)
    # Логируем целевой upstream URL для диагностики
    try:
        # Соберём целевой URL (без лишних двойных слэшей)
        if path:
            target_url = settings.OPENAI_BASE_URL.rstrip("/") + "/" + path.lstrip("/")
        else:
            target_url = settings.OPENAI_BASE_URL
        logger.info("proxying %s -> %s", request.method, target_url)

        response = await reverse_proxy.proxy(request=patched_request, path=path)
    except httpx.ReadTimeout:
        logger.warning("upstream read timeout while proxying /v1/%s", path)
        raise HTTPException(status_code=504, detail="Upstream read timeout")
    except Exception:
        logger.exception("proxy error while handling /v1/%s", path)
        raise HTTPException(status_code=502, detail="Upstream error")

    # При ошибочных статусах попробуем логировать тело ответа (предварительный просмотр)
    try:
        status = getattr(response, "status_code", None)
        if status and status >= 400:
            body_preview = None
            try:
                body = getattr(response, "body", None)
                if body is None:
                    # Могут быть стриминговые ответы — пометим как streaming
                    body_preview = "<streaming or no body>"
                else:
                    if isinstance(body, (bytes, bytearray)):
                        body_preview = body.decode(errors="replace")[:1000]
                    else:
                        body_preview = str(body)[:1000]
            except Exception as e:
                body_preview = f"<body read failed: {e}>"
            logger.warning("upstream response %s for /v1/%s -> %s : %s", status, path, target_url, body_preview)
    except Exception:
        # Нельзя ломать проксирование логированием
        pass

    # Лог
    try:
        auth_in = request.headers.get("authorization")
        await _log({
            "ts": int(time.time()*1000),
            "method": request.method,
            "path": f"/v1/{path}",
            "status": getattr(response, "status_code", None),
            "duration_ms": round((time.perf_counter() - start)*1000, 2),
            "client_auth": _redact(auth_in) if auth_in else None,
            "mode": "forward" if settings.FORWARD_CLIENT_AUTH else "server-key"
        })
    except Exception:
        pass

    return response

@app.get("/")
async def root():
    return {"message": "OpenAI Reverse Proxy — set your SDK base_url to /v1"}