import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, List

import httpx
from fastapi_proxy_lib.core.http import ReverseHttpProxy
from starlette.requests import Request as StarletteRequest
from pydantic_settings import BaseSettings

from fastapi import FastAPI, HTTPException, Request  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from fastapi.responses import JSONResponse, PlainTextResponse # type: ignore

# =====================================================
# Settings
# =====================================================
class Settings(BaseSettings):
    # --- Upstreams ---
    OPENAI_BASE_URL: str = "https://api.openai.com/v1/"  # keep trailing slash
    OPENAI_API_KEY: Optional[str] = None                 # server-side API key used by proxy for private monitel tokens or when no client token provided

    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1/"  # keep trailing slash
    OPENROUTER_API_KEY: Optional[str] = None
    # Optional attribution headers recommended by OpenRouter
    OPENROUTER_HTTP_REFERER: Optional[str] = None  # e.g. https://yourapp.example
    OPENROUTER_X_TITLE: Optional[str] = None       # e.g. "My App"

    # Which upstream to use by default if client doesn't specify
    # one of: "openai" | "openrouter"
    UPSTREAM_DEFAULT: str = "openai"

    # Allow per-request upstream override via header `x-upstream: openai|openrouter`
    ALLOW_UPSTREAM_HEADER: bool = True

    # --- Client auth for your proxy layer ---
    AUTH_ENABLED: bool = True
    CLIENTS_FILE: str = "clients.json"  # json: {"tokens":["..."]} or ["..."]
    ALLOW_BEARER_FROM_AUTH_HEADER: bool = True
    CLIENT_HEADER_NAME: str = "x-api-key"  # alternative header for client tokens

    # Adaptive client auth:
    # If client token starts with monitel: it is a private key and must be present in clients.json.
    # Otherwise the token is treated as an upstream API key and will be forwarded to the upstream.

    # --- HTTP client timeouts & transport ---
    HTTP_TIMEOUT_CONNECT: float = 20.0
    HTTP_TIMEOUT_READ: float = 600.0
    HTTP_TIMEOUT_WRITE: float = 300.0
    HTTP_TIMEOUT_POOL: float = 120.0
    HTTP2_ENABLED: bool = True

    # --- Logging ---
    LOG_JSONL_PATH: str = "logs/requests.jsonl"
    ACCESS_LOG_NOISE_FILTER: bool = True  # suppress common scanner noise in uvicorn.access

    # --- CORS ---
    CORS_ALLOW_ORIGINS: str = "*"
    CORS_ALLOW_METHODS: str = "*"
    CORS_ALLOW_HEADERS: str = "*"

    # --- Root behavior ---
    ROOT_ALLOW_QUERIES: bool = False  # if false, GET / with query string returns 404

    # --- Strict allow-list ---
    ALLOWLIST_ENABLED: bool = False
    # Comma-separated lists
    ALLOWLIST_PREFIXES: str = "/v1/,/openai/,/openrouter/,/api/v1/"
    ALLOWLIST_EXACT: str = "/healthz,/_meta/upstreams,/robots.txt,/admin/reload-clients,/"
    # Whether to let any CORS preflight through regardless of path
    ALLOWLIST_ALLOW_OPTIONS_ANY: bool = True
    # Response to send when blocked
    ALLOWLIST_DENY_CODE: int = 404
    ALLOWLIST_DENY_MESSAGE: str = "Not found"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

# =====================================================
# App / bootstrap
# =====================================================
app = FastAPI(title="Multi-Upstream Reverse Proxy (OpenAI + OpenRouter)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ALLOW_ORIGINS.split(",") if o.strip()],
    allow_methods=[m.strip() for m in settings.CORS_ALLOW_METHODS.split(",") if m.strip()],
    allow_headers=[h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",") if h.strip()],
)

# -------------------- Strict allow-list middleware --------------------
# Build allow-list sets from config once

def _csv_list(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x and x.strip()]

_ALLOW_PREFIXES: Tuple[str, ...] = tuple(_csv_list(settings.ALLOWLIST_PREFIXES))
_ALLOW_EXACT: set[str] = set(_csv_list(settings.ALLOWLIST_EXACT))

@app.middleware("http")
async def _allowlist_middleware(request: Request, call_next):
    if settings.ALLOWLIST_ENABLED:
        path = request.url.path or "/"
        method = request.method.upper()

        # OPTIONS preflight may be allowed broadly to not break CORS
        if method == "OPTIONS" and settings.ALLOWLIST_ALLOW_OPTIONS_ANY:
            return await call_next(request)

        allowed = False
        if path in _ALLOW_EXACT:
            allowed = True
        elif any(path.startswith(pfx) for pfx in _ALLOW_PREFIXES):
            allowed = True

        if not allowed:
            return JSONResponse(
                status_code=settings.ALLOWLIST_DENY_CODE,
                content={"detail": settings.ALLOWLIST_DENY_MESSAGE},
            )

    return await call_next(request)

Path(settings.LOG_JSONL_PATH).parent.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("proxy")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

# Optional: filter noisy access logs from random internet scanners
class AccessLogNoiseFilter(logging.Filter):
    noisy_substrings = (
        "/favicon.ico",
        "/sitemap.xml",
        "/.env",
        "/.git/",
        "/dns-query",
        "/resolve",
        "/query",
        "/wiki",
        "/hello.world",
        "eval-stdin.php",
        "/vendor/phpunit",
    )

    METHODS = ("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            path = ""
            rl = None
            args = getattr(record, "args", None)
            if isinstance(args, dict):
                rl = args.get("request_line")
            elif isinstance(args, tuple) and len(args) >= 2:
                rl = args[1]

            # Normalize to string if possible
            if isinstance(rl, (bytes, bytearray)):
                req_line = rl.decode("utf-8", "ignore")
            elif isinstance(rl, str):
                req_line = rl
            else:
                req_line = None

            if isinstance(req_line, str) and req_line:
                parts = req_line.split(" ")
                if len(parts) >= 2:
                    path = parts[1]
            else:
                # Fallback: derive from formatted message without regex
                try:
                    msg = record.getMessage()
                except Exception:
                    msg = ""
                for m in self.METHODS:
                    token = f'"{m} '
                    idx = msg.find(token)
                    if idx != -1:
                        start = idx + len(token)
                        end = msg.find(" ", start)
                        if end == -1:
                            end = msg.find('"', start)
                        if end != -1:
                            path = msg[start:end]
                        else:
                            path = msg[start:]
                        break

            if not path:
                return True  # fail-open

            for s in self.noisy_substrings:
                if s and s in path:
                    return False
        except Exception:
            return True
        return True

try:
    if settings.ACCESS_LOG_NOISE_FILTER:
        logging.getLogger("uvicorn.access").addFilter(AccessLogNoiseFilter())
except Exception:
    pass

# =====================================================
# Client tokens
# =====================================================
_client_tokens: set[str] = set()
_client_allowed_models: Dict[str, set[str]] = {}


def _load_clients(path: str) -> Tuple[set[str], Dict[str, set[str]]]:
    p = Path(path)
    if not p.exists():
        return set(), {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        tokens: set[str] = set()
        allowed: Dict[str, set[str]] = {}

        # New extended format: list of objects [{"token":"monitel:...","models":["gpt-4", ...]}, ...]
        if isinstance(data, list):
            # If list contains dicts with token+models
            if data and all(isinstance(item, dict) for item in data):
                for obj in data:
                    tok = obj.get("token")
                    if not tok:
                        continue
                    tok = str(tok)
                    tokens.add(tok)
                    models = obj.get("models")
                    if isinstance(models, list):
                        allowed[tok] = set(map(str, models))
            else:
                # Legacy: list of strings
                tokens = set(map(str, data))
        elif isinstance(data, dict):
            # Legacy dict with "tokens": [...]
            if "tokens" in data and isinstance(data.get("tokens"), list):
                tokens = set(map(str, data.get("tokens", [])))
            else:
                # Possibly a mapping token -> [models], e.g. {"monitel:abc": ["gpt-4"]}
                for k, v in data.items():
                    if isinstance(k, str) and isinstance(v, list):
                        tokens.add(k)
                        allowed[k] = set(map(str, v))

        return tokens, allowed
    except Exception as e:
        logger.error(f"clients file read failed: {e}")
    return set(), {}


# Initial load
_client_tokens, _client_allowed_models = _load_clients(settings.CLIENTS_FILE)

# =====================================================
# Utils
# =====================================================

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

    # If token is a private monitel token, require it to be present in clients.json
    if isinstance(token, str) and token.startswith("monitel:"):
        if token not in _client_tokens:
            raise HTTPException(status_code=403, detail="Invalid client token")

    # Otherwise treat token as an upstream API key and allow it (pass-through)
    return token


# =====================================================
# Upstreams
# =====================================================
HttpHeaders = List[Tuple[bytes, bytes]]


class Upstream:
    def __init__(
        self,
        name: str,
        base_url: str,
        server_api_key: Optional[str],
        inject_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/") + "/"  # normalize trailing slash
        self.server_api_key = server_api_key
        self.inject_headers = inject_headers or {}
        self.reverse_proxy = ReverseHttpProxy(client=_httpx_client, base_url=self.base_url)

    @staticmethod
    def sanitize_headers(headers: HttpHeaders) -> HttpHeaders:
        """Drop hop-by-hop headers & ones that must be set by httpx/target.
        RFC 7230: Connection, Keep-Alive, Proxy-*, TE, Trailer, Upgrade.
        Also drop Host & Content-Length so httpx sets them correctly.
        """
        drop = {
            b"connection",
            b"proxy-connection",
            b"keep-alive",
            b"transfer-encoding",
            b"upgrade",
            b"te",
            b"trailer",
            b"proxy-authenticate",
            b"proxy-authorization",
            b"host",
            b"content-length",
        }
        cleaned: HttpHeaders = []
        for k, v in headers:
            if k.lower() in drop:
                continue
            cleaned.append((k, v))
        return cleaned

    def patch_headers(self, headers: HttpHeaders, client_token: Optional[str] = None) -> HttpHeaders:
        """Adaptive Authorization header handling:
        - If client_token is None: use server API key as Authorization.
        - If client_token starts with monitel: treat as private token; do not forward it upstream, use server API key.
        - Otherwise: treat client_token as upstream API key and forward it as Authorization: Bearer <token>.
        Upstream-specific inject_headers are still added if not set by the client.
        """
        def set_header(hdrs: HttpHeaders, name: str, value: str) -> HttpHeaders:
            lname = name.lower().encode()
            new: HttpHeaders = []
            found = False
            for k, v in hdrs:
                if k.lower() == lname:
                    if not found:
                        new.append((k, value.encode()))
                        found = True
                    # skip duplicates
                else:
                    new.append((k, v))
            if not found:
                new.append((lname, value.encode()))
            return new

        patched = headers

        # Authorization: decide based on client_token
        if client_token is None:
            # No client token provided -> use server-side API key
            if not self.server_api_key:
                raise HTTPException(status_code=500, detail=f"Server {self.name.upper()}_API_KEY not configured")
            patched = set_header(patched, "authorization", f"Bearer {self.server_api_key}")
        else:
            if isinstance(client_token, str) and client_token.startswith("monitel:"):
                # Private key: do not forward, use server key
                if not self.server_api_key:
                    raise HTTPException(status_code=500, detail=f"Server {self.name.upper()}_API_KEY not configured")
                patched = set_header(patched, "authorization", f"Bearer {self.server_api_key}")
            else:
                # Treat client_token as upstream API key and forward it
                patched = set_header(patched, "authorization", f"Bearer {client_token}")

        # Upstream-specific headers (e.g., OpenRouter attribution)
        for k, v in self.inject_headers.items():
            # Do not overwrite if client already set
            lname = k.lower().encode()
            if not any(hk.lower() == lname for hk, _ in patched):
                patched = set_header(patched, k, v)

        return patched

    def normalize_path(self, raw_path: str) -> Tuple[str, str]:
        """Return (proxied_path, target_url_for_logs).
        Avoid duplicate prefixes like /v1/v1 or /api/v1/api/v1.
        """
        path = raw_path.lstrip("/") if raw_path else ""
        base_no_slash = self.base_url.rstrip("/")

        # If base ends with /v1 or /api/v1 and path starts with same segment, strip it once
        if base_no_slash.endswith("/v1") and (path.startswith("v1/") or path == "v1"):
            path = path[3:].lstrip("/")
        if base_no_slash.endswith("/api/v1") and (path.startswith("api/v1/") or path == "api/v1"):
            path = path[6:].lstrip("/")

        target_url = f"{base_no_slash}/{path}" if path else self.base_url
        return path, target_url


# Shared httpx client / timeouts
_httpx_timeout = httpx.Timeout(
    connect=settings.HTTP_TIMEOUT_CONNECT,
    read=settings.HTTP_TIMEOUT_READ,
    write=settings.HTTP_TIMEOUT_WRITE,
    pool=settings.HTTP_TIMEOUT_POOL,
)
_httpx_client = httpx.AsyncClient(timeout=_httpx_timeout, http2=settings.HTTP2_ENABLED)


# Compose upstreams
openai_upstream = Upstream(
    name="openai",
    base_url=settings.OPENAI_BASE_URL,
    server_api_key=settings.OPENAI_API_KEY,
)

openrouter_upstream = Upstream(
    name="openrouter",
    base_url=settings.OPENROUTER_BASE_URL,
    server_api_key=settings.OPENROUTER_API_KEY,
    inject_headers={
        **({"HTTP-Referer": settings.OPENROUTER_HTTP_REFERER} if settings.OPENROUTER_HTTP_REFERER else {}),
        **({"X-Title": settings.OPENROUTER_X_TITLE} if settings.OPENROUTER_X_TITLE else {}),
    },
)

UPSTREAMS: Dict[str, Upstream] = {
    "openai": openai_upstream,
    "openrouter": openrouter_upstream,
}


def _pick_upstream(request: Request, explicit: Optional[str] = None) -> Upstream:
    if explicit:
        key = explicit.lower()
        if key not in UPSTREAMS:
            raise HTTPException(status_code=400, detail=f"Unknown upstream '{explicit}'")
        return UPSTREAMS[key]

    # header-based override
    if settings.ALLOW_UPSTREAM_HEADER:
        hdr = request.headers.get("x-upstream")
        if hdr:
            key = hdr.strip().lower()
            if key in UPSTREAMS:
                return UPSTREAMS[key]
            raise HTTPException(status_code=400, detail=f"Unsupported x-upstream: {hdr}")

    # default
    return UPSTREAMS.get(settings.UPSTREAM_DEFAULT.lower(), openai_upstream)


@app.on_event("shutdown")
async def _shutdown_httpx_client():
    try:
        await _httpx_client.aclose()
    except Exception:
        pass


# =====================================================
# Admin & health
# =====================================================
@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/_meta/upstreams")
async def upstreams_meta():
    return {
        name: {
            "base_url": u.base_url,
            "server_key": bool(u.server_api_key),
        }
        for name, u in UPSTREAMS.items()
    }


@app.post("/admin/reload-clients")
async def reload_clients(request: Request):
    admin_token = os.getenv("ADMIN_TOKEN")
    if request.headers.get("x-admin-token") != admin_token or not admin_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    global _client_tokens, _client_allowed_models
    _client_tokens, _client_allowed_models = _load_clients(settings.CLIENTS_FILE)
    return {"reloaded": len(_client_tokens)}


# =====================================================
# Core proxy handler
# =====================================================
async def _proxy(request: Request, raw_path: str, upstream_name: Optional[str] = None):
    start = time.perf_counter()

    # Validate client auth (your proxy's client tokens)
    token = await _require_client(request)

    # Choose upstream
    upstream = _pick_upstream(request, explicit=upstream_name)

    # Prepare headers for upstream
    headers: HttpHeaders = list(request.scope.get("headers", []))

    # Model filter for private monitel tokens
    model = request.query_params.get("model")
    if isinstance(token, str) and token.startswith("monitel:") and token in _client_allowed_models:
        allowed_models = _client_allowed_models.get(token, set())
        if model:
            # Case-insensitive comparison for robustness
            allowed_lower = {m.lower() for m in allowed_models}
            if model.lower() not in allowed_lower:
                logger.warning("forbidden model attempt: %s by client %s", model, _redact(token))
                try:
                    await _log(
                        {
                            "ts": int(time.time() * 1000),
                            "method": request.method,
                            "path": f"/{raw_path}",
                            "upstream": upstream.name,
                            "status": 403,
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "client_token": _redact(token),
                            "reason": "model not allowed",
                            "model": model,
                        }
                    )
                except Exception:
                    pass
                raise HTTPException(status_code=403, detail="Model not allowed")

    patched_headers = upstream.patch_headers(headers, token)

    # Create new Request with modified headers
    scope = dict(request.scope)
    scope["headers"] = patched_headers
    patched_request = StarletteRequest(scope, request.receive)

    # Normalize path and compute target URL for logs
    proxied_path, target_url = upstream.normalize_path(raw_path)
    logger.info("[%s] proxying %s -> %s", upstream.name, request.method, target_url)

    try:
        response = await upstream.reverse_proxy.proxy(request=patched_request, path=proxied_path)
    except httpx.ReadTimeout:
        logger.warning("upstream read timeout while proxying [%s] %s", upstream.name, raw_path)
        raise HTTPException(status_code=504, detail="Upstream read timeout")
    except Exception:
        logger.exception("proxy error while handling [%s] %s", upstream.name, raw_path)
        raise HTTPException(status_code=502, detail="Upstream error")

    # If error status, try to preview body for diagnostics
    try:
        status = getattr(response, "status_code", None)
        if status and status >= 400:
            body_preview = None
            try:
                body = getattr(response, "body", None)
                if body is None:
                    body_preview = "<streaming or no body>"
                else:
                    if isinstance(body, (bytes, bytearray)):
                        body_preview = body.decode(errors="replace")[:1000]
                    else:
                        body_preview = str(body)[:1000]
            except Exception as e:
                body_preview = f"<body read failed: {e}>"
            logger.warning("upstream response %s for [%s] %s -> %s : %s", status, upstream.name, raw_path, target_url, body_preview)
    except Exception:
        pass

    # Access log
    try:
        client_auth = request.headers.get("authorization")
        # Determine adaptive mode for logging
        if token is None:
            mode = "adaptive:server-key"
        elif isinstance(token, str) and token.startswith("monitel:"):
            mode = "adaptive:monitel"
        else:
            mode = "adaptive:pass-through"
        await _log(
            {
                "ts": int(time.time() * 1000),
                "method": request.method,
                "path": f"/{raw_path}",
                "upstream": upstream.name,
                "status": getattr(response, "status_code", None),
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "client_auth": _redact(client_auth) if client_auth else None,
                "mode": mode,
            }
        )
    except Exception:
        pass

    return response


# =====================================================
# Routes
# =====================================================
# 1) Backward-compatible: client points SDK base_url to /v1 and chooses upstream via header `x-upstream`
@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_v1(request: Request, path: str = ""):
    return await _proxy(request, f"v1/{path}" if path else "v1", None)


# 2) Explicit OpenAI path (optional convenience)
@app.api_route("/openai/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_openai(request: Request, path: str = ""):
    # Allows base_url like "/openai/v1" or "/openai/" — we pass raw path through
    return await _proxy(request, path, "openai")


# 3) Explicit OpenRouter path (optional convenience)
@app.api_route("/openrouter/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_openrouter(request: Request, path: str = ""):
    # Allows base_url like "/openrouter/api/v1" or "/openrouter/v1" — normalize accordingly
    return await _proxy(request, path, "openrouter")


# 4) Alias to support clients pointing directly to /api/v1/* (OpenRouter-style base path)
@app.api_route("/api/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_api_v1(request: Request, path: str = ""):
    # Always treat /api/v1/* as OpenRouter
    raw = f"api/v1/{path}" if path else "api/v1"
    return await _proxy(request, raw, "openrouter")



@app.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    return PlainTextResponse("User-agent: *Disallow: /")


@app.get("/")
async def root(request: Request):
    # Avoid returning 200 OK for scanner queries like /?dns=...
    if not settings.ROOT_ALLOW_QUERIES and request.query_params:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "message": "Reverse Proxy ready. Use /v1 (OpenAI-compatible). Choose upstream via x-upstream header or use /openai/* or /openrouter/* base URLs.",
        "default_upstream": settings.UPSTREAM_DEFAULT,
    }
