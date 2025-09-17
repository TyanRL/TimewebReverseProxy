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

# =====================================================
# Settings
# =====================================================
class Settings(BaseSettings):
    # --- Upstreams ---
    OPENAI_BASE_URL: str = "https://api.openai.com/v1/"  # keep trailing slash
    OPENAI_API_KEY: Optional[str] = None                 # used if FORWARD_CLIENT_AUTH=false

    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1/"  # keep trailing slash
    OPENROUTER_API_KEY: Optional[str] = None
    # Optional attribution headers recommended by OpenRouter
    # Docs: https://openrouter.ai/docs/api-reference/overview
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

    # If true, forward the client's Authorization header to the upstream as-is
    # If false, replace Authorization with server-side API key for the chosen upstream
    FORWARD_CLIENT_AUTH: bool = False

    # --- Logging ---
    LOG_JSONL_PATH: str = "logs/requests.jsonl"

    # --- CORS ---
    CORS_ALLOW_ORIGINS: str = "*"
    CORS_ALLOW_METHODS: str = "*"
    CORS_ALLOW_HEADERS: str = "*"

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

Path(settings.LOG_JSONL_PATH).parent.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("proxy")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

# =====================================================
# Client tokens
# =====================================================
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
    if token not in _client_tokens:
        raise HTTPException(status_code=403, detail="Invalid client token")
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

    def patch_headers(self, headers: HttpHeaders) -> HttpHeaders:
        """Replace or add Authorization and any upstream-specific headers
        when FORWARD_CLIENT_AUTH is disabled. Otherwise we leave Authorization as-is
        but still add optional attribution headers for OpenRouter if not present.
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

        # Authorization
        if not settings.FORWARD_CLIENT_AUTH:
            if not self.server_api_key:
                raise HTTPException(status_code=500, detail=f"Server {self.name.upper()}_API_KEY not configured")
            patched = set_header(patched, "authorization", f"Bearer {self.server_api_key}")

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
_httpx_timeout = httpx.Timeout(connect=10.0, read=120.0, write=120.0, pool=60.0)
_httpx_client = httpx.AsyncClient(timeout=_httpx_timeout)

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
    global _client_tokens
    _client_tokens = _load_tokens(settings.CLIENTS_FILE)
    return {"reloaded": len(_client_tokens)}


# =====================================================
# Core proxy handler
# =====================================================
async def _proxy(request: Request, raw_path: str, upstream_name: Optional[str] = None):
    start = time.perf_counter()

    # Validate client auth (your proxy's client tokens)
    await _require_client(request)

    # Choose upstream
    upstream = _pick_upstream(request, explicit=upstream_name)

    # Prepare headers for upstream
    headers: HttpHeaders = list(request.scope.get("headers", []))
    patched_headers = upstream.patch_headers(headers)

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
        await _log(
            {
                "ts": int(time.time() * 1000),
                "method": request.method,
                "path": f"/{raw_path}",
                "upstream": upstream.name,
                "status": getattr(response, "status_code", None),
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "client_auth": _redact(client_auth) if client_auth else None,
                "mode": "forward" if settings.FORWARD_CLIENT_AUTH else "server-key",
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


@app.get("/")
async def root():
    return {
        "message": "Reverse Proxy ready. Use /v1 (OpenAI-compatible). Choose upstream via x-upstream header or use /openai/* or /openrouter/* base URLs.",
        "default_upstream": settings.UPSTREAM_DEFAULT,
    }
