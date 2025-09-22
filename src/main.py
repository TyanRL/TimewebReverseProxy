from fastapi import FastAPI, Request, HTTPException #type: ignore
from fastapi.middleware.cors import CORSMiddleware #type: ignore
from fastapi.responses import JSONResponse #type: ignore

from .settings import settings
from .utils import _csv_list, logger
from . import routes
from .upstreams import shutdown_httpx_client

app = FastAPI(title="Multi-Upstream Reverse Proxy (OpenAI + OpenRouter)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ALLOW_ORIGINS.split(",") if o.strip()],
    allow_methods=[m.strip() for m in settings.CORS_ALLOW_METHODS.split(",") if m.strip()],
    allow_headers=[h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",") if h.strip()],
)

_ALLOW_PREFIXES = tuple(_csv_list(settings.ALLOWLIST_PREFIXES))
_ALLOW_EXACT = set(_csv_list(settings.ALLOWLIST_EXACT))


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
            return JSONResponse(status_code=settings.ALLOWLIST_DENY_CODE, content={"detail": settings.ALLOWLIST_DENY_MESSAGE})

    return await call_next(request)


@app.on_event("shutdown")
async def _shutdown_httpx_client():
    await shutdown_httpx_client()


# Register routes from module
routes.register_routes(app)
