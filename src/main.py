from datetime import datetime
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .keep_alive_render import _keepalive_ping_loop

from .settings import settings
from .utils import _csv_list, logger
from . import routes
from .upstreams import shutdown_httpx_client

import os
import asyncio
from contextlib import asynccontextmanager

# Cross-process singleton lock to ensure only one keepalive task across gunicorn workers
def _acquire_keepalive_singleton(lock_filename: str):
    try:
        import os, tempfile
        lock_dir = tempfile.gettempdir()
        lock_path = lock_filename if os.path.isabs(lock_filename) else os.path.join(lock_dir, lock_filename)
        if os.name == "nt":
            import msvcrt
            f = open(lock_path, "a+")
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    f.seek(0); f.truncate()
                    f.write(str(os.getpid()))
                    f.flush()
                except Exception:
                    pass
                return ("windows", f)
            except OSError:
                try:
                    f.close()
                except Exception:
                    pass
                return None
        else:
            import importlib
            from typing import Any
            fcntl = importlib.import_module("fcntl")  # type: ignore
            f = open(lock_path, "a+")
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                try:
                    f.seek(0); f.truncate()
                    f.write(str(os.getpid()))
                    f.flush()
                except Exception:
                    pass
                return ("posix", f)
            except OSError:
                try:
                    f.close()
                except Exception:
                    pass
                return None
    except Exception as e:
        logger.warning(f"keepalive singleton acquire failed: {e}")
        return None

def _release_keepalive_singleton(lock):
    try:
        if not lock:
            return
        kind, handle = lock
        if kind == "windows":
            import msvcrt
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
            try:
                handle.close()
            except Exception:
                pass
        else:
            import importlib
            from typing import Any
            fcntl = importlib.import_module("fcntl")  # type: ignore
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)  # type: ignore[attr-defined]
            except Exception:
                pass
            try:
                handle.close()
            except Exception:
                pass
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    preflight = os.getenv("PREFLIGHT") == "1"
    if (not preflight) and settings.KEEPALIVE_PING_ENABLED and settings.KEEPALIVE_PING_URL:
        try:
            # Ensure only one worker creates the keepalive task
            lock = _acquire_keepalive_singleton("keepalive-ping.lock")
            if lock:
                app.state._keepalive_lock = lock
                app.state._keepalive_task = asyncio.create_task(_keepalive_ping_loop())
                logger.info(f"[{datetime.now()}] keepalive ping enabled (singleton): {settings.KEEPALIVE_PING_URL} and {settings.KEEPALIVE_PING_URL2} every {settings.KEEPALIVE_PING_INTERVAL_SECONDS}")
            else:
                logger.info(f"[{datetime.now()}] keepalive ping skipped in this worker (lock held by another process)")
        except Exception as e:
            logger.error(f"failed to start keepalive task: {e}")
    # Yield control to application
    try:
        yield
    finally:
        # Shutdown: stop keepalive task
        task = getattr(app.state, "_keepalive_task", None)
        if task:
            task.cancel()
            try:
                await task
            except Exception:
                pass
        # Release singleton lock if held
        lock = getattr(app.state, "_keepalive_lock", None)
        try:
            _release_keepalive_singleton(lock)
        except Exception:
            pass
        # Shutdown shared httpx client(s)
        await shutdown_httpx_client()


app = FastAPI(title="Multi-Upstream Reverse Proxy (OpenAI + OpenRouter)", lifespan=lifespan)

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


# Register routes from module
routes.register_routes(app)
