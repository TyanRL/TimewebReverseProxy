from datetime import datetime
from .settings import settings
from .utils import logger

async def _keepalive_ping_loop():
    asyncio = __import__("asyncio")
    url = settings.KEEPALIVE_PING_URL
    interval = int(getattr(settings, "KEEPALIVE_PING_INTERVAL_SECONDS", 60) or 60)
    timeout = float(getattr(settings, "KEEPALIVE_PING_TIMEOUT", 10.0) or 10.0)

    # minimal sane lower bound
    if interval < 15:
        interval = 15

    while True:
        if settings.KEEPALIVE_PING_ENABLED and url:
            try:
                # Prefer shared client; fallback to short-lived client
                try:
                    from .upstreams import _httpx_client as _client
                    resp = await _client.get(url, timeout=timeout)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    httpx = __import__("httpx")
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        resp = await client.get(url, timeout=timeout)
                logger.info(f"[{datetime.now()}]keepalive ping {url} ->{getattr(resp, "status_code", None)}")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"keepalive ping failed: {e}")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass