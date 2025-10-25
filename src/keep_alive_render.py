from datetime import datetime, time
from .settings import settings
from .utils import logger

# Europe/Moscow timezone handling
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:
    ZoneInfo = None  # Fallback to fixed UTC+3 if zoneinfo is unavailable

def _moscow_now():
    # Try real timezone first; if tzdata missing or ZoneInfo raises -> fallback to fixed UTC+3
    try:
        if ZoneInfo is not None:
            return datetime.now(ZoneInfo("Europe/Moscow"))
    except Exception:
        pass
    # Fallback: fixed offset (MSK UTC+3, no DST)
    from datetime import timezone, timedelta
    return datetime.now(timezone(timedelta(hours=3)))

def _within_hours_msk(start_hour: int, end_hour: int) -> bool:
    """Return True when current time in MSK is within [start_hour, end_hour)."""
    now_t = _moscow_now().time()
    return time(hour=start_hour) <= now_t < time(hour=end_hour)

async def _keepalive_ping_loop():
    asyncio = __import__("asyncio")
    url = settings.KEEPALIVE_PING_URL
    url2 = settings.KEEPALIVE_PING_URL2
    interval = int(getattr(settings, "KEEPALIVE_PING_INTERVAL_SECONDS", 60) or 60)
    timeout = float(getattr(settings, "KEEPALIVE_PING_TIMEOUT", 10.0) or 10.0)

    # minimal sane lower bound
    if interval < 15:
        interval = 15

    while True:
        try:
            if settings.KEEPALIVE_PING_ENABLED:
                # URL1: ping 08:00 <= MSK < 23:00 (guard time-window exceptions to not block URL2)
                if url:
                    try:
                        if _within_hours_msk(9, 22):
                            health_url = f"{url}/health"
                            await ping(asyncio, timeout, health_url)
                    except Exception as e:
                        logger.warning(f"keepalive time-window check failed: {e}")

                # URL2: always attempt when configured (independent from URL1 result)
                if url2:
                    health_url2 = f"{url2}/healthz"
                    await ping(asyncio, timeout, health_url2)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Swallow any unexpected error to keep the loop alive
            pass
        finally:
            try:
                await asyncio.sleep(interval)
            except Exception:
                # If sleep fails for some reason, do not tight-loop
                pass

async def ping(asyncio, timeout, health_url):
    try:
                # Prefer shared client; fallback to short-lived client
        try:
            from .upstreams import _httpx_client as _client
            resp = await _client.get(health_url, timeout=timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            httpx = __import__("httpx")
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(health_url, timeout=timeout)
        logger.info(f"[{datetime.now()}]keepalive ping {health_url} ->{getattr(resp, 'status_code', None)}")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(f"keepalive ping failed: {e}")