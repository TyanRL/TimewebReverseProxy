import json
import logging
import sys
import queue
from logging.handlers import QueueHandler, QueueListener
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException, Request #type: ignore

from .settings import settings

# Ensure log directory exists
Path(settings.LOG_JSONL_PATH).parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("proxy")
logger.setLevel(logging.INFO)
logger.propagate = False

# Non-blocking logging via queue to reduce sync stdout I/O
_log_queue = queue.Queue(-1)
_stream_handler = logging.StreamHandler(sys.stdout)
_queue_handler = QueueHandler(_log_queue)
_queue_listener = QueueListener(_log_queue, _stream_handler, respect_handler_level=True)

# Avoid duplicate handlers on reload
logger.handlers.clear()
logger.addHandler(_queue_handler)
try:
    _queue_listener.start()
except Exception:
    # Fallback to direct stream handler if QueueListener fails
    logger.addHandler(_stream_handler)


def _csv_list(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x and x.strip()]


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

    METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")

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


if settings.ACCESS_LOG_NOISE_FILTER:
    try:
        logging.getLogger("uvicorn.access").addFilter(AccessLogNoiseFilter())
    except Exception:
        pass


def _redact(v: Optional[str]) -> Optional[str]:
    if not v:
        return v
    if len(v) <= 8:
        return "***"
    return v[:4] + "…" + v[-2:]


async def _log(record: Dict):
#    try:
#        with open(settings.LOG_JSONL_PATH, "a", encoding="utf-8") as f:
#            f.write(json.dumps(record, ensure_ascii=False) + "\n")
#    except Exception as e:
#        logger.error(f"log write failed: {e}")
    pass