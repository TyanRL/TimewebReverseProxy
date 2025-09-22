import json
from pathlib import Path
from typing import Dict, Optional, Tuple, Set

from fastapi import HTTPException, Request #type: ignore

from .settings import settings
from .utils import logger

_client_tokens: Set[str] = set()
_client_allowed_models: Dict[str, Set[str]] = {}


def load_clients(path: str) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """Public loader: parse clients.json and return (tokens, allowed_models)."""
    p = Path(path)
    if not p.exists():
        return set(), {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        tokens = set()
        allowed: Dict[str, Set[str]] = {}

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


def _initial_load() -> None:
    global _client_tokens, _client_allowed_models
    _client_tokens, _client_allowed_models = load_clients(settings.CLIENTS_FILE)


_initial_load()


def reload_clients() -> int:
    """Reload clients.json into module state. Returns number of tokens loaded."""
    global _client_tokens, _client_allowed_models
    tokens, allowed = load_clients(settings.CLIENTS_FILE)
    _client_tokens.clear()
    _client_tokens.update(tokens)
    _client_allowed_models.clear()
    _client_allowed_models.update(allowed)
    return len(_client_tokens)


def is_model_allowed(token: Optional[str], model: Optional[str]) -> bool:
    """Return True if the token is allowed to use the given model.
    If token is not a private monitel token or there is no allowlist for it, return True.
    """
    if not token or not isinstance(token, str):
        return True
    if not token.startswith("monitel:"):
        return True
    # If token present in mapping, enforce model allowlist
    allowed = _client_allowed_models.get(token)
    if not allowed:
        return True
    if not model:
        return True
    try:
        return str(model).lower() in {m.lower() for m in allowed}
    except Exception:
        return True


async def require_client(request: Request) -> Optional[str]:
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