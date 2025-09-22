import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple, Set

from fastapi import HTTPException, Request #type: ignore

from .settings import settings
from .utils import logger

_client_tokens: Set[str] = set()
_client_allowed_models: Dict[str, Set[str]] = {}


def load_clients_from_env() -> Tuple[Set[str], Dict[str, Set[str]]]:
    """Load clients from environment variables."""
    tokens = set()
    allowed_models = {}

    # Загрузка из CSV переменной CLIENT_TOKENS
    if settings.CLIENT_TOKENS:
        csv_tokens = [t.strip() for t in settings.CLIENT_TOKENS.split(',')]
        for token in csv_tokens:
            if token:
                tokens.add(token)
                # Поиск ограничений по моделям для этого токена
                for key, value in os.environ.items():
                    if key.startswith('CLIENT_TOKEN_') and key.endswith('_MODELS'):
                        token_key = key.replace('_MODELS', '')
                        env_token = os.environ.get(token_key)
                        if env_token == token:
                            models = [m.strip() for m in value.split(',')]
                            allowed_models[token] = set(models)
                            break

    # Загрузка из JSON переменной CLIENT_TOKENS_JSON (переопределение)
    if settings.CLIENT_TOKENS_JSON:
        try:
            data = json.loads(settings.CLIENT_TOKENS_JSON)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'token' in item:
                        token = item['token']
                        tokens.add(token)
                        if 'models' in item and isinstance(item['models'], list):
                            allowed_models[token] = set(item['models'])
        except Exception as e:
            logger.error(f"Failed to parse CLIENT_TOKENS_JSON: {e}")

    return tokens, allowed_models


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

    # Сначала загружаем из переменных окружения
    env_tokens, env_models = load_clients_from_env()

    # Затем из файла, если он существует
    file_tokens, file_models = set(), {}
    if settings.CLIENTS_FILE:
        file_tokens, file_models = load_clients(settings.CLIENTS_FILE)

    # Объединяем результаты (переменные окружения имеют приоритет)
    _client_tokens = env_tokens or file_tokens
    _client_allowed_models = {**file_models, **env_models}


_initial_load()


def reload_clients() -> int:
    """Reload clients from environment and file into module state. Returns number of tokens loaded."""
    global _client_tokens, _client_allowed_models

    # Загружаем из переменных окружения (всегда актуально)
    env_tokens, env_models = load_clients_from_env()

    # Загружаем из файла, если он существует
    file_tokens, file_models = set(), {}
    if settings.CLIENTS_FILE:
        file_tokens, file_models = load_clients(settings.CLIENTS_FILE)

    # Объединяем результаты (переменные окружения имеют приоритет)
    _client_tokens.clear()
    _client_tokens.update(env_tokens or file_tokens)
    _client_allowed_models.clear()
    _client_allowed_models.update({**file_models, **env_models})

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