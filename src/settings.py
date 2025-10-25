import os
from pydantic_settings import BaseSettings
from typing import Optional


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
    CLIENTS_FILE: Optional[str] = "clients.json"  # json: {"tokens":["..."]} or ["..."]
    ALLOW_BEARER_FROM_AUTH_HEADER: bool = True
    CLIENT_HEADER_NAME: str = "x-api-key"  # alternative header for client tokens

    # Environment-based client configuration
    CLIENT_TOKENS: Optional[str] = None  # CSV list of client tokens from env
    CLIENT_TOKENS_JSON: Optional[str] = None  # JSON string with client configs from env

    # Adaptive client auth:
    # If client token starts with monitel: it is a private key and must be present in clients.json.
    # Otherwise the token is treated as an upstream API key and will be forwarded to the upstream.

    # --- HTTP client timeouts & transport ---
    HTTP_TIMEOUT_CONNECT: float = 20.0
    HTTP_TIMEOUT_READ: float = 600.0
    HTTP_TIMEOUT_WRITE: float = 300.0
    HTTP_TIMEOUT_POOL: float = 120.0
    HTTP2_ENABLED: bool = True

    # Connection pool and environment behavior
    HTTP_MAX_KEEPALIVE_CONNECTIONS: int = 20
    HTTP_MAX_CONNECTIONS: int = 200
    HTTP_KEEPALIVE_EXPIRY: float = 20.0
    HTTP_TRUST_ENV: bool = False

    # --- Request parsing ---
    REQUEST_JSON_PARSE_MAX_BYTES: int = 65536

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
    # --- Keepalive ping ---
    KEEPALIVE_PING_ENABLED: bool = True
    KEEPALIVE_PING_URL: Optional[str] = "https://telegram-bot-xmj4.onrender.com"
    KEEPALIVE_PING_URL2: Optional[str] = "https://renderreverseproxy.onrender.com"
    KEEPALIVE_PING_INTERVAL_SECONDS: int = 50
    KEEPALIVE_PING_TIMEOUT: float = 10.0


    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
