import httpx
from typing import Dict, List, Optional, Tuple
from fastapi import HTTPException, Request #type: ignore

from fastapi_proxy_lib.core.http import ReverseHttpProxy

from .settings import settings
from .utils import logger

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


# Shared httpx client / timeouts and limits
_httpx_timeout = httpx.Timeout(
    connect=settings.HTTP_TIMEOUT_CONNECT,
    read=settings.HTTP_TIMEOUT_READ,
    write=settings.HTTP_TIMEOUT_WRITE,
    pool=settings.HTTP_TIMEOUT_POOL,
)
_httpx_limits = httpx.Limits(
    max_keepalive_connections=settings.HTTP_MAX_KEEPALIVE_CONNECTIONS,
    max_connections=settings.HTTP_MAX_CONNECTIONS,
    keepalive_expiry=settings.HTTP_KEEPALIVE_EXPIRY,
)
_httpx_client = httpx.AsyncClient(
    timeout=_httpx_timeout,
    http2=settings.HTTP2_ENABLED,
    limits=_httpx_limits,
    trust_env=settings.HTTP_TRUST_ENV,
)


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


def pick_upstream(request: Request, explicit: Optional[str] = None) -> Upstream:
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


async def shutdown_httpx_client() -> None:
    try:
        await _httpx_client.aclose()
    except Exception:
        pass