import time
from typing import Optional, Any, AsyncIterable, Iterable, cast

from fastapi import FastAPI, HTTPException, Request #type: ignore
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse #type: ignore

from .settings import settings
from .auth import require_client, reload_clients as auth_reload_clients, is_model_allowed
from .upstreams import UPSTREAMS, pick_upstream, shutdown_httpx_client, Upstream
from .utils import logger, _log, _redact


async def _proxy(request: Request, raw_path: str, upstream_name: Optional[str] = None):
    start = time.perf_counter()

    # Validate client auth (your proxy's client tokens)
    token = await require_client(request)

    # Choose upstream
    upstream = pick_upstream(request, explicit=upstream_name)

    # Prepare headers for upstream
    headers = list(request.scope.get("headers", []))

    # Model filter for private monitel tokens
    model = request.query_params.get("model")

    # Conditionally read body only for small JSON to detect model; keep streaming otherwise
    body_bytes = b""
    body_model = None
    try:
        content_type = request.headers.get("content-type", "").lower()
        is_json = "application/json" in content_type
        parse_limit = getattr(settings, "REQUEST_JSON_PARSE_MAX_BYTES", 65536)
        cl_header = request.headers.get("content-length")
        content_length = int(cl_header) if cl_header is not None and cl_header.isdigit() else None
        if is_json and content_length is not None and content_length <= parse_limit:
            body_bytes = await request.body()
            try:
                data = __import__("json").loads(body_bytes)
                if isinstance(data, dict):
                    body_model = data.get("model", None)
            except Exception:
                body_model = None
    except Exception:
        body_bytes = b""

    # prefer query param, fallback to body
    if not model and body_model:
        model = body_model

    try:
        # Use auth.is_model_allowed which encapsulates private-token model allowlists
        if not is_model_allowed(token, model):
            logger.warning("forbidden model attempt: %s by client %s", model, _redact(token))
            try:
                await _log(
                    {
                        "ts": int(time.time() * 1000),
                        "method": request.method,
                        "path": f"/{raw_path}",
                        "upstream": upstream.name,
                        "status": 403,
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "client_token": _redact(token),
                        "reason": "model not allowed",
                        "model": model,
                    }
                )
            except Exception:
                pass
            raise HTTPException(status_code=403, detail="Model not allowed")
    except Exception as e:
        # fail-closed on errors during model checks - log and reject
        logger.exception("model validation error for client %s, model %s: %s", _redact(token), model, str(e))
        try:
            await _log(
                {
                    "ts": int(time.time() * 1000),
                    "method": request.method,
                    "path": f"/{raw_path}",
                    "upstream": upstream.name,
                    "status": 500,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                    "client_token": _redact(token),
                    "reason": "model validation error",
                    "model": model,
                    "error": str(e),
                }
            )
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Internal server error during model validation")

    patched_headers = upstream.patch_headers(headers, token)

    # Create new Request with modified headers, replaying body we already read
    from starlette.requests import Request as StarletteRequest

    scope = dict(request.scope)
    scope["headers"] = patched_headers
    if body_bytes:
        async def _receive() -> dict:
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        patched_request = StarletteRequest(scope, _receive)
    else:
        patched_request = StarletteRequest(scope, request.receive)

    # Normalize path and compute target URL for logs
    proxied_path, target_url = upstream.normalize_path(raw_path)
    logger.info("[%s] proxying %s -> %s", upstream.name, request.method, target_url)

    try:
        response = await upstream.reverse_proxy.proxy(request=patched_request, path=proxied_path)
    except Exception as e:
        import httpx as _httpx
        if isinstance(e, _httpx.ReadTimeout):
            logger.warning("upstream read timeout while proxying [%s] %s", upstream.name, raw_path)
            raise HTTPException(status_code=504, detail="Upstream read timeout")
        logger.exception("proxy error while handling [%s] %s", upstream.name, raw_path)
        raise HTTPException(status_code=502, detail="Upstream error")

    # Wrap streaming body to gracefully handle HTTP/2 stream resets during iteration
    if hasattr(response, "body_iterator") and getattr(response, "body_iterator", None) is not None:
        orig_iterator = getattr(response, "body_iterator")

        async def _safe_stream():
            iterator: Any = orig_iterator() if callable(orig_iterator) else orig_iterator
            try:
                if hasattr(iterator, "__aiter__"):
                    async for chunk in cast(AsyncIterable[bytes], iterator):
                        yield chunk
                elif hasattr(iterator, "__iter__"):
                    for chunk in cast(Iterable[bytes], iterator):
                        yield chunk
                else:
                    # Unknown iterator type; nothing to stream
                    return
            except Exception as e:
                # Swallow only HTTP/2 stream reset errors from upstream
                try:
                    import httpx as __httpx  # type: ignore
                    if isinstance(e, __httpx.RemoteProtocolError):
                        logger.warning("HTTP/2 stream reset from upstream [%s] %s -> %s: %s", upstream.name, raw_path, target_url, e)
                        return
                except Exception:
                    pass
                try:
                    from httpcore import RemoteProtocolError as __HCRemoteProtocolError  # type: ignore
                    if isinstance(e, __HCRemoteProtocolError):
                        logger.warning("HTTP/2 stream reset from upstream [%s] %s -> %s: %s", upstream.name, raw_path, target_url, e)
                        return
                except Exception:
                    pass
                logger.exception("streaming error while proxying [%s] %s", upstream.name, raw_path)
                raise

        # Rebuild streaming response with preserved metadata
        hdrs = dict(getattr(response, "headers", {}) or {})
        # Prevent possible Content-Length mismatch if stream ends early
        for _k in list(hdrs.keys()):
            if _k.lower() == "content-length":
                hdrs.pop(_k, None)
                break

        response = StreamingResponse(
            _safe_stream(),
            status_code=getattr(response, "status_code", 200),
            headers=hdrs,
            media_type=getattr(response, "media_type", None),
            background=getattr(response, "background", None),
        )

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
        # Determine adaptive mode for logging
        if token is None:
            mode = "adaptive:server-key"
        elif isinstance(token, str) and token.startswith("monitel:"):
            mode = "adaptive:monitel"
        else:
            mode = "adaptive:pass-through"
        await _log(
            {
                "ts": int(time.time() * 1000),
                "method": request.method,
                "path": f"/{raw_path}",
                "upstream": upstream.name,
                "status": getattr(response, "status_code", None),
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "client_auth": _redact(client_auth) if client_auth else None,
                "mode": mode,
            }
        )
    except Exception:
        pass

    return response


def register_routes(app: FastAPI):
    # Admin & health
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
        admin_token = __import__("os").getenv("ADMIN_TOKEN")
        if request.headers.get("x-admin-token") != admin_token or not admin_token:
            raise HTTPException(status_code=401, detail="Unauthorized")
        reloaded = auth_reload_clients()
        return {"reloaded": reloaded}

    # Routes proxies
    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def proxy_v1(request: Request, path: str = ""):
        return await _proxy(request, f"v1/{path}" if path else "v1", None)

    @app.api_route("/openai/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def proxy_openai(request: Request, path: str = ""):
        return await _proxy(request, path, "openai")

    @app.api_route("/openrouter/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def proxy_openrouter(request: Request, path: str = ""):
        return await _proxy(request, path, "openrouter")

    @app.api_route("/api/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def proxy_api_v1(request: Request, path: str = ""):
        raw = f"api/v1/{path}" if path else "api/v1"
        return await _proxy(request, raw, "openrouter")

    @app.get("/robots.txt", include_in_schema=False)
    async def robots_txt():
        return PlainTextResponse("User-agent: *Disallow: /")

    @app.get("/")
    async def root(request: Request):
        # Avoid returning 200 OK for scanner queries like /?dns=...
        if not settings.ROOT_ALLOW_QUERIES and request.query_params:
            raise HTTPException(status_code=404, detail="Not found")
        return {
            "message": "Reverse Proxy ready. Use /v1 (OpenAI-compatible). Choose upstream via x-upstream header or use /openai/* or /openrouter/* base URLs.",
            "default_upstream": settings.UPSTREAM_DEFAULT,
        }