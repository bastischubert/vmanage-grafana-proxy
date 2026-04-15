import asyncio
import logging
import os

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config — load from Docker secrets (_FILE variants) or plain env vars
# ---------------------------------------------------------------------------

def _read_secret(name: str) -> str:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        with open(file_path) as fh:
            return fh.read().strip()
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Required env var {name} (or {name}_FILE) is not set")
    return value


VMANAGE_HOST  = _read_secret("VMANAGE_HOST")    # e.g. https://vmanage.example.com
VMANAGE_USER  = _read_secret("VMANAGE_USER")
VMANAGE_PASS  = _read_secret("VMANAGE_PASS")
PROXY_TOKEN   = _read_secret("PROXY_BEARER_TOKEN")

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

_session_lock = asyncio.Lock()
_session: dict[str, str | None] = {"jsessionid": None, "xsrf_token": None}

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


async def _authenticate(client: httpx.AsyncClient) -> None:
    """Perform the two-step vManage login and store the resulting tokens."""
    logger.info("Authenticating to vManage at %s", VMANAGE_HOST)

    resp = await client.post(
        f"{VMANAGE_HOST}/j_security_check",
        data={"j_username": VMANAGE_USER, "j_password": VMANAGE_PASS},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=True,
    )
    resp.raise_for_status()

    jsessionid = client.cookies.get("JSESSIONID")
    if not jsessionid:
        raise RuntimeError(
            "Authentication failed: no JSESSIONID cookie returned — "
            "check credentials or vManage URL"
        )

    token_resp = await client.get(
        f"{VMANAGE_HOST}/dataservice/client/token",
        cookies={"JSESSIONID": jsessionid},
    )
    token_resp.raise_for_status()
    xsrf_token = token_resp.text.strip()

    _session["jsessionid"] = jsessionid
    _session["xsrf_token"] = xsrf_token
    logger.info("Authentication successful")


@app.middleware("http")
async def verify_proxy_token(request: Request, call_next):
    """Reject requests that don't carry the shared proxy bearer token."""
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {PROXY_TOKEN}":
        logger.warning("Unauthorized request from %s", request.client)
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return await call_next(request)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(path: str, request: Request) -> Response:
    """
    Forward any request to vManage's /dataservice/<path> endpoint.

    Grafana Infinity base URL: http://<this-proxy>:8080
    Panel URL field:           device/vedgeinventory/detail  (no leading slash)
    """
    async with httpx.AsyncClient(verify=True) as client:
        # Ensure we have a valid session before the first request
        async with _session_lock:
            if not _session["jsessionid"]:
                await _authenticate(client)

        async def _do_request() -> httpx.Response:
            return await client.request(
                method=request.method,
                url=f"{VMANAGE_HOST}/dataservice/{path}",
                params=dict(request.query_params),
                cookies={"JSESSIONID": _session["jsessionid"]},
                headers={"X-XSRF-TOKEN": _session["xsrf_token"]},
                content=await request.body(),
            )

        upstream = await _do_request()

        # Session expired — re-authenticate once, then retry
        if upstream.status_code in (401, 403):
            logger.info("Session expired, re-authenticating…")
            async with _session_lock:
                await _authenticate(client)
            upstream = await _do_request()

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}
