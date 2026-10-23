"""HTTP API over BackendService (Student 2, S2-T1 API behavior catalog).

Every response carries the correlation ID in the body and in the
X-Correlation-ID header (NFR-02). Errors use the stable categories in
errors.py; unexpected exceptions become a bare INTERNAL error, so no path or
stack trace leaves the process (SR-11, US-02).

The app is built by create_app(service, authenticator); tests drive it with
FastAPI's TestClient. There is no deployable entry point in this phase.
"""
from __future__ import annotations

import json
import re
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .auth import ANONYMOUS, Authenticator
from .errors import ApiError
from .service import BackendService

CID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")


def _cid(request: Request) -> str:
    cid = getattr(request.state, "cid", None)
    if cid:
        return cid
    given = request.headers.get("X-Correlation-ID", "")
    cid = given if CID_RE.match(given) else uuid.uuid4().hex
    request.state.cid = cid
    return cid


def create_app(service: BackendService, authenticator: Authenticator) -> FastAPI:
    app = FastAPI(title="SecureOTA-V OEM backend (Phase 2 prototype)",
                  docs_url=None, redoc_url=None, openapi_url=None)
    limit = service.max_artifact_bytes

    def reply(request: Request, body, status: int = 200) -> JSONResponse:
        cid = _cid(request)
        payload = dict(body, correlation_id=cid) if isinstance(body, dict) else body
        return JSONResponse(payload, status_code=status, headers={"X-Correlation-ID": cid})

    @app.exception_handler(ApiError)
    async def api_error(request: Request, err: ApiError):
        return reply(request, err.public(_cid(request)), err.status)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, _err: Exception):
        err = ApiError("INTERNAL")
        return reply(request, err.public(_cid(request)), err.status)

    def principal(request: Request):
        header = request.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else None
        try:
            return authenticator.authenticate(token)
        except ApiError:
            service.audit.record(actor=ANONYMOUS.name, action="authenticate",
                                 obj=request.url.path, outcome="UNAUTHENTICATED",
                                 correlation_id=_cid(request))
            raise

    async def body_bytes(request: Request) -> bytes:
        declared = request.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ApiError("PAYLOAD_TOO_LARGE", "ARTIFACT_TOO_LARGE")
        data = await request.body()
        if len(data) > limit:
            raise ApiError("PAYLOAD_TOO_LARGE", "ARTIFACT_TOO_LARGE")
        return data

    async def body_json(request: Request):
        try:
            return json.loads(await body_bytes(request))
        except (ValueError, UnicodeDecodeError):
            raise ApiError("VALIDATION_FAILED", "MALFORMED_JSON") from None

    @app.get("/health")
    def health(request: Request):
        return reply(request, {"status": "ok"})

    @app.post("/vehicles")
    async def register(request: Request):
        p = principal(request)
        return reply(request, service.register_vehicle(p, await body_json(request),
                                                       _cid(request)), 201)

    @app.post("/artifacts")
    async def upload(request: Request, ecu_id: str = "", hardware_id: str = ""):
        p = principal(request)
        return reply(request, service.upload_artifact(p, await body_bytes(request), ecu_id,
                                                      hardware_id, _cid(request)), 201)

    @app.post("/releases")
    async def create_release(request: Request):
        p = principal(request)
        return reply(request, service.create_release(p, await body_json(request),
                                                     _cid(request)), 201)

    @app.post("/releases/{release_id}/approve")
    def approve(request: Request, release_id: str):
        return reply(request, service.approve_release(principal(request), release_id,
                                                      _cid(request)))

    @app.post("/campaigns")
    async def create_campaign(request: Request):
        p = principal(request)
        return reply(request, service.create_campaign(p, await body_json(request),
                                                      _cid(request)), 201)

    @app.post("/campaigns/{campaign_id}/start")
    def start(request: Request, campaign_id: str):
        return reply(request, service.start_campaign(principal(request), campaign_id,
                                                     _cid(request)))

    @app.post("/campaigns/{campaign_id}/pause")
    def pause(request: Request, campaign_id: str):
        return reply(request, service.pause_campaign(principal(request), campaign_id,
                                                     _cid(request)))

    @app.get("/campaigns/{campaign_id}/status")
    def status(request: Request, campaign_id: str):
        return reply(request, service.campaign_status(principal(request), campaign_id,
                                                      _cid(request)))

    @app.get("/vehicles/{vehicle_id}/instructions")
    def instructions(request: Request, vehicle_id: str):
        return reply(request, service.get_instructions(principal(request), vehicle_id,
                                                       _cid(request)))

    @app.get("/artifacts/{artifact_id}")
    def download(request: Request, artifact_id: str):
        data = service.download_artifact(principal(request), artifact_id, _cid(request))
        return Response(data, media_type="application/octet-stream",
                        headers={"X-Correlation-ID": _cid(request)})

    @app.post("/vehicles/{vehicle_id}/events")
    async def events(request: Request, vehicle_id: str):
        p = principal(request)
        return reply(request, service.report_event(p, vehicle_id, await body_json(request),
                                                   _cid(request)))

    @app.post("/vehicles/{vehicle_id}/manifest")
    async def manifest(request: Request, vehicle_id: str):
        p = principal(request)
        return reply(request, service.submit_manifest(p, vehicle_id, await body_json(request),
                                                      _cid(request)))

    @app.get("/audit")
    def audit(request: Request, actor: str = "", action: str = "", correlation_id: str = ""):
        filters = {k: v for k, v in (("actor", actor), ("action", action),
                                     ("correlation_id", correlation_id)) if v}
        return reply(request, service.query_audit(principal(request), _cid(request), **filters))

    return app
