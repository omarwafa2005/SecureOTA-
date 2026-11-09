#!/usr/bin/env python3
"""SecureOTA-V demo console server: the Phase 2 OEM API plus one simulated vehicle.

DEMO ONLY. It wires the same objects as phase2/tests/fleet.py (backend,
signing service, trust store, gateway, two A/B ECUs) into one process and
serves them to the web UI in console/web:

  /api/*    the unchanged Phase 2 OEM HTTP API (create_app), bearer tokens
  /demo/*   console helpers: per-run identities, a read-only catalog for OEM
            staff, the simulated vehicle (poll, activate, reboot, health
            check, attack scenarios) and a reset
  /         the built web UI (console/web/dist), when it exists

/demo/session hands out the per-run bearer tokens so the UI can switch roles.
That is why the server only listens on 127.0.0.1. Tokens and keys are random
per run and live in memory; nothing is written outside a temp directory.

Usage (from the repository root):  python console/server.py [--port 8000]
"""
from __future__ import annotations

import argparse
import copy
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Literal, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "phase2"))

from fastapi import FastAPI, Request                          # noqa: E402
from fastapi.responses import JSONResponse, Response         # noqa: E402
from fastapi.staticfiles import StaticFiles                  # noqa: E402
from pydantic import BaseModel                               # noqa: E402

from oem_backend.api import create_app                       # noqa: E402
from oem_backend.errors import ApiError                      # noqa: E402
from tests.fleet import PRINCIPALS, VEHICLE_ID, Fleet        # noqa: E402
from vehicle import Reason, VehicleConditions                # noqa: E402
from vehicle.ecu import SLOTS, SimulatedPowerLoss, UpdateState  # noqa: E402
from vehicle.testkit import ECU_HW, firmware                 # noqa: E402

Attack = Literal["tamper", "forge", "power_loss"]
STAFF = [k for k, p in PRINCIPALS.items() if "vehicle" not in p.roles]


def new_cid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Demo:
    """One fresh fleet per run (and per reset)."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="secureota-console-")
        self.fleet = Fleet(self._tmp.name)
        self.api = create_app(self.fleet.backend, self.fleet.auth)
        self.offers: dict[str, dict] = {}   # ecu_id -> current campaign assignment on the vehicle

    def close(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------ helpers
    def restart_vehicle(self) -> None:
        """Power cycle: rebuild gateway and ECUs from what is on disk."""
        self.fleet.bench.restart()
        self.fleet.gateway = self.fleet.make_gateway()

    def report(self, ecu_id: str, outcome: str, cid: str, reason: str = "") -> dict:
        offer = self.offers.get(ecu_id)
        if offer is None:
            return {"skipped": "NO_ASSIGNMENT"}
        try:
            return self.fleet.report(offer["campaign_id"], ecu_id, outcome,
                                     offer["metadata_version"], cid, reason[:64])
        except ApiError as err:
            return err.public(cid)

    def sync_manifest(self, cid: str) -> dict:
        f = self.fleet
        try:
            return f.backend.submit_manifest(f.p["vehicle"], VEHICLE_ID,
                                             f.gateway.build_manifest(cid), cid)
        except ApiError as err:
            return err.public(cid)

    def ecu(self, ecu_id: str):
        ecu = self.fleet.bench.ecus.get(ecu_id)
        if ecu is None:
            raise ApiError("NOT_FOUND", "UNKNOWN_ECU")
        return ecu

    # ------------------------------------------------------------ views
    def catalog(self) -> dict:
        db = copy.deepcopy(self.fleet.backend._db)
        vehicles = [{"vehicle_id": v["vehicle_id"], "manifest_key_id": v["manifest_key_id"],
                     "ecus": [{"ecu_id": k, **e} for k, e in sorted(v["ecus"].items())]}
                    for v in db["vehicles"].values()]
        return {"vehicles": vehicles,
                "artifacts": list(db["artifacts"].values()),
                "releases": list(db["releases"].values()),
                "campaigns": list(db["campaigns"].values())}

    def vehicle(self) -> dict:
        ecus = []
        for ecu_id, ecu in sorted(self.fleet.bench.ecus.items()):
            slots = {}
            for slot in SLOTS:
                rec = ecu.slot_record(slot)
                slots[slot] = rec and {"version": rec["version"], "sha256": rec["sha256"],
                                       "length": rec["length"], "valid": ecu.slot_image_valid(slot)}
            ecus.append({**ecu.report(), "confirmed_slot": ecu.confirmed_slot,
                         "boot_attempts": ecu.boot_attempts, "slots": slots,
                         "offer": self.offers.get(ecu_id)})
        events = self.fleet.bench.audit.events[-60:][::-1]
        return {"vehicle_id": VEHICLE_ID, "ecus": ecus, "events": events}

    # ------------------------------------------------------------ vehicle actions
    def poll(self, attack: Optional[str]) -> dict:
        """Gateway pulls instructions, verifies, downloads and stages (UC-05..07)."""
        f = self.fleet
        cid = new_cid("veh")
        instr = f.backend.get_instructions(f.p["vehicle"], VEHICLE_ID, cid)
        fetch = f.backend.fetcher(f.p["vehicle"], cid)
        if attack == "tamper":
            fetch = _tampered(fetch)
        if attack == "power_loss":
            f.bench.fail_at.add("stage:mid_write")
        results = []
        try:
            for bundle in instr["bundles"]:
                if attack == "forge":
                    bundle = _forged(bundle)
                try:
                    outcome = f.gateway.process_bundle(bundle, fetch, cid)
                except SimulatedPowerLoss as loss:
                    self.restart_vehicle()
                    results.append({"campaign_id": bundle["campaign_id"], "ecu_id": "*",
                                    "status": "POWER_LOSS", "reason": str(loss),
                                    "correlation_id": cid})
                    continue
                for env in bundle["targets"]:
                    signed = env["signed"]
                    ecu_id = signed["ecu_id"]
                    r = outcome.get(ecu_id) or outcome["*"]
                    self.offers[ecu_id] = {"campaign_id": bundle["campaign_id"],
                                           "metadata_version": signed["metadata_version"],
                                           "version": signed["version"]}
                    backend = self.report(ecu_id, "STAGED" if r.ok else "REJECTED", cid,
                                          "" if r.ok else r.reason.value)
                    if not r.ok:
                        self.offers.pop(ecu_id)
                    results.append({"campaign_id": bundle["campaign_id"], "ecu_id": ecu_id,
                                    "version": signed["version"], **r.public(),
                                    "backend": backend})
        finally:
            f.bench.fail_at.clear()
        return {"correlation_id": cid, "results": results,
                "manifest": self.sync_manifest(cid)}

    def activate(self, ecu_id: str, conditions: VehicleConditions) -> dict:
        self.ecu(ecu_id)
        cid = new_cid("veh")
        r = self.fleet.gateway.activate(ecu_id, conditions, cid)
        backend = None
        if r.ok:
            backend = self.report(ecu_id, "INSTALLED", cid)
        elif r.reason is Reason.ACTIVATION_POSTPONED:
            backend = self.report(ecu_id, "POSTPONED", cid, ",".join(r.detail))
        return {**r.public(), "blockers": list(r.detail), "backend": backend,
                "manifest": self.sync_manifest(cid)}

    def boot(self, ecu_id: str) -> dict:
        ecu = self.ecu(ecu_id)
        cid = new_cid("veh")
        slot = ecu.boot(cid)
        backend = None
        if ecu.update_state is UpdateState.ROLLED_BACK and ecu_id in self.offers:
            backend = self.report(ecu_id, "ROLLED_BACK", cid, "BOOT_FAILED")
            self.offers.pop(ecu_id)
        return {"status": "OK", "running_slot": slot, "update_state": ecu.update_state.value,
                "boot_attempts": ecu.boot_attempts, "correlation_id": cid, "backend": backend,
                "manifest": self.sync_manifest(cid)}

    def confirm(self, ecu_id: str, healthy: bool) -> dict:
        ecu = self.ecu(ecu_id)
        cid = new_cid("veh")
        r = ecu.confirm_health(healthy, cid)
        backend = None
        if r.ok:
            backend = self.report(ecu_id, "CONFIRMED", cid)
            self.offers.pop(ecu_id, None)
        elif r.reason is Reason.HEALTH_FAILED:
            backend = self.report(ecu_id, "ROLLED_BACK", cid, r.reason.value)
            self.offers.pop(ecu_id, None)
        return {**r.public(), "backend": backend, "manifest": self.sync_manifest(cid)}


def _tampered(fetch):
    """Attacker on the download path flips one byte of the artifact (AT-01)."""
    def evil(artifact_id, sha256):
        first = True
        for chunk in fetch(artifact_id, sha256):
            if first and chunk:
                chunk = bytes([chunk[0] ^ 0xFF]) + chunk[1:]
                first = False
            yield chunk
    return evil


def _forged(bundle: dict) -> dict:
    """Attacker edits signed metadata (bumps the version) without the release key."""
    bundle = copy.deepcopy(bundle)
    for env in bundle["targets"]:
        env["signed"]["version"] += 100
    return bundle


# ---------------------------------------------------------------- HTTP layer
class Conditions(BaseModel):
    speed_kph: float = 0.0
    gear: str = "P"
    ignition: str = "ON"
    battery_v: float = 12.6
    diagnostic_session: bool = False


class ActivateBody(BaseModel):
    ecu_id: str
    conditions: Conditions = Conditions()


class EcuBody(BaseModel):
    ecu_id: str


class ConfirmBody(BaseModel):
    ecu_id: str
    healthy: bool


class PollBody(BaseModel):
    attack: Optional[Attack] = None


def build_app(dist: Optional[Path] = HERE / "web" / "dist") -> FastAPI:
    app = FastAPI(title="SecureOTA-V demo console", docs_url=None, redoc_url=None,
                  openapi_url=None)
    lock = threading.RLock()
    state = {"demo": Demo()}

    def demo() -> Demo:
        return state["demo"]

    async def api(scope, receive, send):
        await demo().api(scope, receive, send)

    @app.middleware("http")
    async def tick(request: Request, call_next):
        demo().fleet.clock.advance(1)       # simulated wall clock moves one second per request
        return await call_next(request)

    @app.exception_handler(ApiError)
    async def api_error(request: Request, err: ApiError):
        cid = getattr(request.state, "cid", None) or new_cid("con")
        return JSONResponse(err.public(cid), status_code=err.status,
                            headers={"X-Correlation-ID": cid})

    def staff(request: Request):
        """Catalog readers: any authenticated OEM identity, never a vehicle. Audited."""
        f = demo().fleet
        cid = request.state.cid = new_cid("con")
        header = request.headers.get("Authorization", "")
        try:
            p = f.auth.authenticate(header[7:] if header.startswith("Bearer ") else None)
        except ApiError:
            f.backend.audit.record(actor="anonymous", action="view_catalog", obj="catalog",
                                   outcome="UNAUTHENTICATED", correlation_id=cid)
            raise
        if "vehicle" in p.roles:
            f.backend.audit.record(actor=p.name, action="view_catalog", obj="catalog",
                                   outcome="DENIED", correlation_id=cid)
            raise ApiError("FORBIDDEN")
        f.backend.audit.record(actor=p.name, action="view_catalog", obj="catalog",
                               outcome="SUCCESS", correlation_id=cid)
        return cid

    @app.get("/demo/session")
    def session():
        f = demo().fleet
        return {"vehicle_id": VEHICLE_ID, "ecu_hw": ECU_HW,
                "identities": [{"key": k, "name": PRINCIPALS[k].name,
                                "roles": sorted(PRINCIPALS[k].roles), "token": f.tokens[k]}
                               for k in STAFF]}

    @app.get("/demo/catalog")
    def catalog(request: Request):
        with lock:
            cid = staff(request)
            return {**demo().catalog(), "correlation_id": cid}

    @app.get("/demo/firmware")
    def demo_firmware(ecu_id: str, version: int):
        if ecu_id not in ECU_HW or not 1 <= version <= 9999:
            raise ApiError("VALIDATION_FAILED", "INVALID_FIRMWARE_REQUEST")
        return Response(firmware(ecu_id, version), media_type="application/octet-stream")

    @app.get("/demo/vehicle")
    def vehicle():
        with lock:
            return demo().vehicle()

    @app.post("/demo/vehicle/poll")
    def poll(body: PollBody):
        with lock:
            return demo().poll(body.attack)

    @app.post("/demo/vehicle/activate")
    def activate(body: ActivateBody):
        with lock:
            return demo().activate(body.ecu_id, VehicleConditions(**body.conditions.model_dump()))

    @app.post("/demo/vehicle/boot")
    def boot(body: EcuBody):
        with lock:
            return demo().boot(body.ecu_id)

    @app.post("/demo/vehicle/confirm")
    def confirm(body: ConfirmBody):
        with lock:
            return demo().confirm(body.ecu_id, body.healthy)

    @app.post("/demo/reset")
    def reset():
        with lock:
            old, state["demo"] = state["demo"], Demo()
            old.close()
            return {"status": "ok"}

    app.mount("/api", api)
    if dist is not None and dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="web")
    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    import uvicorn
    uvicorn.run(build_app(), host="127.0.0.1", port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
