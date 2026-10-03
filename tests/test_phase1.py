"""Automated Phase 1 tests (P1-01 .. P1-11).

Run from the repository root:
    python -m pytest -v
"""

import json
import sys
from pathlib import Path

import pytest
import requests
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend import app as backend_module  # noqa: E402
from ecu_simulator import ecu  # noqa: E402
from gateway import gateway  # noqa: E402

REQUIRED_FIELDS = ["ecu_id", "hardware_id", "version", "filename", "download_url"]
GOOD_UPDATE = {
    "ecu_id": "ECU-A",
    "hardware_id": "HW-A-01",
    "version": 2,
    "filename": "ecu_a_v2.bin",
    "download_url": "/firmware/ecu_a_v2.bin",
}


# ---------------------------------------------------------------- fixtures

@pytest.fixture
def api():
    return TestClient(backend_module.app)


@pytest.fixture
def ecu_env(tmp_path, monkeypatch):
    """Isolated ECU folders so tests never touch the real state.json."""
    monkeypatch.setattr(ecu, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(ecu, "SLOT_A_DIR", tmp_path / "slot_a")
    monkeypatch.setattr(ecu, "SLOT_B_DIR", tmp_path / "slot_b")
    assert ecu.reset_ecu()["success"]
    return tmp_path


@pytest.fixture
def firmware_file(tmp_path):
    path = tmp_path / "ecu_a_v2.bin"
    path.write_text(
        "SECUREOTA TEST FIRMWARE\nECU=ECU-A\nHARDWARE=HW-A-01\nVERSION=2\n"
        "MESSAGE=Hello from firmware version 2\n",
        encoding="utf-8",
    )
    return path


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json = json_data
        self.content = content

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


def make_fake_get(routes):
    """routes: {path: FakeResponse or Exception}"""

    def fake_get(url, timeout=None):
        path = url.replace(gateway.BASE_URL, "")
        outcome = routes[path]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return fake_get


def routes_ok(update=None):
    return {
        "/health": FakeResponse(json_data={"status": "ok"}),
        "/updates/ECU-A": FakeResponse(json_data=update or dict(GOOD_UPDATE)),
        "/firmware/ecu_a_v2.bin": FakeResponse(content=b"FIRMWARE V2"),
    }


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway, "DOWNLOAD_DIR", tmp_path / "downloads")
    return gateway


# ------------------------------------------------------------ backend tests

def test_p1_01_health(api):
    response = api.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_p1_02_update_info_has_required_fields(api):
    response = api.get("/updates/ECU-A")
    assert response.status_code == 200
    body = response.json()
    for field in REQUIRED_FIELDS:
        assert field in body
    assert body == GOOD_UPDATE


def test_firmware_endpoint_returns_non_empty_file(api):
    response = api.get("/firmware/ecu_a_v2.bin")
    assert response.status_code == 200
    assert len(response.content) > 0


def test_p1_07_unknown_ecu(api):
    response = api.get("/updates/ECU-Z")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_p1_08_firmware_missing_returns_404(api, monkeypatch, tmp_path):
    monkeypatch.setattr(backend_module, "FIRMWARE_FILE", tmp_path / "missing.bin")
    response = api.get("/firmware/ecu_a_v2.bin")
    assert response.status_code == 404
    assert str(tmp_path) not in response.text  # no local paths leaked


# -------------------------------------------------------------- gateway tests

def test_p1_03_valid_download(gw, monkeypatch):
    monkeypatch.setattr(gw.requests, "get", make_fake_get(routes_ok()))
    path = gw.download_firmware(dict(GOOD_UPDATE))
    assert path is not None
    assert path.read_bytes() == b"FIRMWARE V2"


def test_p1_06_backend_unavailable(gw, monkeypatch, capsys):
    routes = {"/health": requests.ConnectionError("down")}
    monkeypatch.setattr(gw.requests, "get", make_fake_get(routes))
    staged = []
    monkeypatch.setattr(gw, "stage_firmware", lambda p, v: staged.append(p))

    assert gw.main() == 1
    assert "Backend unavailable" in capsys.readouterr().out
    assert staged == []
    assert not (gw.DOWNLOAD_DIR / "ecu_a_v2.bin").exists()


@pytest.mark.parametrize("missing", REQUIRED_FIELDS)
def test_p1_09_incomplete_json_rejected(gw, missing):
    update = dict(GOOD_UPDATE)
    del update[missing]
    assert gw.validate_update_info(update) is False


def test_p1_08_gateway_firmware_404_no_staging(gw, monkeypatch):
    routes = routes_ok()
    routes["/firmware/ecu_a_v2.bin"] = FakeResponse(status_code=404)
    monkeypatch.setattr(gw.requests, "get", make_fake_get(routes))
    staged = []
    monkeypatch.setattr(gw, "stage_firmware", lambda p, v: staged.append(p))

    assert gw.main() == 1
    assert staged == []
    assert not (gw.DOWNLOAD_DIR / "ecu_a_v2.bin").exists()
    assert not list(gw.DOWNLOAD_DIR.glob("*.part"))


def test_gateway_rejects_filename_with_path(gw):
    update = dict(GOOD_UPDATE, filename="../evil.bin")
    assert gw.validate_update_info(update) is False


# ------------------------------------------------------------------ ECU tests

def test_p1_04_valid_staging_copies_to_slot_b(ecu_env, firmware_file):
    result = ecu.stage_firmware(firmware_file, 2)
    assert result["success"] is True
    staged = ecu_env / "slot_b" / "ecu_a_v2.bin"
    assert staged.read_bytes() == firmware_file.read_bytes()
    assert firmware_file.exists()  # source untouched


def test_p1_05_state_preserved_after_staging(ecu_env, firmware_file):
    ecu.stage_firmware(firmware_file, 2)
    state = json.loads((ecu_env / "state.json").read_text())
    assert state["active_slot"] == "A"
    assert state["installed_version"] == 1
    assert state["staged_version"] == 2
    assert (ecu_env / "slot_a" / "ecu_a_v1.bin").is_file()


def test_p1_10_missing_source_leaves_state_unchanged(ecu_env, tmp_path):
    before = (ecu_env / "state.json").read_text()
    result = ecu.stage_firmware(tmp_path / "does_not_exist.bin", 2)
    assert result["success"] is False
    assert (ecu_env / "state.json").read_text() == before
    assert not list((ecu_env / "slot_b").iterdir())


def test_reset_removes_staged_file(ecu_env, firmware_file):
    ecu.stage_firmware(firmware_file, 2)
    assert ecu.reset_ecu()["success"] is True
    state = json.loads((ecu_env / "state.json").read_text())
    assert state == ecu.INITIAL_STATE
    assert not list((ecu_env / "slot_b").iterdir())
    assert (ecu_env / "slot_a" / "ecu_a_v1.bin").is_file()


# --------------------------------------------------------- full integration

def test_p1_11_full_flow_repeats_after_reset(ecu_env, gw, api, monkeypatch):
    def backend_get(url, timeout=None):
        response = api.get(url.replace(gw.BASE_URL, ""))
        if response.status_code >= 400:
            return FakeResponse(status_code=response.status_code)
        if response.headers["content-type"].startswith("application/json"):
            return FakeResponse(json_data=response.json())
        return FakeResponse(content=response.content)

    monkeypatch.setattr(gw.requests, "get", backend_get)

    for _ in range(2):  # run, reset, run again -> same final state
        assert gw.main() == 0
        state = json.loads((ecu_env / "state.json").read_text())
        assert state["installed_version"] == 1
        assert state["active_slot"] == "A"
        assert state["staged_version"] == 2
        assert (ecu_env / "slot_b" / "ecu_a_v2.bin").is_file()
        assert ecu.reset_ecu()["success"] is True