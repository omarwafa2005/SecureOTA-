"""ECU-A simulator for SecureOTA-V Phase 1.

Models Slot A (active, Version 1), Slot B (inactive, receives updates) and a
persistent state.json file.

Public interface used by the gateway:
    stage_firmware(source_path, version) -> {"success": bool, "message": str}
    reset_ecu()                          -> {"success": bool, "message": str}

Command line (run from the repository root):
    python ecu_simulator/ecu.py reset
    python ecu_simulator/ecu.py status
"""

import json
import os
import shutil
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "state.json"
SLOT_A_DIR = BASE_DIR / "slot_a"
SLOT_B_DIR = BASE_DIR / "slot_b"
ACTIVE_FIRMWARE_NAME = "ecu_a_v1.bin"

INITIAL_STATE = {
    "ecu_id": "ECU-A",
    "hardware_id": "HW-A-01",
    "installed_version": 1,
    "active_slot": "A",
    "staged_version": None,
}

V1_FIRMWARE_CONTENT = (
    "SECUREOTA TEST FIRMWARE\n"
    "ECU=ECU-A\n"
    "HARDWARE=HW-A-01\n"
    "VERSION=1\n"
    "MESSAGE=Hello from firmware version 1\n"
)


def _result(success, message):
    return {"success": success, "message": message}


def _read_state():
    with open(STATE_FILE, "r", encoding="utf-8") as state_file:
        return json.load(state_file)


def _write_state(state):
    """Write state.json safely: temp file first, then atomic replace."""
    temp_file = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    with open(temp_file, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_file, STATE_FILE)


def _clear_slot_b():
    SLOT_B_DIR.mkdir(parents=True, exist_ok=True)
    for item in SLOT_B_DIR.iterdir():
        if item.is_file():
            item.unlink()


def stage_firmware(source_path, version):
    """Copy a downloaded firmware file into Slot B and record the version.

    Slot A stays active and installed_version is not touched.
    On any failure state.json is left unchanged.
    """
    if source_path is None:
        return _result(False, "Firmware path does not exist")

    source = Path(source_path)
    if not source.is_file():
        return _result(False, "Firmware path does not exist")

    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        return _result(False, "Invalid firmware version")

    try:
        state = _read_state()
    except (OSError, ValueError):
        return _result(False, "ECU state is missing or unreadable (run reset)")

    print("ECU-A received the firmware")

    SLOT_B_DIR.mkdir(parents=True, exist_ok=True)
    target = SLOT_B_DIR / f"ecu_a_v{version}.bin"
    temp_target = SLOT_B_DIR / (target.name + ".tmp")

    try:
        shutil.copyfile(source, temp_target)
        os.replace(temp_target, target)
    except OSError as error:
        if temp_target.exists():
            temp_target.unlink()
        return _result(False, f"Could not save firmware in Slot B: {error}")

    print("Firmware saved in Slot B")

    state["staged_version"] = version
    try:
        _write_state(state)
    except OSError as error:
        if target.exists():
            target.unlink()
        return _result(False, f"Could not update ECU state: {error}")

    # Slot B holds one staged image only.
    for item in SLOT_B_DIR.iterdir():
        if item.is_file() and item != target:
            item.unlink()

    print(f"Version {version} is staged")
    print("Slot A remains active")
    return _result(True, "Firmware staged in Slot B")


def reset_ecu():
    """Return ECU-A to the clean initial state (Version 1 active, Slot B empty)."""
    try:
        SLOT_A_DIR.mkdir(parents=True, exist_ok=True)
        active_file = SLOT_A_DIR / ACTIVE_FIRMWARE_NAME
        if not active_file.is_file():
            active_file.write_text(V1_FIRMWARE_CONTENT, encoding="utf-8")

        _clear_slot_b()
        _write_state(dict(INITIAL_STATE))
    except OSError as error:
        return _result(False, f"Reset failed: {error}")

    print("ECU-A reset: Version 1 active in Slot A, Slot B empty")
    return _result(True, "ECU-A reset completed")


def get_status():
    """Return the current state plus the files present in each slot."""
    state = _read_state()
    slot_a = sorted(p.name for p in SLOT_A_DIR.glob("*") if p.is_file())
    slot_b = sorted(p.name for p in SLOT_B_DIR.glob("*") if p.is_file())
    return {"state": state, "slot_a": slot_a, "slot_b": slot_b}


def _main(argv):
    if len(argv) != 2 or argv[1] not in ("reset", "status"):
        print("Usage: python ecu_simulator/ecu.py [reset|status]")
        return 2

    if argv[1] == "reset":
        return 0 if reset_ecu()["success"] else 1

    try:
        print(json.dumps(get_status(), indent=2))
    except (OSError, ValueError) as error:
        print(f"Cannot read ECU status: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))