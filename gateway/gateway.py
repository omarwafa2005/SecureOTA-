"""Vehicle gateway for SecureOTA-V Phase 1.

Flow: check backend -> get update info -> validate -> download -> stage in ECU-A.

Run from the repository root:
    python gateway/gateway.py
"""

import sys
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ecu_simulator.ecu import stage_firmware  # noqa: E402

BASE_URL = "http://127.0.0.1:8000"
DOWNLOAD_DIR = Path(__file__).resolve().parent / "downloads"

HEALTH_TIMEOUT = 5
UPDATE_TIMEOUT = 5
DOWNLOAD_TIMEOUT = 10

REQUIRED_FIELDS = ["ecu_id", "hardware_id", "version", "filename", "download_url"]


def check_backend():
    print("Connecting to backend...")

    try:
        response = requests.get(f"{BASE_URL}/health", timeout=HEALTH_TIMEOUT)
        response.raise_for_status()
        body = response.json()
    except (requests.RequestException, ValueError):
        print("Backend unavailable")
        return False

    if not isinstance(body, dict) or body.get("status") != "ok":
        print("Backend unavailable")
        return False

    print("Backend is available")
    return True


def get_update_info():
    print("Checking updates for ECU-A...")

    try:
        response = requests.get(f"{BASE_URL}/updates/ECU-A", timeout=UPDATE_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as error:
        print(f"Failed to get update information: {error}")
        return None


def validate_update_info(update_info):
    if not isinstance(update_info, dict):
        print("Validation failed: Update information is not a JSON object")
        return False

    for field in REQUIRED_FIELDS:
        if field not in update_info:
            print(f"Validation failed: Missing {field}")
            return False

    if update_info["ecu_id"] != "ECU-A":
        print("Validation failed: Unknown ECU")
        return False

    if update_info["hardware_id"] != "HW-A-01":
        print("Validation failed: Hardware ID mismatch")
        return False

    version = update_info["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        print("Validation failed: Invalid version")
        return False

    filename = update_info["filename"]
    if not isinstance(filename, str) or not filename.strip():
        print("Validation failed: Empty filename")
        return False
    if Path(filename).name != filename:
        print("Validation failed: Filename must not contain a path")
        return False

    download_url = update_info["download_url"]
    if not isinstance(download_url, str) or not download_url.startswith("/"):
        print("Validation failed: Invalid download URL")
        return False

    return True


def print_update_info(update_info):
    print(f"Update Version {update_info['version']} found")
    print(f"  ECU:      {update_info['ecu_id']}")
    print(f"  Hardware: {update_info['hardware_id']}")
    print(f"  File:     {update_info['filename']}")
    print(f"  URL:      {update_info['download_url']}")


def download_firmware(update_info):
    print("Downloading firmware...")

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    output_path = DOWNLOAD_DIR / update_info["filename"]
    temp_path = DOWNLOAD_DIR / (update_info["filename"] + ".part")
    firmware_url = f"{BASE_URL}{update_info['download_url']}"

    try:
        response = requests.get(firmware_url, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()

        if not response.content:
            print("Download failed: Firmware file is empty")
            return None

        # Write to a temp file first so a failed download never leaves a
        # partial firmware file behind.
        with open(temp_path, "wb") as firmware_file:
            firmware_file.write(response.content)
        temp_path.replace(output_path)
    except (requests.RequestException, OSError) as error:
        print(f"Download failed: {error}")
        if temp_path.exists():
            temp_path.unlink()
        return None

    print("Download completed")
    print(f"Saved to: {output_path}")
    print(f"File size: {output_path.stat().st_size} bytes")
    return output_path


def send_to_ecu(firmware_path, version):
    print("Sending firmware to ECU-A...")

    result = stage_firmware(firmware_path, version)

    if result["success"]:
        print("Firmware staged successfully")
        return True

    print(f"Staging failed: {result['message']}")
    return False


def main():
    if not check_backend():
        return 1

    update_info = get_update_info()
    if update_info is None:
        return 1

    if not validate_update_info(update_info):
        return 1

    print_update_info(update_info)

    firmware_path = download_firmware(update_info)
    if firmware_path is None:
        return 1

    if not send_to_ecu(firmware_path, update_info["version"]):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())