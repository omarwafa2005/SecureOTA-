import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"

DOWNLOAD_DIR = Path(__file__).parent / "downloads"


def check_backend():
    print("Checking backend connection...")

    try:
        response = requests.get(
            f"{BASE_URL}/health",
            timeout=5
        )

        response.raise_for_status()

        print("Backend is available!")
        print("Response:", response.json())

        return True

    except requests.RequestException as error:
        print("Backend connection failed:", error)
        return False


def get_update_info():
    print("\nRequesting update information...")

    try:
        response = requests.get(
            f"{BASE_URL}/updates/ECU-A",
            timeout=5
        )

        response.raise_for_status()

        update_info = response.json()

        print("Update information received:")
        print(update_info)

        return update_info

    except requests.RequestException as error:
        print("Failed to get update information:", error)
        return None


def validate_update_info(update_info):
    print("\nValidating update information...")

    required_fields = [
        "ecu_id",
        "hardware_id",
        "version",
        "filename",
        "download_url"
    ]

    for field in required_fields:
        if field not in update_info:
            print(f"Validation failed: Missing {field}")
            return False

    if update_info["ecu_id"] != "ECU-A":
        print("Validation failed: Unknown ECU")
        return False

    if update_info["hardware_id"] != "HW-A-01":
        print("Validation failed: Hardware ID mismatch")
        return False

    if not isinstance(update_info["version"], int):
        print("Validation failed: Invalid version")
        return False

    if update_info["version"] < 1:
        print("Validation failed: Invalid version")
        return False

    if not update_info["filename"]:
        print("Validation failed: Empty filename")
        return False

    if not update_info["download_url"]:
        print("Validation failed: Empty download URL")
        return False

    print("Validation successful!")
    return True


def download_firmware(update_info):
    print("\nDownloading firmware...")

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    filename = update_info["filename"]
    download_url = update_info["download_url"]

    firmware_url = f"{BASE_URL}{download_url}"
    output_path = DOWNLOAD_DIR / filename

    try:
        response = requests.get(
            firmware_url,
            timeout=10
        )

        response.raise_for_status()

        if not response.content:
            print("Download failed: Firmware file is empty")
            return None

        with open(output_path, "wb") as firmware_file:
            firmware_file.write(response.content)

        print("Firmware downloaded successfully!")
        print("Saved to:", output_path)
        print("File size:", len(response.content), "bytes")

        return output_path

    except requests.RequestException as error:
        print("Firmware download failed:", error)
        return None


if __name__ == "__main__":

    if check_backend():

        update_info = get_update_info()

        if update_info:

            if validate_update_info(update_info):

                firmware_path = download_firmware(update_info)