from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse


app = FastAPI(title="SecureOTA-V OEM Backend")


BASE_DIR = Path(__file__).resolve().parent
FIRMWARE_DIR = BASE_DIR / "firmware"
FIRMWARE_FILE = FIRMWARE_DIR / "ecu_a_v2.bin"


@app.get("/health")
def health():
    print("GET /health")
    return {"status": "ok"}


@app.get("/updates/{ecu_id}")
def get_update(ecu_id: str):
    print(f"GET /updates/{ecu_id}")

    if ecu_id != "ECU-A":
        raise HTTPException(
            status_code=404,
            detail="Update not found for requested ECU"
        )

    return {
        "ecu_id": "ECU-A",
        "hardware_id": "HW-A-01",
        "version": 2,
        "filename": "ecu_a_v2.bin",
        "download_url": "/firmware/ecu_a_v2.bin"
    }


@app.get("/firmware/ecu_a_v2.bin")
def download_firmware():
    print("GET /firmware/ecu_a_v2.bin")

    if not FIRMWARE_FILE.is_file():
        raise HTTPException(
            status_code=404,
            detail="Firmware not found"
        )

    return FileResponse(
        path=FIRMWARE_FILE,
        filename="ecu_a_v2.bin",
        media_type="application/octet-stream"
    )