import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("secureota.backend")

app = FastAPI(title="SecureOTA-V OEM Backend")

BASE_DIR = Path(__file__).resolve().parent
FIRMWARE_DIR = BASE_DIR / "firmware"
FIRMWARE_FILE = FIRMWARE_DIR / "ecu_a_v2.bin"


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    logger.info("%s %s -> %s", request.method, request.url.path, response.status_code)
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/updates/{ecu_id}")
def get_update(ecu_id: str):
    if ecu_id != "ECU-A":
        raise HTTPException(
            status_code=404,
            detail="Update not found for requested ECU",
        )

    return {
        "ecu_id": "ECU-A",
        "hardware_id": "HW-A-01",
        "version": 2,
        "filename": "ecu_a_v2.bin",
        "download_url": "/firmware/ecu_a_v2.bin",
    }


@app.get("/firmware/ecu_a_v2.bin")
def download_firmware():
    if not FIRMWARE_FILE.is_file():
        raise HTTPException(status_code=404, detail="Firmware not found")

    return FileResponse(
        path=FIRMWARE_FILE,
        filename="ecu_a_v2.bin",
        media_type="application/octet-stream",
    )