import hmac, logging, os
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .config import DATA_DIR, API_TOKEN
from .engine import PoolEngine

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = FastAPI(title="NAS IP Pool Manager", version="0.1.0")
engines = {family: PoolEngine(family, DATA_DIR) for family in ("ipv4", "ipv6")}

def authorize(authorization: str | None):
    if not API_TOKEN:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    if not isinstance(authorization, str) or not hmac.compare_digest(authorization, f"Bearer {API_TOKEN}"):
        raise HTTPException(status_code=401, detail="unauthorized")

class ResultInput(BaseModel):
    ip: str
    success: bool

@app.get("/health")
def health():
    return {"ok": True, "service": "nas-ip-pool-manager"}

@app.get("/api/v1/status")
def status(authorization: str | None = Header(default=None)):
    authorize(authorization)
    return {family: engine.status() for family, engine in engines.items()}

@app.get("/api/v1/{family}/pool")
def pool(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    return engines[family].status()

@app.post("/api/v1/{family}/scan")
def scan(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    result = engines[family].run_scan()
    if not result.get("ok"):
        raise HTTPException(409, result)
    return result

@app.post("/api/v1/{family}/refresh")
def refresh(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    return engines[family].refresh()

@app.post("/api/v1/{family}/scan-refresh")
def scan_refresh(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    result = engines[family].run_scan()
    if not result.get("ok"):
        raise HTTPException(409, result)
    result["pool"] = engines[family].refresh()
    return result

@app.post("/api/v1/{family}/result")
def mark_result(family: str, payload: ResultInput,
                authorization: str | None = Header(default=None)):
    authorize(authorization)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    try:
        engines[family].mark_result(payload.ip, payload.success)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True}
