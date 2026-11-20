import hmac, logging, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .config import DATA_DIR, API_TOKEN, SCHEDULER_ENABLED
from .engine import PoolEngine
from .scheduler import start_scheduler, stop_scheduler, run_full_cycle

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
engines = {family: PoolEngine(family, DATA_DIR) for family in ("ipv6_cf", "ipv6_other")}


def resolve_family(family: str):
    # Backward compatibility: historical IPv6 endpoints map to CF1/CF2 pool.
    if family == "ipv6":
        return "ipv6_cf"
    return family


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = start_scheduler(engines) if SCHEDULER_ENABLED else []
    logging.getLogger("ip-pool.scheduler").info(
        "automatic scheduler %s; timezone=Asia/Taipei; allowed run times=07:30,13:30,19:30",
        "enabled" if SCHEDULER_ENABLED else "disabled",
    )
    try:
        yield
    finally:
        if tasks:
            await stop_scheduler(tasks)


app = FastAPI(title="NAS IP Pool Manager", version="0.5.0", lifespan=lifespan)


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
    return {
        "ok": True,
        "service": "nas-ip-pool-manager",
        "version": "0.5.0",
        "scheduler_enabled": SCHEDULER_ENABLED,
        "scheduler_timezone": "Asia/Taipei",
        "scheduler_run_times": ["07:30", "13:30", "19:30"],
    }


@app.get("/api/v1/status")
def status(authorization: str | None = Header(default=None)):
    authorize(authorization)
    return {**{family: engine.status() for family, engine in engines.items()},
            "ipv6": engines["ipv6_cf"].status()}


@app.get("/api/v1/{family}/pool")
def pool(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    family = resolve_family(family)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    return engines[family].status()


@app.post("/api/v1/{family}/scan")
def scan(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    family = resolve_family(family)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    result = engines[family].run_scan()
    if not result.get("ok"):
        raise HTTPException(409, result)
    return result


@app.post("/api/v1/{family}/refresh")
def refresh(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    family = resolve_family(family)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    return engines[family].refresh()


@app.post("/api/v1/{family}/scan-refresh")
def scan_refresh(family: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    family = resolve_family(family)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    result = engines[family].run_scan()
    if not result.get("ok"):
        raise HTTPException(409, result)
    result["pool"] = engines[family].refresh()
    return result


@app.post("/api/v1/scan-cycle")
async def scan_cycle(authorization: str | None = Header(default=None)):
    authorize(authorization)
    result = await run_full_cycle(engines)
    if not result.get("ok"):
        raise HTTPException(409, result)
    return result


@app.post("/api/v1/{family}/result")
def mark_result(family: str, payload: ResultInput,
                authorization: str | None = Header(default=None)):
    authorize(authorization)
    family = resolve_family(family)
    if family not in engines:
        raise HTTPException(404, "unknown family")
    try:
        engines[family].mark_result(payload.ip, payload.success)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True}
