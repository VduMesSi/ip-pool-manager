import asyncio
import logging
import time
from datetime import datetime, timedelta

from .config import SCHEDULER_RUN_HOURS
from .engine import PoolEngine

log = logging.getLogger("ip-pool.scheduler")


def _next_run_time() -> datetime:
    """Return the next allowed wall-clock run slot in the container's local timezone."""
    now = datetime.now().astimezone()
    for hour in SCHEDULER_RUN_HOURS:
        candidate = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if candidate > now:
            return candidate
    return (now + timedelta(days=1)).replace(
        hour=SCHEDULER_RUN_HOURS[0], minute=0, second=0, microsecond=0
    )


async def _run_family(engine: PoolEngine) -> None:
    family = engine.family
    started = time.monotonic()
    log.info("%s scheduled cycle started", family)

    try:
        scan = await asyncio.to_thread(engine.run_scan)
        scan_elapsed = time.monotonic() - started

        if not scan.get("ok"):
            log.error(
                "%s scheduled scan failed after %.1fs; refresh skipped: %s",
                family, scan_elapsed, scan,
            )
            return

        candidates = int(scan.get("candidates", 0))
        log.info(
            "%s scheduled scan succeeded: candidates=%d duration=%.1fs",
            family, candidates, scan_elapsed,
        )

        refresh_started = time.monotonic()
        refreshed = await asyncio.to_thread(engine.refresh)
        refresh_elapsed = time.monotonic() - refresh_started

        if not refreshed.get("ok"):
            log.error(
                "%s scheduled refresh failed: candidates=%d duration=%.1fs result=%s",
                family, candidates, refresh_elapsed, refreshed,
            )
            return

        log.info(
            "%s scheduled cycle completed: candidates=%d added=%d total=%d active=%d "
            "scan_duration=%.1fs refresh_duration=%.1fs total_duration=%.1fs",
            family,
            candidates,
            int(refreshed.get("added", 0)),
            int(refreshed.get("total", 0)),
            int(refreshed.get("active", 0)),
            scan_elapsed,
            refresh_elapsed,
            time.monotonic() - started,
        )
    except Exception:
        log.exception("%s scheduled cycle raised an unexpected exception", family)


async def _family_loop(engine: PoolEngine) -> None:
    family = engine.family
    log.info(
        "%s scheduler enabled; allowed run times are %s local time",
        family, ", ".join(f"{hour:02d}:00" for hour in SCHEDULER_RUN_HOURS),
    )

    while True:
        next_run = _next_run_time()
        delay = max(0.0, (next_run - datetime.now(next_run.tzinfo)).total_seconds())
        log.info(
            "%s scheduler next run at %s",
            family, next_run.isoformat(timespec="seconds"),
        )
        await asyncio.sleep(delay)
        await _run_family(engine)


def start_scheduler(engines: dict[str, PoolEngine]) -> list[asyncio.Task]:
    """Start one independent scheduled task for each address family."""
    return [
        asyncio.create_task(_family_loop(engine), name=f"ip-pool-scheduler-{family}")
        for family, engine in engines.items()
    ]


async def stop_scheduler(tasks: list[asyncio.Task]) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
