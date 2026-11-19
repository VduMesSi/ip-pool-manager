import asyncio
import logging
import time

from .config import SCHEDULER_INTERVAL_SECONDS
from .engine import PoolEngine

log = logging.getLogger("ip-pool.scheduler")


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
    interval = SCHEDULER_INTERVAL_SECONDS
    log.info(
        "%s scheduler enabled; first run in %d seconds, then after each completed cycle",
        family, interval,
    )

    loop = asyncio.get_running_loop()
    next_run = loop.time() + interval
    while True:
        await asyncio.sleep(max(0.0, next_run - loop.time()))
        await _run_family(engine)
        next_run += interval


def start_scheduler(engines: dict[str, PoolEngine]) -> list[asyncio.Task]:
    """Start one independent periodic task for each address family."""
    return [
        asyncio.create_task(_family_loop(engine), name=f"ip-pool-scheduler-{family}")
        for family, engine in engines.items()
    ]


async def stop_scheduler(tasks: list[asyncio.Task]) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
