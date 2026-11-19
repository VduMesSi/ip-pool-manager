import csv, ipaddress, json, logging, random, socket, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import (
    CFST_BIN, SCAN_TIMEOUT, SCAN_WORKERS, POOL_MAX, POOL_MIN,
    ADD_PER_REFRESH, FRESH_TOP, SAMPLE_RATIO, COOLDOWN_MIN,
    COOLDOWN_MAX, BURN_SECONDS, PRECHECK_TRIES
)
from .store import JsonStore

log = logging.getLogger("ip-pool")

FAMILIES = {
    "ipv4": {"source": "ipv4.txt", "result": "result_ipv4.csv", "state": "pool_state_ipv4.json"},
    "ipv6": {"source": "ipv6.txt", "result": "result_ipv6.csv", "state": "pool_state_ipv6.json"},
}

def valid_ip(value, version):
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False

def tcp_ok(ip, port=443, timeout=2.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

def ip_weight(m):
    # Keep original scoring formula as baseline; missing latency receives a conservative penalty.
    lat = m.get("lat")
    if lat is None:
        lat = 100.0
    ok, fail = int(m.get("ok", 0)), int(m.get("fail", 0))
    return ((ok + 1) / (ok + fail + 2)) / (float(lat) + 30.0)

class PoolEngine:
    def __init__(self, family: str, data_dir: Path):
        if family not in FAMILIES:
            raise ValueError("family must be ipv4 or ipv6")
        self.family = family
        self.version = 4 if family == "ipv4" else 6
        self.paths = FAMILIES[family]
        self.base = data_dir / family
        self.base.mkdir(parents=True, exist_ok=True)
        self.source = self.base / self.paths["source"]
        self.result = self.base / self.paths["result"]
        self.store = JsonStore(self.base / self.paths["state"])
        self.lock = threading.RLock()
        self.state = self.store.load()
        self.scan_lock = threading.Lock()

    def status(self):
        now = time.time()
        with self.lock:
            ips = self.state["ips"]
            active = [ip for ip, m in ips.items() if float(m.get("cool_until", 0)) <= now]
            cooling = [ip for ip, m in ips.items() if float(m.get("cool_until", 0)) > now]
            return {
                "family": self.family,
                "total": len(ips),
                "active": len(active),
                "cooling": len(cooling),
                "burned": len(self.state["burned"]),
                "pool": [
                    {"ip": ip, "latency_ms": m.get("lat"), "ok": m.get("ok", 0),
                     "fail": m.get("fail", 0), "cool_until": m.get("cool_until", 0),
                     "last_test": m.get("last_test", 0), "weight": round(ip_weight(m), 8)}
                    for ip, m in sorted(ips.items(), key=lambda kv: ip_weight(kv[1]), reverse=True)
                ],
            }

    def _read_candidates(self):
        rows_out = []
        if not self.result.exists():
            return rows_out
        try:
            with self.result.open("r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.reader(f))
        except Exception as e:
            log.exception("%s result CSV read failed", self.family)
            return rows_out
        for row in rows[1:]:
            if not row or not row[0].strip():
                continue
            ip = row[0].strip()
            if not valid_ip(ip, self.version):
                continue
            try:
                lat = float(row[4]) if len(row) > 4 else 100.0
                if lat <= 0 or lat > 60000:
                    continue
            except (ValueError, TypeError):
                continue
            rows_out.append((ip, lat))
        # Deduplicate while keeping the lowest observed latency.
        best = {}
        for ip, lat in rows_out:
            best[ip] = min(lat, best.get(ip, float("inf")))
        return list(best.items())

    def run_scan(self, force=False):
        if not self.scan_lock.acquire(blocking=False):
            return {"ok": False, "reason": "scan_already_running"}
        try:
            if not CFST_BIN.exists():
                return {"ok": False, "reason": f"CFST binary not found: {CFST_BIN}"}
            if not self.source.exists():
                return {"ok": False, "reason": f"source file not found: {self.source}"}
            lines = [x.strip() for x in self.source.read_text(encoding="utf-8").splitlines()
                     if x.strip() and not x.lstrip().startswith("#")]
            if len(lines) < 2:
                return {"ok": False, "reason": "source file has fewer than 2 entries"}
            k = max(2, min(len(lines), int(len(lines) * SAMPLE_RATIO)))
            sampled = random.sample(lines, k) if k < len(lines) else lines
            scan_input = self.base / "cfst_input.tmp.txt"
            scan_input.write_text("\\n".join(sampled) + "\\n", encoding="utf-8")
            # CloudflareSpeedTest writes result.csv in its working directory by default.
            default_output = self.base / "result.csv"
            if default_output.exists():
                default_output.unlink()
            if self.result.exists():
                self.result.unlink()
            cmd = [str(CFST_BIN), "-f", str(scan_input), "-n", "50", "-tl", "99",
                   "-dd", "-tlr", "0", "-p", "0"]
            log.info("%s CFST scan started (%d source entries)", self.family, len(sampled))
            try:
                p = subprocess.run(cmd, cwd=str(self.base), capture_output=True,
                                   timeout=SCAN_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                return {"ok": False, "reason": "scan_timeout"}
            if p.returncode != 0:
                return {"ok": False, "reason": "cfst_failed",
                        "stderr": p.stderr.decode("utf-8", "replace")[-2000:]}
            if default_output.exists():
                default_output.replace(self.result)
            if not self.result.exists():
                return {"ok": False, "reason": "cfst_output_missing",
                        "stdout": p.stdout.decode("utf-8", "replace")[-2000:]}
            candidates = self._read_candidates()
            return {"ok": True, "candidates": len(candidates),
                    "stdout": p.stdout.decode("utf-8", "replace")[-2000:]}
        finally:
            self.scan_lock.release()

    def _assigned(self):
        # Pool-only stage has no outbound slot assignments yet.
        return set()

    def refresh(self):
        candidates = self._read_candidates()
        if not candidates:
            return {"ok": False, "reason": "no_valid_candidates"}
        now = time.time()
        latency = dict(candidates)
        with self.lock:
            pool = self.state["ips"]
            burned = self.state["burned"]
            for ip in [ip for ip, until in burned.items() if float(until) <= now]:
                del burned[ip]
            for ip, meta in pool.items():
                if ip in latency:
                    meta["lat"] = latency[ip]
                    meta["last_test"] = now

            # Retain original burn policy, but do not burn an IP based on a single failure.
            for ip in [ip for ip, m in pool.items()
                       if int(m.get("fail", 0)) >= 3 and int(m.get("fail", 0)) > int(m.get("ok", 0))]:
                burned[ip] = now + BURN_SECONDS
                del pool[ip]

            active = sum(1 for m in pool.values() if float(m.get("cool_until", 0)) <= now)
            want = ADD_PER_REFRESH if active >= POOL_MIN else max(POOL_MAX - active, 0)
            fresh = sorted(
                [(ip, lat) for ip, lat in candidates if ip not in pool and ip not in burned],
                key=lambda x: x[1]
            )[:FRESH_TOP]

        random.shuffle(fresh)
        batch = fresh[:max(want * 3, want)]
        accepted = []
        if batch and want > 0:
            with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as executor:
                checks = list(executor.map(lambda item: tcp_ok(item[0]), batch))
            for (ip, lat), ok in zip(batch, checks):
                if ok and len(accepted) < want:
                    accepted.append((ip, lat))

        with self.lock:
            pool = self.state["ips"]
            now = time.time()
            active_ips = [ip for ip, m in pool.items() if float(m.get("cool_until", 0)) <= now]
            overflow = len(active_ips) + len(accepted) - POOL_MAX
            if overflow > 0:
                assigned = self._assigned()
                evictable = [ip for ip in active_ips if ip not in assigned]
                evict = sorted(evictable, key=lambda ip: ip_weight(pool[ip]))[:overflow]
                for ip in evict:
                    del pool[ip]
            for ip, lat in accepted:
                pool[ip] = {"lat": lat, "ok": 0, "fail": 0, "cool_until": 0,
                            "added": now, "last_test": now}
            self.state["meta"]["last_refresh"] = now
            self.store.save(self.state)
            total = len(pool)
        return {"ok": True, "added": len(accepted), "total": total,
                "active": self.status()["active"]}

    def mark_result(self, ip, success: bool):
        if not valid_ip(ip, self.version):
            raise ValueError("IP family mismatch")
        now = time.time()
        with self.lock:
            meta = self.state["ips"].get(ip)
            if not meta:
                raise KeyError(ip)
            key = "ok" if success else "fail"
            meta[key] = int(meta.get(key, 0)) + 1
            if not success:
                meta["cool_until"] = now + random.uniform(COOLDOWN_MIN, COOLDOWN_MAX)
            meta["last_result"] = now
            self.store.save(self.state)

    def get_candidates(self):
        now = time.time()
        with self.lock:
            return [
                {"ip": ip, "latency_ms": m.get("lat"), "weight": ip_weight(m)}
                for ip, m in self.state["ips"].items()
                if float(m.get("cool_until", 0)) <= now
            ]
