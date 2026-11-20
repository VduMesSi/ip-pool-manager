import csv, ipaddress, json, logging, os, random, socket, subprocess, threading, time
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import (
    CFST_BIN, SCAN_TIMEOUT, SCAN_WORKERS, POOL_MAX, POOL_MIN,
    ADD_PER_REFRESH, FRESH_TOP, SAMPLE_RATIO, IPV6_SCAN_TARGET, COOLDOWN_MIN,
    COOLDOWN_MAX, BURN_SECONDS
)
from .store import JsonStore

log = logging.getLogger("ip-pool")

FAMILIES = {
    "ipv60": {"source": "ipv60.txt", "result": "result_ipv60.csv", "state": "pool_state_ipv60.json"},
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
            raise ValueError("unknown pool family")
        self.family = family
        self.version = 4 if family == "ipv4" else 6
        self.paths = FAMILIES[family]
        self.base = data_dir / family
        self.base.mkdir(parents=True, exist_ok=True)
        self.source = self.base / self.paths["source"]
        self.source.touch(exist_ok=True)
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

    def _read_candidates(self, result_path=None):
        """Read CFST CSV, retaining only valid IPs of this engine's address family."""
        rows_out = []
        path = Path(result_path) if result_path else self.result
        if not path.exists():
            return rows_out
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.reader(f))
        except Exception:
            log.exception("%s result CSV read failed: %s", self.family, path)
            return rows_out

        if not rows:
            return rows_out

        # XIU2/CFST CSV: IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
        # Average latency is the fifth column (zero-based index 4).
        header = [x.strip().lstrip("\ufeff") for x in rows[0]]
        if len(header) < 5 or not (header[0].lower().startswith("ip") or "IP" in header[0]):
            log.error("%s CFST CSV has an unexpected header: %s", self.family, header)
            return rows_out

        for row in rows[1:]:
            if not row or len(row) < 5 or not row[0].strip():
                continue
            ip = row[0].strip()
            if not valid_ip(ip, self.version):
                continue
            try:
                lat = float(row[4])
                if not (0 < lat <= 60000):
                    continue
            except (ValueError, TypeError):
                continue
            rows_out.append((ip, lat))

        best = {}
        for ip, lat in rows_out:
            best[ip] = min(lat, best.get(ip, float("inf")))
        return list(best.items())

    def run_scan(self, force=False):
        if not self.scan_lock.acquire(blocking=False):
            return {"ok": False, "reason": "scan_already_running"}
        scan_input = self.base / f".{self.family}.cfst_input.tmp.txt"
        scan_output = self.base / f".{self.family}.cfst_result.tmp.csv"
        try:
            if not CFST_BIN.is_file():
                return {"ok": False, "reason": f"CFST binary not found: {CFST_BIN}"}
            if not os.access(CFST_BIN, os.X_OK):
                return {"ok": False, "reason": f"CFST binary is not executable: {CFST_BIN}"}
            if not self.source.is_file():
                return {"ok": False, "reason": f"source file not found: {self.source}"}

            raw_lines = self.source.read_text(encoding="utf-8-sig").splitlines()
            lines, invalid = [], []
            seen = set()
            for raw in raw_lines:
                value = raw.strip()
                if not value or value.startswith("#"):
                    continue
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    if network.version != self.version:
                        raise ValueError("address family mismatch")
                    normalized = str(network)
                except ValueError:
                    invalid.append(value)
                    continue
                if normalized not in seen:
                    seen.add(normalized)
                    lines.append(normalized)

            if invalid:
                return {"ok": False, "reason": "source_contains_invalid_or_wrong_family_entries",
                        "invalid_count": len(invalid), "invalid_examples": invalid[:5]}
            if len(lines) < 2:
                return {"ok": False, "reason": "source file has fewer than 2 valid entries"}

            if self.version == 6:
                # Sample individual addresses uniformly from the union of all source CIDRs.
                # Collapse overlapping/adjacent networks first to avoid duplicate weighting.
                networks = [ipaddress.ip_network(value) for value in lines]
                merged = list(ipaddress.collapse_addresses(networks))
                ranges = []
                cumulative_ends = []
                total_addresses = 0
                for network in merged:
                    start = int(network.network_address)
                    count = network.num_addresses
                    total_addresses += count
                    ranges.append((start, count))
                    cumulative_ends.append(total_addresses)

                target = min(max(1, IPV6_SCAN_TARGET), total_addresses)
                if target == total_addresses:
                    offsets = list(range(total_addresses))
                else:
                    selected_offsets = set()
                    while len(selected_offsets) < target:
                        selected_offsets.add(random.randrange(total_addresses))
                    offsets = sorted(selected_offsets)

                sampled = []
                for offset in offsets:
                    range_index = bisect_right(cumulative_ends, offset)
                    previous_end = cumulative_ends[range_index - 1] if range_index else 0
                    start, _ = ranges[range_index]
                    sampled.append(str(ipaddress.IPv6Address(start + offset - previous_end)))

                log.info(
                    "ipv6 address sampling: %d source CIDRs, %d merged ranges, "
                    "%s addresses available, %d unique addresses selected",
                    len(lines), len(merged), total_addresses, len(sampled)
                )
            else:
                k = max(2, min(len(lines), int(len(lines) * SAMPLE_RATIO)))
                sampled = random.sample(lines, k) if k < len(lines) else lines

            # CFST accepts one IP/CIDR per line. IPv6 input is now individual addresses.
            scan_input.write_text("\n".join(sampled) + "\n", encoding="utf-8")
            scan_output.unlink(missing_ok=True)

            # Use an explicit temporary output so a failed scan never destroys the last good CSV.
            cmd = [str(CFST_BIN), "-f", str(scan_input), "-o", str(scan_output),
                   "-n", "20", "-tl", "120", "-dd", "-tlr", "0", "-p", "0"]
            log.info("%s CFST scan started (%d source entries, %d test targets)",
                     self.family, len(lines), len(sampled))
            try:
                p = subprocess.run(cmd, cwd=str(self.base), capture_output=True,
                                   timeout=SCAN_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                return {"ok": False, "reason": "scan_timeout"}
            except OSError as e:
                log.exception("%s CFST process could not start", self.family)
                return {"ok": False, "reason": "cfst_start_failed", "detail": str(e)}

            stdout = p.stdout.decode("utf-8", "replace")[-2000:]
            stderr = p.stderr.decode("utf-8", "replace")[-2000:]
            if p.returncode != 0:
                return {"ok": False, "reason": "cfst_failed", "returncode": p.returncode,
                        "stderr": stderr, "stdout": stdout}
            if not scan_output.is_file():
                return {"ok": False, "reason": "cfst_output_missing",
                        "stdout": stdout, "stderr": stderr}

            candidates = self._read_candidates(scan_output)
            # A valid header-only CSV is a completed scan with no qualifying IPs.
            try:
                with scan_output.open("r", encoding="utf-8-sig", newline="") as f:
                    header = next(csv.reader(f), [])
            except OSError as e:
                return {"ok": False, "reason": "cfst_output_unreadable", "detail": str(e)}
            expected_latency_header = header[4].strip()
            if (len(header) < 7
                    or not header[0].strip().lower().startswith("ip")
                    or expected_latency_header != "平均延迟"):
                return {"ok": False, "reason": "cfst_output_invalid",
                        "header": header[:7]}

            scan_output.replace(self.result)
            return {"ok": True, "candidates": len(candidates),
                    "stdout": stdout, "stderr": stderr}
        except (OSError, UnicodeError) as e:
            log.exception("%s scan preparation or file operation failed", self.family)
            return {"ok": False, "reason": "scan_io_error", "detail": str(e)}
        finally:
            self.scan_lock.release()

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
            # Prefer addresses that have earned seven-day permanent qualification.
            try:
                from .quality import QualityStore
                permanent = dict(QualityStore(self.base.parent / "quality" / f"{self.family}.sqlite3").active(self.family))
            except Exception:
                log.exception("could not read permanent IP quality database")
                permanent = {}
            fresh = sorted(
                [(ip, lat) for ip, lat in candidates if ip not in pool and ip not in burned],
                key=lambda x: (0 if x[0] in permanent else 1, permanent.get(x[0], x[1]), x[1])
            )[:FRESH_TOP]

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
                evictable = active_ips
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
