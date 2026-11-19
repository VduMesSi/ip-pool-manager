import csv, ipaddress, json, logging, os, random, socket, subprocess, threading, time, tempfile
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import (
    CFST_BIN, SCAN_TIMEOUT, SCAN_WORKERS, POOL_MAX, POOL_MIN,
    ADD_PER_REFRESH, FRESH_TOP, SAMPLE_RATIO, IPV6_SCAN_TARGET, COOLDOWN_MIN,
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
        self.cidr_state_path = self.base / "ipv6_cidr_state.json" if family == "ipv6" else None
        self.cidr_state_lock = threading.RLock()

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

            cidr_probe_networks = []
            cidr_state = None
            if self.family == "ipv6":
                # Stage 1: probe only a small, rotating subset of source CIDRs.
                # Stage 2: sample individual IPv6 addresses only from previously
                # confirmed-good CIDRs. CIDR state is persisted independently of the IP pool.
                networks = [ipaddress.ip_network(value) for value in lines]
                cidr_state = self._load_cidr_state()
                now = time.time()
                records = cidr_state["cidrs"]

                # Expired bans become eligible for a fresh probe; do not permanently delete them.
                for network in networks:
                    key = str(network)
                    record = records.setdefault(key, {
                        "fail_count": 0, "valid": False, "last_probe": 0,
                        "last_success": 0, "banned_until": 0
                    })
                    if float(record.get("banned_until", 0)) <= now and record.get("banned_until"):
                        record["banned_until"] = 0
                        record["fail_count"] = 0
                        record["valid"] = False

                eligible = [
                    n for n in networks
                    if float(records[str(n)].get("banned_until", 0)) <= now
                ]
                probe_count = min(
                    len(eligible),
                    max(1, int(len(networks) * IPV6_CIDR_PROBE_RATIO + 0.999999))
                )
                # Oldest-tested CIDRs first ensures the whole source list is covered
                # progressively instead of repeatedly choosing the same random subset.
                eligible.sort(key=lambda n: (
                    float(records[str(n)].get("last_probe", 0)),
                    random.random()
                ))
                cidr_probe_networks = eligible[:probe_count]
                for network in cidr_probe_networks:
                    records[str(network)]["last_probe"] = now

                valid_networks = [
                    n for n in eligible
                    if records[str(n)].get("valid") is True
                    and n not in cidr_probe_networks
                ]
                sampled_ips = set()
                # Draw unique addresses from known-good CIDRs only.
                total_valid_addresses = sum(n.num_addresses for n in valid_networks)
                target = min(max(0, IPV6_SCAN_TARGET), total_valid_addresses)
                attempts = 0
                max_attempts = max(target * 20, 100)
                while len(sampled_ips) < target and attempts < max_attempts and valid_networks:
                    network = random.choice(valid_networks)
                    address = ipaddress.IPv6Address(
                        int(network.network_address) + random.randrange(network.num_addresses)
                    )
                    sampled_ips.add(str(address))
                    attempts += 1

                sampled = [str(n) for n in cidr_probe_networks] + sorted(sampled_ips)
                log.info(
                    "ipv6 staged sampling: source_cidrs=%d cidr_probes=%d (%.1f%%), "
                    "known_good_cidrs=%d ip_targets=%d banned_cidrs=%d",
                    len(networks), len(cidr_probe_networks),
                    len(cidr_probe_networks) * 100.0 / max(1, len(networks)),
                    len(valid_networks), len(sampled_ips),
                    sum(1 for n in networks if float(records[str(n)].get("banned_until", 0)) > now)
                )
            else:
                k = max(2, min(len(lines), int(len(lines) * SAMPLE_RATIO)))
                sampled = random.sample(lines, k) if k < len(lines) else lines

            # CFST accepts one IP/CIDR per line. IPv6 input is now individual addresses.
            scan_input.write_text("\n".join(sampled) + "\n", encoding="utf-8")
            scan_output.unlink(missing_ok=True)

            # Use an explicit temporary output so a failed scan never destroys the last good CSV.
            cmd = [str(CFST_BIN), "-f", str(scan_input), "-o", str(scan_output),
                   "-n", "50", "-tl", "120", "-dd", "-tlr", "0", "-p", "0"]
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
            if self.family == "ipv6" and cidr_state is not None:
                # A CIDR is healthy if CFST returns at least one successful address inside it.
                # A failed observation increments its counter; three failed probes disable it
                # for a week. A later successful probe resets the counter.
                candidate_addresses = []
                for ip, _lat in candidates:
                    try:
                        candidate_addresses.append(ipaddress.IPv6Address(ip))
                    except ValueError:
                        pass
                now = time.time()
                activated = banned = 0
                for network in cidr_probe_networks:
                    record = cidr_state["cidrs"][str(network)]
                    if any(address in network for address in candidate_addresses):
                        if not record.get("valid"):
                            activated += 1
                        record["valid"] = True
                        record["fail_count"] = 0
                        record["last_success"] = now
                        record["banned_until"] = 0
                    else:
                        record["fail_count"] = int(record.get("fail_count", 0)) + 1
                        if record["fail_count"] >= IPV6_CIDR_FAIL_LIMIT:
                            record["valid"] = False
                            record["banned_until"] = now + IPV6_CIDR_BAN_SECONDS
                            banned += 1
                cidr_state.setdefault("meta", {})["last_scan"] = now
                self._save_cidr_state(cidr_state)
                log.info(
                    "ipv6 CIDR health updated: probed=%d newly_valid=%d newly_banned=%d",
                    len(cidr_probe_networks), activated, banned
                )
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
            result = {"ok": True, "candidates": len(candidates),
                      "stdout": stdout, "stderr": stderr}
            if self.family == "ipv6":
                result.update({
                    "cidr_probed": len(cidr_probe_networks),
                    "ipv6_ips_sampled": len(sampled_ips),
                    "cidr_valid": sum(1 for r in cidr_state["cidrs"].values() if r.get("valid")),
                    "cidr_banned": sum(1 for r in cidr_state["cidrs"].values()
                                       if float(r.get("banned_until", 0)) > time.time())
                })
            return result
        except (OSError, UnicodeError) as e:
            log.exception("%s scan preparation or file operation failed", self.family)
            return {"ok": False, "reason": "scan_io_error", "detail": str(e)}
        finally:
            self.scan_lock.release()

    def _load_cidr_state(self):
        """Load persistent IPv6 CIDR health records without touching the IP pool state."""
        path = self.cidr_state_path
        empty = {"cidrs": {}, "meta": {"created": time.time()}}
        with self.cidr_state_lock:
            if not path.exists():
                return empty
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or not isinstance(data.get("cidrs", {}), dict):
                    raise ValueError("invalid IPv6 CIDR state")
                return {"cidrs": data.get("cidrs", {}), "meta": data.get("meta", {})}
            except Exception:
                backup = path.with_suffix(path.suffix + f".corrupt-{int(time.time())}")
                try:
                    path.replace(backup)
                except OSError:
                    pass
                log.exception("IPv6 CIDR state is corrupt; starting a fresh CIDR health index")
                return empty

    def _save_cidr_state(self, state):
        """Atomically persist CIDR health records."""
        path = self.cidr_state_path
        with self.cidr_state_lock:
            fd, tmp = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, path)
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass

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
