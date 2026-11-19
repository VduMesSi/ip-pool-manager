import ipaddress, json, os, tempfile, threading, time
from pathlib import Path

class JsonStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self):
        empty = {"ips": {}, "burned": {}, "meta": {"created": time.time()}}
        with self.lock:
            if not self.path.exists():
                return empty
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("state root must be an object")
                ips = data.get("ips", {})
                burned = data.get("burned", {})
                meta = data.get("meta", {})
                if not isinstance(ips, dict) or not isinstance(burned, dict) or not isinstance(meta, dict):
                    raise ValueError("state ips, burned and meta fields must be objects")
                # Reject malformed records rather than allowing a later status/refresh crash.
                for ip, record in ips.items():
                    if not isinstance(ip, str) or not isinstance(record, dict):
                        raise ValueError("invalid IP pool record")
                    ipaddress.ip_address(ip)
                for ip, until in burned.items():
                    if not isinstance(ip, str):
                        raise ValueError("invalid burned IP")
                    ipaddress.ip_address(ip)
                    float(until)
                return {"ips": ips, "burned": burned, "meta": meta}
            except Exception:
                backup = self.path.with_suffix(self.path.suffix + f".corrupt-{int(time.time())}")
                try:
                    self.path.replace(backup)
                except OSError:
                    pass
                return {"ips": {}, "burned": {}, "meta": {"recovered": time.time()}}

    def save(self, data):
        with self.lock:
            fd, tmp = tempfile.mkstemp(prefix=self.path.name, suffix=".tmp", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
