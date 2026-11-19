import json, os, tempfile, threading, time
from pathlib import Path

class JsonStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self):
        with self.lock:
            if not self.path.exists():
                return {"ips": {}, "burned": {}, "meta": {"created": time.time()}}
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("state root must be an object")
                data.setdefault("ips", {})
                data.setdefault("burned", {})
                data.setdefault("meta", {})
                return data
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
