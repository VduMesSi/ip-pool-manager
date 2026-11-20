import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
BIN_DIR = Path(os.getenv("BIN_DIR", "/opt/ip-pool/bin"))
CFST_BIN = Path(os.getenv("CFST_BIN", str(BIN_DIR / "CloudflareST")))
API_TOKEN = os.getenv("API_TOKEN", "")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "1800"))
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "4"))

POOL_MAX = int(os.getenv("POOL_MAX", "30"))
POOL_MIN = int(os.getenv("POOL_MIN", "12"))
ADD_PER_REFRESH = int(os.getenv("ADD_PER_REFRESH", "5"))
FRESH_TOP = int(os.getenv("FRESH_TOP", "60"))
SAMPLE_RATIO = float(os.getenv("SAMPLE_RATIO", "0.5"))
IPV6_SCAN_TARGET = int(os.getenv("IPV6_SCAN_TARGET", "1500"))
COOLDOWN_MIN = int(os.getenv("COOLDOWN_MIN", str(6 * 3600)))
COOLDOWN_MAX = int(os.getenv("COOLDOWN_MAX", str(24 * 3600)))
BURN_SECONDS = int(os.getenv("BURN_SECONDS", str(3 * 86400)))

SCHEDULER_ENABLED = os.getenv("SCHEDULER_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")
