import ipaddress
import sqlite3
import threading
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path

class QualityStore:
    """Durable per-IP daily quality history and seven-day qualification."""
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS ip_daily_quality (
                ip TEXT NOT NULL, family TEXT NOT NULL, day TEXT NOT NULL,
                latency_sum REAL NOT NULL DEFAULT 0,
                samples INTEGER NOT NULL DEFAULT 0,
                max_loss REAL NOT NULL DEFAULT 0,
                PRIMARY KEY(ip, family, day)
            );
            CREATE TABLE IF NOT EXISTS permanent_ips (
                ip TEXT NOT NULL, family TEXT NOT NULL,
                first_qualified_at TEXT NOT NULL,
                last_qualified_day TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                PRIMARY KEY(ip, family)
            );
            CREATE INDEX IF NOT EXISTS idx_daily_family_day
                ON ip_daily_quality(family, day);
            """)
    def _connect(self):
        db=sqlite3.connect(self.path, timeout=30)
        db.row_factory=sqlite3.Row
        return db
    def record(self, ip, family, day, latency, loss=0.0):
        parsed=ipaddress.ip_address(ip)
        if (family.startswith("ipv4")) != (parsed.version == 4):
            return
        day=day.isoformat() if hasattr(day, "isoformat") else str(day)
        with self.lock, self._connect() as db:
            db.execute("""
              INSERT INTO ip_daily_quality(ip,family,day,latency_sum,samples,max_loss)
              VALUES(?,?,?,?,1,?)
              ON CONFLICT(ip,family,day) DO UPDATE SET
                latency_sum=latency_sum+excluded.latency_sum,
                samples=samples+1,
                max_loss=MAX(max_loss,excluded.max_loss)
            """,(str(parsed),family,day,float(latency),float(loss)))
            self._qualify(db,str(parsed),family,day)
    def _qualify(self, db, ip, family, day):
        end=date.fromisoformat(day)
        start=end-timedelta(days=6)
        rows=db.execute("""
          SELECT day, latency_sum, samples, max_loss FROM ip_daily_quality
          WHERE ip=? AND family=? AND day BETWEEN ? AND ?
          ORDER BY day
        """,(ip,family,start.isoformat(),end.isoformat())).fetchall()
        by_day={r["day"]:r for r in rows}
        eligible=True
        for i in range(7):
            key=(start+timedelta(days=i)).isoformat()
            row=by_day.get(key)
            if not row or row["samples"] < 1:
                eligible=False; break
            latency_limit = 160 if family == "ipv60" else 80
            if row["latency_sum"]/row["samples"] >= latency_limit or row["max_loss"] > 0:
                eligible=False; break
        existing=db.execute("SELECT first_qualified_at FROM permanent_ips WHERE ip=? AND family=?",(ip,family)).fetchone()
        if eligible:
            first=existing["first_qualified_at"] if existing else end.isoformat()
            db.execute("""
              INSERT INTO permanent_ips(ip,family,first_qualified_at,last_qualified_day,status)
              VALUES(?,?,?,?, 'active')
              ON CONFLICT(ip,family) DO UPDATE SET
                last_qualified_day=excluded.last_qualified_day,status='active'
            """,(ip,family,first,end.isoformat()))
        elif existing:
            # Preserve the record and history; only mark it historical, never delete it.
            db.execute("UPDATE permanent_ips SET status='historical' WHERE ip=? AND family=?",(ip,family))
    def active(self, family):
        # Keep a qualification current through the day after its last qualifying
        # scan; a missed full calendar day makes the address historical.
        cutoff=(datetime.now(ZoneInfo("Asia/Taipei")).date()-timedelta(days=1)).isoformat()
        with self.lock, self._connect() as db:
            db.execute("""
              UPDATE permanent_ips SET status='historical'
              WHERE family=? AND status='active' AND last_qualified_day<?
            """,(family,cutoff))
            rows=db.execute("""
              SELECT p.ip, q.latency_sum/q.samples AS latency
              FROM permanent_ips p
              JOIN ip_daily_quality q ON q.ip=p.ip AND q.family=p.family
                AND q.day=p.last_qualified_day
              WHERE p.family=? AND p.status='active'
                AND p.last_qualified_day>=?
              ORDER BY latency ASC
            """,(family,cutoff)).fetchall()
            return [(r["ip"],float(r["latency"])) for r in rows]
    def known(self, family):
        with self._connect() as db:
            return {r["ip"] for r in db.execute(
                "SELECT ip FROM permanent_ips WHERE family=?",(family,)).fetchall()}
