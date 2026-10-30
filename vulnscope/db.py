import json
import sqlite3
import threading
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, target TEXT, kind TEXT, profile TEXT, status TEXT,
  started REAL, finished REAL, options TEXT, summary TEXT, error TEXT,
  authorization TEXT, progress REAL DEFAULT 0, current TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, fingerprint TEXT,
  severity TEXT, status TEXT, title TEXT, data TEXT,
  UNIQUE(scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, kind TEXT, value TEXT, data TEXT,
  UNIQUE(scan_id, kind, value)
);
CREATE TABLE IF NOT EXISTS plugin_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, plugin_id TEXT, status TEXT,
  duration REAL, message TEXT, findings INTEGER
);
"""


class Store:
    def __init__(self, path):
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def create_scan(self, target, kind, profile, options, authorization):
        scan_id = uuid.uuid4().hex[:12]
        with self.lock:
            self.conn.execute(
                "INSERT INTO scans (id,target,kind,profile,status,started,options,authorization) VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, target, kind, profile, "running", time.time(), json.dumps(options), authorization),
            )
            self.conn.commit()
        return scan_id

    def update_scan(self, scan_id, **fields):
        if not fields:
            return
        cols = ", ".join("%s=?" % key for key in fields)
        values = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in fields.values()]
        with self.lock:
            self.conn.execute("UPDATE scans SET %s WHERE id=?" % cols, values + [scan_id])
            self.conn.commit()

    def add_finding(self, scan_id, finding):
        data = finding.to_dict()
        with self.lock:
            row = self.conn.execute(
                "SELECT id, data FROM findings WHERE scan_id=? AND fingerprint=?", (scan_id, finding.fingerprint)
            ).fetchone()
            if row:
                existing = json.loads(row["data"])
                if existing.get("source") != finding.source and finding.source not in existing.get("notes", ""):
                    existing["notes"] = (existing.get("notes", "") + " Also reported by %s." % finding.source).strip()
                    self.conn.execute("UPDATE findings SET data=? WHERE id=?", (json.dumps(existing), row["id"]))
                    self.conn.commit()
                return False
            self.conn.execute(
                "INSERT INTO findings (scan_id,fingerprint,severity,status,title,data) VALUES (?,?,?,?,?,?)",
                (scan_id, finding.fingerprint, finding.severity, finding.status, finding.title, json.dumps(data)),
            )
            self.conn.commit()
            return True

    def add_asset(self, scan_id, kind, value, data=None):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO assets (scan_id,kind,value,data) VALUES (?,?,?,?)",
                (scan_id, kind, value, json.dumps(data or {})),
            )
            self.conn.commit()

    def add_plugin_run(self, scan_id, plugin_id, status, duration, message, count):
        with self.lock:
            self.conn.execute(
                "INSERT INTO plugin_runs (scan_id,plugin_id,status,duration,message,findings) VALUES (?,?,?,?,?,?)",
                (scan_id, plugin_id, status, duration, message, count),
            )
            self.conn.commit()

    def get_scan(self, scan_id):
        with self.lock:
            row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return self._scan(row) if row else None

    def list_scans(self, limit=100):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM scans ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        return [self._scan(r) for r in rows]

    def latest_scan_id(self):
        with self.lock:
            row = self.conn.execute("SELECT id FROM scans ORDER BY started DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    def get_findings(self, scan_id, severity=None):
        query = "SELECT id, data FROM findings WHERE scan_id=?"
        args = [scan_id]
        if severity:
            query += " AND severity=?"
            args.append(severity)
        with self.lock:
            rows = self.conn.execute(query, args).fetchall()
        out = []
        for row in rows:
            item = json.loads(row["data"])
            item["id"] = row["id"]
            out.append(item)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        out.sort(key=lambda f: (order.get(f["severity"], 5), -(f.get("cvss_score") or 0), f["title"]))
        return out

    def get_finding(self, finding_id):
        with self.lock:
            row = self.conn.execute("SELECT id, scan_id, data FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return None
        item = json.loads(row["data"])
        item["id"] = row["id"]
        item["scan_id"] = row["scan_id"]
        return item

    def get_assets(self, scan_id=None):
        query = "SELECT scan_id, kind, value, data FROM assets"
        args = []
        if scan_id:
            query += " WHERE scan_id=?"
            args.append(scan_id)
        with self.lock:
            rows = self.conn.execute(query, args).fetchall()
        return [{"scan_id": r["scan_id"], "kind": r["kind"], "value": r["value"], "data": json.loads(r["data"])} for r in rows]

    def plugin_runs(self, scan_id):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM plugin_runs WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def delete_scan(self, scan_id):
        with self.lock:
            for table in ("findings", "assets", "plugin_runs"):
                self.conn.execute("DELETE FROM %s WHERE scan_id=?" % table, (scan_id,))
            self.conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            self.conn.commit()

    def counts(self):
        with self.lock:
            rows = self.conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity").fetchall()
            scans = self.conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        return {"severity": {r["severity"]: r["c"] for r in rows}, "scans": scans}

    @staticmethod
    def _scan(row):
        data = dict(row)
        for key in ("options", "summary"):
            if data.get(key):
                try:
                    data[key] = json.loads(data[key])
                except ValueError:
                    pass
        return data

    def close(self):
        with self.lock:
            self.conn.close()
