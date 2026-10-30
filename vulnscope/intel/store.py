import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
  id TEXT PRIMARY KEY, status TEXT, published TEXT, modified TEXT, description TEXT,
  cvss_score REAL, cvss_vector TEXT, cvss_version TEXT, severity TEXT, source TEXT,
  disputed INTEGER DEFAULT 0, refs TEXT
);
CREATE TABLE IF NOT EXISTS cpe (
  id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT, vendor TEXT, product TEXT, version TEXT,
  start_incl TEXT, start_excl TEXT, end_incl TEXT, end_excl TEXT, ctx INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe(product);
CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe(cve_id);
CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT,
  due TEXT, ransomware TEXT, action TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS osv_cache (key TEXT PRIMARY KEY, value TEXT, fetched REAL);
CREATE TABLE IF NOT EXISTS osv_vuln (id TEXT PRIMARY KEY, data TEXT, fetched REAL);
"""

_CVE_SELECT = (
    "SELECT c.*, k.cve_id AS kev_id, k.date_added AS kev_added, k.due AS kev_due, "
    "k.action AS kev_action, k.ransomware AS kev_ransomware FROM cve c LEFT JOIN kev k ON k.cve_id=c.id "
)


class IntelDB:
    def __init__(self, path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def get_meta(self, key, default=None):
        with self.lock:
            row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key, value):
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES (?,?)", (key, str(value)))
            self.conn.commit()

    def upsert_cve(self, record, cpes):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cve (id,status,published,modified,description,cvss_score,cvss_vector,"
                "cvss_version,severity,source,disputed,refs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (record["id"], record["status"], record["published"], record["modified"], record["description"],
                 record["cvss_score"], record["cvss_vector"], record["cvss_version"], record["severity"],
                 record["source"], int(record.get("disputed", 0)), json.dumps(record.get("refs", []))),
            )
            self.conn.execute("DELETE FROM cpe WHERE cve_id=?", (record["id"],))
            self.conn.executemany(
                "INSERT INTO cpe (cve_id,vendor,product,version,start_incl,start_excl,end_incl,end_excl,ctx) VALUES (?,?,?,?,?,?,?,?,?)",
                [(record["id"], c["vendor"], c["product"], c["version"], c.get("start_incl"), c.get("start_excl"),
                  c.get("end_incl"), c.get("end_excl"), c.get("ctx", 0)) for c in cpes],
            )

    def commit(self):
        with self.lock:
            self.conn.commit()

    def replace_kev(self, rows):
        with self.lock:
            self.conn.execute("DELETE FROM kev")
            self.conn.executemany(
                "INSERT OR REPLACE INTO kev (cve_id,vendor,product,name,date_added,due,ransomware,action) VALUES (?,?,?,?,?,?,?,?)",
                [(r["cve_id"], r["vendor"], r["product"], r["name"], r["date_added"], r["due"], r["ransomware"], r["action"]) for r in rows],
            )
            self.conn.commit()

    def get_cve(self, cve_id):
        with self.lock:
            row = self.conn.execute(_CVE_SELECT + "WHERE c.id=?", (cve_id.upper(),)).fetchone()
        return self._cve(row) if row else None

    def kev_entry(self, cve_id):
        with self.lock:
            row = self.conn.execute("SELECT * FROM kev WHERE cve_id=?", (cve_id.upper(),)).fetchone()
        return dict(row) if row else None

    def search(self, query="", limit=50, product=None, version=None):
        from vulnscope.intel.aliases import lookup
        from vulnscope.intel.matcher import find_matches

        if product:
            pairs = lookup(product) or [(None, product.lower())]
            if version:
                return [m["cve"] for m in find_matches(self, pairs, version, limit=limit)]
            marks = ",".join("?" for _ in pairs)
            with self.lock:
                rows = self.conn.execute(
                    _CVE_SELECT + "WHERE c.id IN (SELECT cve_id FROM cpe WHERE product IN (%s)) "
                    "ORDER BY c.published DESC LIMIT ?" % marks, [p for _, p in pairs] + [limit]).fetchall()
            return [self._cve(r) for r in rows]
        query = (query or "").strip()
        with self.lock:
            if query.upper().startswith("CVE-"):
                rows = self.conn.execute(_CVE_SELECT + "WHERE c.id LIKE ? ORDER BY c.id DESC LIMIT ?",
                                         (query.upper() + "%", limit)).fetchall()
            else:
                like = "%" + query.replace("%", "") + "%"
                rows = self.conn.execute(
                    _CVE_SELECT + "WHERE c.description LIKE ? OR c.id IN (SELECT cve_id FROM cpe WHERE product LIKE ? OR vendor LIKE ?) "
                    "ORDER BY c.published DESC LIMIT ?", (like, like, like, limit)).fetchall()
        return [self._cve(r) for r in rows]

    def stats(self):
        with self.lock:
            cves = self.conn.execute("SELECT COUNT(*) c FROM cve").fetchone()["c"]
            kev = self.conn.execute("SELECT COUNT(*) c FROM kev").fetchone()["c"]
            cpes = self.conn.execute("SELECT COUNT(*) c FROM cpe").fetchone()["c"]
            osv = self.conn.execute("SELECT COUNT(*) c FROM osv_vuln").fetchone()["c"]
        size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        return {
            "cves": cves, "cpe_entries": cpes, "kev": kev, "osv_cached": osv, "size_bytes": size,
            "nvd_last_sync": self.get_meta("nvd_last_sync"), "kev_last_sync": self.get_meta("kev_last_sync"),
            "nvd_cursor": self.get_meta("nvd_cursor"),
        }

    def freshness(self, stale_days):
        stamp = self.get_meta("nvd_last_sync")
        if not stamp:
            return "empty"
        age = (time.time() - float(stamp)) / 86400.0
        return "stale" if age > stale_days else "current"

    def osv_cache_get(self, key, ttl_hours=None):
        with self.lock:
            row = self.conn.execute("SELECT value, fetched FROM osv_cache WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        if ttl_hours is not None and time.time() - row["fetched"] > ttl_hours * 3600:
            return None
        return json.loads(row["value"])

    def osv_cache_any(self, key):
        return self.osv_cache_get(key, None)

    def osv_cache_put(self, key, value):
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO osv_cache (key,value,fetched) VALUES (?,?,?)",
                              (key, json.dumps(value), time.time()))
            self.conn.commit()

    def osv_vuln_get(self, vuln_id):
        with self.lock:
            row = self.conn.execute("SELECT data FROM osv_vuln WHERE id=?", (vuln_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def osv_vuln_put(self, vuln_id, data):
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO osv_vuln (id,data,fetched) VALUES (?,?,?)",
                              (vuln_id, json.dumps(data), time.time()))
            self.conn.commit()

    def vacuum(self):
        with self.lock:
            self.conn.commit()
            self.conn.execute("VACUUM")

    def clear_osv_cache(self):
        with self.lock:
            self.conn.execute("DELETE FROM osv_cache")
            self.conn.execute("DELETE FROM osv_vuln")
            self.conn.commit()

    @staticmethod
    def _cve(row):
        data = dict(row)
        data["refs"] = json.loads(data.get("refs") or "[]")
        data["known_exploited"] = bool(data.get("kev_id"))
        return data

    def close(self):
        with self.lock:
            self.conn.close()
