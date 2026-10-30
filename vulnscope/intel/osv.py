from concurrent.futures import ThreadPoolExecutor

from vulnscope.cvss import cvss3_score, severity_from_score
from vulnscope.intel.netutil import get_json, post_json

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"
_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def normalize(vuln):
    score, vector, severity = None, "", "unknown"
    for sev in vuln.get("severity", []) or []:
        if sev.get("type", "").startswith("CVSS_V3") and sev.get("score", "").startswith("CVSS:3"):
            vector = sev["score"]
            score = cvss3_score(vector)
            severity = severity_from_score(score)
            break
    if severity == "unknown":
        label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        severity = _LABELS.get(label, "unknown")
    fixed = []
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    refs = [r.get("url") for r in vuln.get("references", []) or [] if r.get("url")][:8]
    return {
        "id": vuln.get("id", ""), "aliases": vuln.get("aliases", []) or [],
        "summary": vuln.get("summary") or (vuln.get("details", "") or "")[:200],
        "details": (vuln.get("details", "") or "")[:600],
        "score": score, "vector": vector, "severity": severity,
        "fixed": sorted(set(fixed)), "refs": refs,
    }


class OsvClient:
    def __init__(self, intel, cfg):
        self.intel = intel
        self.ttl = cfg.data["intel"]["osv_cache_ttl_hours"]
        self.offline = bool(cfg.data["intel"]["offline"])
        self.errors = []
        self.uncached = 0

    @staticmethod
    def _key(eco, name, version):
        return "%s|%s|%s" % (eco, name.lower(), version)

    def query(self, packages):
        results = {}
        pending = []
        for idx, (eco, name, version) in enumerate(packages):
            cached = self.intel.osv_cache_get(self._key(eco, name, version), self.ttl)
            if cached is not None:
                results[idx] = cached
            else:
                pending.append(idx)
        if pending and not self.offline:
            for start in range(0, len(pending), 500):
                chunk = pending[start:start + 500]
                queries = [{"package": {"name": packages[i][1], "ecosystem": packages[i][0]}, "version": packages[i][2]} for i in chunk]
                try:
                    data = post_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
                except Exception as exc:
                    self.errors.append(str(exc)[:200])
                    break
                for i, res in zip(chunk, data.get("results", [])):
                    ids = [v["id"] for v in res.get("vulns", []) or []]
                    self.intel.osv_cache_put(self._key(*packages[i]), ids)
                    results[i] = ids
        for idx in pending:
            if idx not in results:
                stale = self.intel.osv_cache_any(self._key(*packages[idx]))
                if stale is not None:
                    results[idx] = stale
                else:
                    self.uncached += 1
        return results

    def vuln(self, vuln_id):
        cached = self.intel.osv_vuln_get(vuln_id)
        if cached is not None:
            return cached
        if self.offline:
            return None
        try:
            data, _ = get_json(VULN_URL + vuln_id, timeout=30, retries=2, backoff=2)
        except Exception as exc:
            self.errors.append(str(exc)[:200])
            return None
        norm = normalize(data)
        self.intel.osv_vuln_put(vuln_id, norm)
        return norm

    def vulns(self, ids):
        ids = sorted(set(ids))
        out = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            for vid, norm in zip(ids, pool.map(self.vuln, ids)):
                if norm:
                    out[vid] = norm
        return out
