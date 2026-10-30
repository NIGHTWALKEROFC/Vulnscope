import time
from datetime import datetime, timedelta, timezone

from vulnscope.cvss import severity_from_score
from vulnscope.intel.netutil import get_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
WINDOW_DAYS = 119
PAGE_SIZE = 2000


def _fmt(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000")


def _metrics(metrics):
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        return data.get("baseScore"), data.get("vectorString", ""), version
    return None, "", ""


def _collect(node, require_context, out):
    for match in node.get("cpeMatch", []) or []:
        if not match.get("vulnerable"):
            continue
        parts = match.get("criteria", "").split(":")
        if len(parts) < 6:
            continue
        out.append({
            "vendor": parts[3], "product": parts[4], "version": parts[5],
            "start_incl": match.get("versionStartIncluding"), "start_excl": match.get("versionStartExcluding"),
            "end_incl": match.get("versionEndIncluding"), "end_excl": match.get("versionEndExcluding"),
            "ctx": 1 if require_context else 0,
        })
    for child in node.get("children", []) or []:
        _collect(child, require_context, out)


def parse_nvd_item(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None, []
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, vector, version = _metrics(cve.get("metrics", {}))
    tags = [t.get("tag", "") for t in cve.get("cveTags", []) or []]
    record = {
        "id": cve_id, "status": cve.get("vulnStatus", ""), "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""), "description": desc, "cvss_score": score,
        "cvss_vector": vector, "cvss_version": version, "severity": severity_from_score(score),
        "source": "NVD", "disputed": 1 if "disputed" in tags else 0,
        "refs": [r.get("url") for r in cve.get("references", []) if r.get("url")][:12],
    }
    cpes = []
    for config in cve.get("configurations", []) or []:
        nodes = config.get("nodes", []) or []
        context = config.get("operator") == "AND" and len(nodes) > 1
        for node in nodes:
            _collect(node, context, cpes)
    return record, cpes


def ingest_nvd_page(intel, payload):
    count = 0
    for item in payload.get("vulnerabilities", []):
        record, cpes = parse_nvd_item(item)
        if record:
            intel.upsert_cve(record, cpes)
            count += 1
    intel.commit()
    return count


def _windows(start, end):
    cursor = start
    while cursor < end:
        nxt = min(cursor + timedelta(days=WINDOW_DAYS), end)
        yield cursor, nxt
        cursor = nxt


def sync_nvd(intel, cfg, since_year=None, days=None, full=False, progress=None, cancel=None):
    say = progress or (lambda msg: None)
    key = cfg.data["intel"].get("nvd_api_key", "")
    headers = {"apiKey": key} if key else {}
    pause = 0.7 if key else 6.5
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    started = time.time()
    last = intel.get_meta("nvd_last_sync")
    if days:
        mode, start = "lastMod", now - timedelta(days=days)
    elif last and not full and not intel.get_meta("nvd_cursor"):
        mode, start = "lastMod", datetime.fromtimestamp(float(last), timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    else:
        mode = "pub"
        year = 1999 if full else (since_year or max(2015, now.year - 10))
        start = datetime(year, 1, 1)
        cursor = intel.get_meta("nvd_cursor")
        if cursor:
            start = max(start, datetime.strptime(cursor, "%Y-%m-%dT%H:%M:%S"))
    total = 0
    for w_start, w_end in _windows(start, now):
        if cancel and cancel():
            say("cancelled")
            return total
        index = 0
        while True:
            params = {
                "resultsPerPage": PAGE_SIZE, "startIndex": index,
                ("lastModStartDate" if mode == "lastMod" else "pubStartDate"): _fmt(w_start),
                ("lastModEndDate" if mode == "lastMod" else "pubEndDate"): _fmt(w_end),
            }
            payload, _ = get_json(NVD_URL, params=params, headers=headers, timeout=120)
            total += ingest_nvd_page(intel, payload)
            index += payload.get("resultsPerPage", 0)
            say("NVD %s %s: %d records" % (mode, w_start.date(), total))
            time.sleep(pause)
            if index >= payload.get("totalResults", 0) or not payload.get("resultsPerPage"):
                break
        if mode == "pub":
            intel.set_meta("nvd_cursor", w_end.strftime("%Y-%m-%dT%H:%M:%S"))
    intel.set_meta("nvd_last_sync", started)
    intel.set_meta("nvd_cursor", "")
    return total


def sync_kev(intel, progress=None):
    say = progress or (lambda msg: None)
    etag = intel.get_meta("kev_etag") or None
    payload, headers = get_json(KEV_URL, etag=etag, timeout=60)
    if payload is None:
        intel.set_meta("kev_last_sync", time.time())
        say("KEV catalog unchanged")
        return 0
    rows = []
    for item in payload.get("vulnerabilities", []):
        rows.append({
            "cve_id": item.get("cveID", "").upper(), "vendor": item.get("vendorProject", ""),
            "product": item.get("product", ""), "name": item.get("vulnerabilityName", ""),
            "date_added": item.get("dateAdded", ""), "due": item.get("dueDate", ""),
            "ransomware": item.get("knownRansomwareCampaignUse", ""), "action": item.get("requiredAction", ""),
        })
    intel.replace_kev(rows)
    if headers.get("ETag"):
        intel.set_meta("kev_etag", headers["ETag"])
    intel.set_meta("kev_last_sync", time.time())
    say("KEV catalog: %d entries" % len(rows))
    return len(rows)
