from vulnscope.intel.aliases import lookup
from vulnscope.versions import compare_versions, in_range

_BAD_STATUS = {"rejected", "withdrawn"}


def _row_matches(row, version):
    ver = row["version"]
    if ver not in ("*", "-", ""):
        return compare_versions(version, ver) == 0
    if not any((row["start_incl"], row["start_excl"], row["end_incl"], row["end_excl"])):
        return False
    return in_range(version, row["start_incl"], row["start_excl"], row["end_incl"], row["end_excl"])


def find_matches(intel, pairs, version, limit=None):
    if not pairs or not version:
        return []
    products = sorted({p for _, p in pairs})
    vendors = {v for v, _ in pairs if v}
    marks = ",".join("?" for _ in products)
    with intel.lock:
        rows = intel.conn.execute("SELECT * FROM cpe WHERE product IN (%s)" % marks, products).fetchall()
    found = {}
    for row in rows:
        if vendors and row["vendor"] not in vendors:
            continue
        if not _row_matches(row, version):
            continue
        entry = found.setdefault(row["cve_id"], {"needs_context": True})
        if not row["ctx"]:
            entry["needs_context"] = False
    results = []
    for cve_id, info in found.items():
        cve = intel.get_cve(cve_id)
        if not cve or (cve["status"] or "").lower() in _BAD_STATUS:
            continue
        results.append({"cve": cve, "needs_context": info["needs_context"]})
    results.sort(key=lambda m: (not m["cve"]["known_exploited"], -(m["cve"]["cvss_score"] or 0), m["cve"]["id"]))
    return results[:limit] if limit else results


def match_product(intel, name, version, limit=None):
    pairs = lookup(name)
    if not pairs:
        return []
    return find_matches(intel, pairs, version, limit)


def cve_findings(ctx, label, version, evidence, confidence, target=None, location="", category="Known vulnerable component"):
    intel = ctx.intel
    if intel is None:
        return []
    limit = int(ctx.config.data["scan"]["max_cves_per_product"])
    matches = match_product(intel, label, version)
    out = []
    for item in matches[:limit]:
        cve = item["cve"]
        status = "potential" if item["needs_context"] or cve.get("disputed") else "version_match"
        conf = "low" if cve.get("disputed") else confidence
        notes = "Version evidence comes from a banner or file name; vendor back-ported fixes can make this a false positive."
        if item["needs_context"]:
            notes += " The advisory also requires platform conditions that were not verified."
        if cve.get("disputed"):
            notes += " The CVE record is marked disputed."
        out.append(ctx.finding(
            "%s %s: %s" % (label, version, cve["id"]), cve["severity"] or "unknown", status, category,
            target=target or ctx.target.value, confidence=conf,
            rule_id="cve:" + cve["id"], rule_basis="Affected-version range from %s" % cve["source"],
            evidence="%s Matched %s %s against %s." % (evidence, label, version, cve["id"]),
            impact=(cve["description"] or "")[:400],
            remediation="Upgrade %s to a release that fixes %s or apply the vendor mitigation." % (label, cve["id"]),
            references=cve["refs"][:6] + ["https://nvd.nist.gov/vuln/detail/" + cve["id"]],
            cve=[cve["id"]], cvss_score=cve["cvss_score"], cvss_vector=cve["cvss_vector"] or "",
            cvss_version=cve["cvss_version"] or "", location=location, notes=notes,
            known_exploited=cve["known_exploited"],
        ))
    extra = len(matches) - limit
    if extra > 0:
        out.append(ctx.finding(
            "%s %s: %d additional CVE matches not listed" % (label, version, extra), "info", "informational", category,
            target=target or ctx.target.value, rule_id="cve-overflow:%s:%s" % (label, version), confidence="medium",
            evidence="Only the %d highest-ranked matches are shown." % limit, location=location,
            remediation="Review the full list with: vulnscope intel search --product %s --version %s" % (label, version),
        ))
    return out
