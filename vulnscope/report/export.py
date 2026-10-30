import csv
import html
import io
import json
import time

from vulnscope.models import severity_counts

_SEV_COLOR = {"critical": "#8b1a1a", "high": "#b84a1e", "medium": "#9a7b12", "low": "#3b6e3b", "info": "#3a6b8a", "unknown": "#555"}


def to_json(scan, findings, assets=None, plugin_runs=None):
    return json.dumps({
        "scan": scan, "findings": findings, "assets": assets or [], "plugin_runs": plugin_runs or [],
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2, default=str)


def to_csv(findings):
    buf = io.StringIO()
    fields = ["title", "severity", "status", "confidence", "category", "cve", "cvss_score", "target", "location",
             "source", "known_exploited", "remediation"]
    writer = csv.writer(buf)
    writer.writerow(fields)
    for item in findings:
        row = []
        for field in fields:
            value = item.get(field, "")
            if isinstance(value, list):
                value = ", ".join(value)
            row.append(value)
        writer.writerow(row)
    return buf.getvalue()


def _esc(value):
    return html.escape(str(value or ""), quote=True)


def to_html(scan, findings, assets=None, plugin_runs=None):
    counts = severity_counts(findings)
    rows = []
    for item in findings:
        color = _SEV_COLOR.get(item.get("severity", "unknown"), "#555")
        cves = ", ".join(item.get("cve") or [])
        kev = " ⚠ KEV" if item.get("known_exploited") else ""
        refs = "".join('<li><a href="%s">%s</a></li>' % (_esc(r), _esc(r)) for r in (item.get("references") or [])[:6])
        rows.append("""
        <div class="finding" style="border-left-color:%s">
          <div class="f-head"><span class="sev" style="background:%s">%s%s</span>
            <span class="status">%s</span><h3>%s</h3></div>
          <div class="meta">%s%s%s</div>
          <table>
            <tr><th>Evidence</th><td>%s</td></tr>
            <tr><th>Impact</th><td>%s</td></tr>
            <tr><th>Remediation</th><td>%s</td></tr>
            <tr><th>Rule basis</th><td>%s</td></tr>
            %s
          </table>
          %s
        </div>""" % (
            color, color, _esc(item.get("severity", "unknown")).upper(), kev, _esc(item.get("status", "")),
            _esc(item.get("title", "")),
            "Category: %s &nbsp;·&nbsp; " % _esc(item.get("category", "")),
            ("CVE: %s &nbsp;·&nbsp; " % _esc(cves)) if cves else "",
            "Confidence: %s" % _esc(item.get("confidence", "")),
            _esc(item.get("evidence", "")), _esc(item.get("impact", "")), _esc(item.get("remediation", "")),
            _esc(item.get("rule_basis", "")),
            ('<tr><th>Location</th><td>%s</td></tr>' % _esc(item.get("location", ""))) if item.get("location") else "",
            ("<p class='refs'>References:</p><ul>%s</ul>" % refs) if refs else "",
        ))
    summary_bars = "".join(
        '<div class="bar"><span class="label">%s</span><span class="count" style="background:%s">%d</span></div>' %
        (sev, _SEV_COLOR.get(sev, "#555"), counts.get(sev, 0)) for sev in ("critical", "high", "medium", "low", "info", "unknown")
    )
    return """<!doctype html><html><head><meta charset="utf-8">
<title>VulnScope report: %s</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f6f6;--border:#ddd}
@media (prefers-color-scheme: dark){:root{--bg:#14161a;--fg:#e8e8e8;--muted:#9aa0a6;--card:#1d2026;--border:#2b2f36}}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:980px;margin-inline:auto}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
.bar{display:flex;flex-direction:column;align-items:center;font-size:.8rem;color:var(--muted)}
.count{color:#fff;border-radius:6px;padding:4px 10px;font-weight:600;margin-top:4px}
.finding{background:var(--card);border:1px solid var(--border);border-left-width:5px;border-radius:8px;padding:14px 16px;margin:12px 0}
.f-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.f-head h3{margin:0;font-size:1rem;flex:1}
.sev{color:#fff;border-radius:5px;padding:2px 8px;font-size:.75rem;font-weight:700}
.status{font-size:.75rem;color:var(--muted);border:1px solid var(--border);border-radius:5px;padding:2px 8px}
.meta{font-size:.8rem;color:var(--muted);margin:6px 0}
table{width:100%%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;color:var(--muted);vertical-align:top;padding:3px 10px 3px 0;white-space:nowrap}
td{padding:3px 0}
.refs{margin:8px 0 2px;font-size:.8rem;color:var(--muted)}
ul{margin:2px 0;padding-left:18px;font-size:.8rem}
a{color:#4a90d9}
</style></head><body>
<h1>VulnScope assessment report</h1>
<p>Target: <strong>%s</strong> &nbsp;·&nbsp; Profile: %s &nbsp;·&nbsp; Generated: %s</p>
<div class="summary">%s</div>
<h2>Findings (%d)</h2>
%s
</body></html>""" % (
        _esc(scan.get("target", "")), _esc(scan.get("target", "")), _esc(scan.get("profile", "")),
        time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), summary_bars, len(findings), "".join(rows) or "<p>No findings.</p>",
    )
