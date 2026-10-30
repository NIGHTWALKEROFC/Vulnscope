from vulnscope.report import export


def test_csv_export_has_header_and_row():
    findings = [{"title": "Test", "severity": "high", "status": "confirmed", "confidence": "high",
                "category": "x", "cve": ["CVE-2020-0001"], "cvss_score": 7.5, "target": "t", "location": "",
                "source": "s", "known_exploited": False, "remediation": "fix it"}]
    out = export.to_csv(findings)
    assert "title" in out.splitlines()[0]
    assert "Test" in out


def test_html_export_contains_title():
    scan = {"target": "example.com", "profile": "standard"}
    findings = [{"title": "Issue A", "severity": "critical", "status": "confirmed", "evidence": "e",
                "impact": "i", "remediation": "r", "rule_basis": "b", "references": [], "cve": [],
                "category": "c", "confidence": "high", "known_exploited": True}]
    html = export.to_html(scan, findings)
    assert "Issue A" in html
    assert "KEV" in html


def test_json_export_roundtrip():
    import json
    out = export.to_json({"id": "1"}, [])
    data = json.loads(out)
    assert data["scan"]["id"] == "1"
