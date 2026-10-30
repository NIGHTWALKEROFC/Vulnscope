from vulnscope.models import Finding, severity_counts


def test_finding_defaults_and_fingerprint():
    f = Finding(title="X", severity="bogus", status="bogus", target="t", source="s", category="c")
    assert f.severity == "unknown"
    assert f.status == "potential"
    assert len(f.fingerprint) == 24


def test_fingerprint_deterministic():
    a = Finding(title="X", severity="high", status="confirmed", target="t", source="s", category="c", rule_id="r1", location="l1")
    b = Finding(title="X", severity="high", status="confirmed", target="t", source="s", category="c", rule_id="r1", location="l1")
    assert a.fingerprint == b.fingerprint


def test_severity_counts():
    items = [Finding(title=str(i), severity=s, status="confirmed", target="t", source="s", category="c")
             for i, s in enumerate(["high", "high", "low"])]
    counts = severity_counts(items)
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0
