from vulnscope.db import Store
from vulnscope.models import Finding


def test_scan_lifecycle(tmp_path):
    store = Store(tmp_path / "test.db")
    scan_id = store.create_scan("example.com", "host", "standard", {}, "tester")
    assert store.get_scan(scan_id)["status"] == "running"
    f = Finding(title="Open port", severity="info", status="informational", target="example.com", source="net.ports", category="x")
    assert store.add_finding(scan_id, f) is True
    assert store.add_finding(scan_id, f) is False  # duplicate fingerprint
    findings = store.get_findings(scan_id)
    assert len(findings) == 1
    store.update_scan(scan_id, status="completed")
    assert store.get_scan(scan_id)["status"] == "completed"
    store.delete_scan(scan_id)
    assert store.get_scan(scan_id) is None
