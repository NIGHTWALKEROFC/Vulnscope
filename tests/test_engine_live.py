from vulnscope.config import Config
from vulnscope.db import Store
from vulnscope.engine import ScanEngine, make_target


def test_scan_web_target(tmp_path, test_server):
    cfg = Config.load(tmp_path / "home")
    cfg.apply_lite()
    cfg.data["scan"]["require_ack"] = False
    store = Store(cfg.db_path)
    engine = ScanEngine(cfg, store, intel=None)
    target = make_target(test_server)
    scan_id = engine.run(target, profile="standard", options={"allow_private": True})
    scan = store.get_scan(scan_id)
    assert scan["status"] == "completed"
    findings = store.get_findings(scan_id)
    titles = {f["title"] for f in findings}
    assert any("cleartext" in t.lower() or "http" in t.lower() for t in titles)
    assert any("jquery" in t.lower() for t in titles)
