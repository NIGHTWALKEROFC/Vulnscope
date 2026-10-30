from vulnscope.config import Config
from vulnscope.dashboard.app import create_app


def test_dashboard_index_and_overview(tmp_path):
    cfg = Config.load(tmp_path / "home")
    app = create_app(cfg)
    client = app.test_client()
    assert client.get("/").status_code == 200
    r = client.get("/api/overview")
    assert r.status_code == 200
    assert "counts" in r.get_json()


def test_dashboard_scan_requires_authorization(tmp_path):
    cfg = Config.load(tmp_path / "home")
    app = create_app(cfg)
    client = app.test_client()
    r = client.post("/api/scan", json={"target": "example.com"})
    assert r.status_code == 400
