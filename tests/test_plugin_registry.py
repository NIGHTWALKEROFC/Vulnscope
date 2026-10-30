from vulnscope import plugin


def test_discover_finds_web_plugins():
    registry = plugin.discover()
    assert "web.headers" in registry
    assert "net.ports" in registry
    assert "source.secrets" in registry


def test_select_respects_target_type():
    chosen, skipped = plugin.select("url", "standard", "linux")
    ids = {p.id for p in chosen}
    assert "web.headers" in ids
    assert "net.ports" not in ids


def test_select_respects_profile():
    chosen, _ = plugin.select("url", "passive", "linux")
    ids = {p.id for p in chosen}
    assert "web.cors" not in ids  # min_profile standard
    assert "web.headers" in ids
