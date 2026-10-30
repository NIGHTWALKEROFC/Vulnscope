import os

from vulnscope.config import Config
from vulnscope.context import Context
from vulnscope.db import Store
from vulnscope.engine import make_target
from vulnscope.plugins.source_secrets import SourceSecrets
from vulnscope.plugins.source_patterns import SourcePatterns
from vulnscope.scope import build_scope

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "source_project")


def _ctx(tmp_path):
    cfg = Config.load(tmp_path / "home")
    store = Store(cfg.db_path)
    target = make_target(FIXTURE, "source")
    scope = build_scope(target)
    scan_id = store.create_scan(target.value, "source", "standard", {}, "")
    import threading
    return Context(scan_id, target, "standard", cfg, store, scope, None, {}, threading.Event(), {"lock": threading.Lock(), "data": {}})


def test_source_secrets_finds_aws_key(tmp_path):
    ctx = _ctx(tmp_path)
    plug = SourceSecrets()
    ctx.plugin_id = plug.id
    findings = list(plug.run(ctx))
    assert any("AWS" in f.title for f in findings)


def test_source_patterns_finds_shell_true(tmp_path):
    ctx = _ctx(tmp_path)
    plug = SourcePatterns()
    ctx.plugin_id = plug.id
    findings = list(plug.run(ctx))
    assert any("shell=True".lower() in f.title.lower() or "subprocess" in f.title.lower() for f in findings)
