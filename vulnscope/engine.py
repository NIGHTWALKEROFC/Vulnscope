import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from vulnscope import __version__, plugin as plugin_mod
from vulnscope.models import Target, severity_counts
from vulnscope.context import Context
from vulnscope.platform_info import detect_os
from vulnscope.scope import Cancelled, ScopeError, build_scope, is_ip, normalize_url, split_url

log = logging.getLogger("vulnscope.engine")
GRACE = 20


def make_target(raw, kind=None):
    import os

    text = raw.strip()
    if kind is None:
        lower = text.lower()
        if lower.startswith(("http://", "https://")):
            kind = "url"
        elif lower == "local":
            kind = "local"
        elif os.path.isdir(text):
            kind = "source"
        elif os.path.isfile(text):
            if lower.endswith(".apk"):
                kind = "apk"
            elif lower.endswith(".ipa"):
                kind = "ipa"
            elif lower.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
                kind = "archive"
            else:
                kind = "source"
        elif "/" in text and all(_is_net(p) for p in text.split("/", 1)[:1]):
            kind = "host"
        else:
            kind = "host"
    if kind == "url":
        url = normalize_url(text)
        scheme, host, port = split_url(url)
        return Target("url", url, host, port, scheme)
    if kind == "host":
        host = text
        try:
            ipaddress.ip_network(host, strict=False)
        except ValueError:
            host = host.lower().strip(".")
        return Target("host", host, host)
    if kind in ("source", "apk", "ipa", "archive"):
        return Target(kind, os.path.abspath(text))
    return Target(kind, text)


def _is_net(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class ScanEngine:
    def __init__(self, config, store, intel=None):
        self.config = config
        self.store = store
        self.intel = intel

    def run(self, target, profile="standard", scope=None, options=None, cancel=None, progress=None,
            include=None, exclude=None, authorization="", scan_id=None):
        options = dict(options or {})
        cancel = cancel or threading.Event()
        if target.kind in ("url", "host") and scope is None:
            scope = build_scope(target, options.get("scope", ()), options.get("allow_private", False))
        if scope is None:
            scope = build_scope(target)
        os_name = detect_os()
        authenticated = bool(options.get("headers") or options.get("cookies"))
        disabled = self.config.data["plugins"]["disabled"]
        plugins, skipped = plugin_mod.select(target.kind, profile, os_name, disabled, include, exclude, authenticated)
        if scan_id is None:
            scan_id = self.store.create_scan(target.value, target.kind, profile, _public_options(options), authorization)
        else:
            self.store.update_scan(scan_id, status="running")
        started = time.time()
        shared = {"lock": threading.RLock(), "data": {}}
        base_ctx = Context(scan_id, target, profile, self.config, self.store, scope, self.intel, options, cancel, shared, __version__)
        for plug, reason in skipped:
            self.store.add_plugin_run(scan_id, plug.id, "skipped", 0.0, reason, 0)
        total = len(plugins)
        done = 0
        counts = {"requests": 0}
        lock = threading.Lock()
        running = {}
        abandoned = set()

        def report(current=""):
            fraction = done / total if total else 1.0
            self.store.update_scan(scan_id, progress=fraction, current=current)
            if progress:
                progress(scan_id, fraction, current)

        def worker(plug):
            nonlocal done
            ctx = base_ctx.bind(plug)
            began = time.monotonic()
            with lock:
                running[plug.id] = (began, ctx, plug)
            status, message, found = "ok", "", 0
            try:
                for finding in plug.run(ctx) or ():
                    ctx.check()
                    if self.store.add_finding(scan_id, finding):
                        found += 1
            except Cancelled:
                status = "cancelled" if cancel.is_set() else "timeout"
                message = "stopped before completion"
            except ScopeError as exc:
                status, message = "error", "scope: %s" % exc
            except Exception as exc:
                status, message = "error", "%s: %s" % (type(exc).__name__, str(exc)[:300])
                log.warning("plugin %s failed: %s", plug.id, message)
            try:
                plug.cleanup(ctx)
            except Exception:
                pass
            with lock:
                running.pop(plug.id, None)
                counts["requests"] += ctx.requests_made
                if plug.id in abandoned:
                    return
                done += 1
            self.store.add_plugin_run(scan_id, plug.id, status, time.monotonic() - began, message, found)
            report(plug.id)

        error = ""
        pool = ThreadPoolExecutor(max_workers=int(self.config.data["scan"]["concurrency"]))
        futures = [pool.submit(worker, p) for p in plugins]
        report("starting")
        while True:
            if all(f.done() for f in futures):
                break
            now = time.monotonic()
            with lock:
                snapshot = list(running.items())
            for pid, (began, ctx, plug) in snapshot:
                limit = plug.timeout * float(self.config.data["scan"]["plugin_timeout_scale"]) + GRACE
                if now - began > limit and pid not in abandoned:
                    abandoned.add(pid)
                    ctx.stop_plugin()
                    with lock:
                        done += 1
                    self.store.add_plugin_run(scan_id, pid, "timeout", now - began, "exceeded time limit", 0)
                    report(pid)
            if cancel.is_set() and all(f.done() or f.cancelled() for f in futures):
                break
            time.sleep(0.25)
        pool.shutdown(wait=False, cancel_futures=True)
        findings = self.store.get_findings(scan_id)
        status = "cancelled" if cancel.is_set() else "completed"
        summary = {
            "severity": severity_counts(findings), "total": len(findings), "plugins_run": total,
            "plugins_skipped": [{"id": p.id, "reason": r} for p, r in skipped],
            "requests": counts["requests"], "duration": round(time.time() - started, 2),
        }
        self.store.update_scan(scan_id, status=status, finished=time.time(), summary=summary, progress=1.0, error=error, current="")
        if progress:
            progress(scan_id, 1.0, "")
        return scan_id


def _public_options(options):
    safe = {}
    for key, value in options.items():
        if key in ("headers", "cookies", "headers2", "cookies2"):
            safe[key] = "[set]" if value else ""
        else:
            safe[key] = value
    return safe
