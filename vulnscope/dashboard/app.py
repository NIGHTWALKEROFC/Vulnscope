import threading
import time

from flask import Flask, jsonify, request, send_file

from vulnscope import __version__, plugin as plugin_mod
from vulnscope.db import Store
from vulnscope.engine import ScanEngine, make_target
from vulnscope.intel import IntelDB
from vulnscope.intel.sync import sync_kev, sync_nvd
from vulnscope.platform_info import detect_os, diagnostics
from vulnscope.report import export
from vulnscope.scope import build_scope

_RUNNING = {}
_RUNNING_LOCK = threading.Lock()


def create_app(cfg):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["cfg"] = cfg
    store = Store(cfg.db_path)
    try:
        intel = IntelDB(cfg.intel_path)
    except Exception:
        intel = None
    engine = ScanEngine(cfg, store, intel)

    @app.get("/")
    def index():
        return send_file(__file__.rsplit("/", 1)[0] + "/static/index.html")

    @app.get("/api/diagnostics")
    def api_diag():
        return jsonify(diagnostics(cfg.home))

    @app.get("/api/plugins")
    def api_plugins():
        plugins = plugin_mod.discover()
        os_name = detect_os()
        return jsonify([plugins[pid].describe(os_name) for pid in sorted(plugins)])

    @app.get("/api/overview")
    def api_overview():
        counts = store.counts()
        intel_stats = intel.stats() if intel else None
        return jsonify({"counts": counts, "intel": intel_stats, "version": __version__})

    @app.get("/api/scans")
    def api_scans():
        return jsonify(store.list_scans(int(request.args.get("limit", 100))))

    @app.get("/api/scans/<scan_id>")
    def api_scan(scan_id):
        scan = store.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "not found"}), 404
        return jsonify(scan)

    @app.get("/api/scans/<scan_id>/findings")
    def api_findings(scan_id):
        return jsonify(store.get_findings(scan_id, request.args.get("severity")))

    @app.get("/api/findings/<int:finding_id>")
    def api_finding(finding_id):
        item = store.get_finding(finding_id)
        if not item:
            return jsonify({"error": "not found"}), 404
        return jsonify(item)

    @app.get("/api/scans/<scan_id>/assets")
    def api_assets(scan_id):
        return jsonify(store.get_assets(scan_id))

    @app.get("/api/scans/<scan_id>/plugin-runs")
    def api_plugin_runs(scan_id):
        return jsonify(store.plugin_runs(scan_id))

    @app.get("/api/scans/<scan_id>/export")
    def api_export(scan_id):
        fmt = request.args.get("format", "html")
        scan = store.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "not found"}), 404
        findings = store.get_findings(scan_id)
        assets = store.get_assets(scan_id)
        runs = store.plugin_runs(scan_id)
        if fmt == "json":
            body, mimetype = export.to_json(scan, findings, assets, runs), "application/json"
        elif fmt == "csv":
            body, mimetype = export.to_csv(findings), "text/csv"
        else:
            body, mimetype = export.to_html(scan, findings, assets, runs), "text/html"
        from flask import Response

        return Response(body, mimetype=mimetype, headers={"Content-Disposition": "attachment; filename=vulnscope-%s.%s" % (scan_id, fmt)})

    @app.delete("/api/scans/<scan_id>")
    def api_delete(scan_id):
        store.delete_scan(scan_id)
        return jsonify({"ok": True})

    @app.post("/api/scan")
    def api_start_scan():
        data = request.get_json(force=True) or {}
        target_raw = (data.get("target") or "").strip()
        if not target_raw:
            return jsonify({"error": "target is required"}), 400
        if not data.get("authorized"):
            return jsonify({"error": "authorization acknowledgement is required"}), 400
        try:
            target = make_target(target_raw, data.get("target_type") or None)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        options = {"scope": data.get("scope") or [], "allow_private": bool(data.get("allow_private"))}
        if data.get("headers"):
            options["headers"] = data["headers"]
        if data.get("cookies"):
            options["cookies"] = data["cookies"]
        try:
            scope = build_scope(target, options["scope"], options["allow_private"]) if target.kind in ("url", "host") else None
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        cancel = threading.Event()
        scan_id = store.create_scan(target.value, target.kind, data.get("profile", "standard"), {}, data.get("authorized_by", ""))
        with _RUNNING_LOCK:
            _RUNNING[scan_id] = cancel

        def work():
            try:
                engine.run(target, profile=data.get("profile", "standard"), scope=scope, options=options, cancel=cancel,
                          include=data.get("only"), exclude=data.get("exclude"),
                          authorization=data.get("authorized_by", ""), scan_id=scan_id)
            finally:
                with _RUNNING_LOCK:
                    _RUNNING.pop(scan_id, None)

        threading.Thread(target=work, daemon=True).start()
        return jsonify({"scan_id": scan_id})

    @app.post("/api/scans/<scan_id>/cancel")
    def api_cancel(scan_id):
        with _RUNNING_LOCK:
            cancel = _RUNNING.get(scan_id)
        if cancel:
            cancel.set()
            return jsonify({"ok": True})
        return jsonify({"ok": False, "reason": "scan is not running"}), 404

    @app.post("/api/intel/update")
    def api_intel_update():
        if intel is None:
            return jsonify({"error": "intelligence database unavailable"}), 500
        data = request.get_json(silent=True) or {}

        def work():
            sync_nvd(intel, cfg, since_year=data.get("since_year"), days=data.get("days"), full=bool(data.get("full")))
            sync_kev(intel)

        threading.Thread(target=work, daemon=True).start()
        return jsonify({"started": True})

    @app.get("/api/intel/search")
    def api_intel_search():
        if intel is None:
            return jsonify({"error": "intelligence database unavailable"}), 500
        results = intel.search(request.args.get("q", ""), limit=int(request.args.get("limit", 50)),
                               product=request.args.get("product"), version=request.args.get("version"))
        return jsonify(results)

    @app.get("/api/intel/status")
    def api_intel_status():
        if intel is None:
            return jsonify({"error": "intelligence database unavailable"}), 500
        stats = intel.stats()
        stats["freshness"] = intel.freshness(cfg.data["intel"]["stale_after_days"])
        return jsonify(stats)

    return app


def run_dashboard(cfg, host="127.0.0.1", port=8787):
    app = create_app(cfg)
    print("VulnScope dashboard running at http://%s:%d (local access only)" % (host, port))
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
