import argparse
import json
import sys
import threading
import time

from vulnscope import __version__, plugin as plugin_mod
from vulnscope.config import Config
from vulnscope.db import Store
from vulnscope.engine import ScanEngine, make_target
from vulnscope.intel import IntelDB
from vulnscope.intel.sync import sync_kev, sync_nvd
from vulnscope.logutil import setup_logging
from vulnscope.platform_info import diagnostics
from vulnscope.report import export
from vulnscope.scope import build_scope


def _config(args):
    cfg = Config.load(getattr(args, "home", None))
    if getattr(args, "lite", False):
        cfg.apply_lite()
    if getattr(args, "offline", False):
        cfg.data["intel"]["offline"] = True
    return cfg


def _store(cfg):
    return Store(cfg.db_path)


def _intel(cfg, required=False):
    try:
        return IntelDB(cfg.intel_path)
    except Exception as exc:
        if required:
            raise
        print("warning: could not open the vulnerability database (%s)" % exc, file=sys.stderr)
        return None


def cmd_check(args):
    cfg = _config(args)
    diag = diagnostics(cfg.home)
    print("VulnScope %s" % __version__)
    print("OS: %s (%s)  Python: %s  Arch: %s" % (diag["os"], diag["platform"], diag["python"], diag["arch"]))
    disk = diag["disk"]
    print("Home: %s  Disk free: %.1f GB" % (diag["home"], disk["free"] / (1024 ** 3)))
    print("\nPython modules:")
    for name, ok in diag["modules"].items():
        print("  [%s] %s" % ("x" if ok else " ", name))
    print("\nExternal tools:")
    for name, ok in diag["binaries"].items():
        print("  [%s] %s" % ("x" if ok else " ", name))
    print("\nPlugins:")
    plugins = plugin_mod.discover()
    for pid in sorted(plugins):
        p = plugins[pid].describe(diag["os"])
        print("  [%s] %-22s %s" % ("x" if p["available"] else " ", pid, "" if p["available"] else "(%s)" % p["unavailable_reason"]))
    return 0


def cmd_plugins(args):
    plugins = plugin_mod.discover()
    for pid in sorted(plugins):
        p = plugins[pid].describe()
        if args.target_type and args.target_type not in p["target_types"]:
            continue
        print("%-20s %-45s targets=%s active=%s profile>=%s" % (
            pid, p["name"], ",".join(p["target_types"]), p["active"], p["min_profile"]))
    return 0


def _print_progress(scan_id, fraction, current):
    bar_len = 28
    filled = int(bar_len * fraction)
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stderr.write("\r[%s] %3d%%  %s%s" % (bar, int(fraction * 100), current, " " * 10))
    sys.stderr.flush()
    if fraction >= 1.0:
        sys.stderr.write("\n")


def cmd_scan(args):
    cfg = _config(args)
    store = _store(cfg)
    intel = _intel(cfg)
    setup_logging(cfg.logs_dir, args.verbose)
    if not args.yes and cfg.data["scan"]["require_ack"]:
        print("You must confirm you are authorized to assess this target.")
        reply = input("Type 'yes' to confirm authorization and continue: ").strip().lower()
        if reply != "yes":
            print("Aborted: authorization not confirmed.")
            return 1
    target = make_target(args.target, args.target_type)
    options = {"scope": args.scope or [], "allow_private": args.allow_private}
    if args.header:
        options["headers"] = dict(h.split(":", 1) for h in args.header)
        options["headers"] = {k.strip(): v.strip() for k, v in options["headers"].items()}
    if args.cookie:
        options["cookies"] = args.cookie
    engine = ScanEngine(cfg, store, intel)
    cancel = threading.Event()

    def handle_sigint(signum, frame):
        print("\nCancelling scan (finishing already-running checks)...", file=sys.stderr)
        cancel.set()

    import signal
    signal.signal(signal.SIGINT, handle_sigint)
    scope = None
    try:
        if target.kind in ("url", "host"):
            scope = build_scope(target, options["scope"], options["allow_private"])
    except Exception as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    progress = None if args.quiet else _print_progress
    scan_id = engine.run(
        target, profile=args.profile, scope=scope, options=options, cancel=cancel, progress=progress,
        include=args.only, exclude=args.exclude, authorization=args.authorized_by or "",
    )
    scan = store.get_scan(scan_id)
    findings = store.get_findings(scan_id)
    print("\nScan %s: %s" % (scan_id, scan["status"]))
    summary = scan.get("summary") or {}
    sev = summary.get("severity", {})
    print("Findings: %d  (critical=%d high=%d medium=%d low=%d info=%d)" % (
        summary.get("total", len(findings)), sev.get("critical", 0), sev.get("high", 0),
        sev.get("medium", 0), sev.get("low", 0), sev.get("info", 0)))
    if args.output:
        _write_report(cfg, store, scan_id, args.output, args.format)
    return 0


def _write_report(cfg, store, scan_id, path, fmt):
    scan = store.get_scan(scan_id)
    findings = store.get_findings(scan_id)
    assets = store.get_assets(scan_id)
    runs = store.plugin_runs(scan_id)
    if fmt == "json":
        content = export.to_json(scan, findings, assets, runs)
    elif fmt == "csv":
        content = export.to_csv(findings)
    else:
        content = export.to_html(scan, findings, assets, runs)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    print("Report written to %s" % path)


def cmd_results(args):
    cfg = _config(args)
    store = _store(cfg)
    scan_id = args.scan_id or store.latest_scan_id()
    if not scan_id:
        print("No scans found.")
        return 1
    findings = store.get_findings(scan_id, args.severity)
    if args.json:
        print(json.dumps(findings, indent=2, default=str))
        return 0
    for item in findings:
        cve = (" " + ",".join(item["cve"])) if item.get("cve") else ""
        print("[%-8s] %-10s %s%s" % (item["severity"].upper(), item["status"], item["title"], cve))
    print("\n%d findings for scan %s" % (len(findings), scan_id))
    return 0


def cmd_history(args):
    cfg = _config(args)
    store = _store(cfg)
    for scan in store.list_scans(args.limit):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(scan["started"]))
        total = (scan.get("summary") or {}).get("total", "?")
        print("%s  %-10s %-10s %-10s findings=%-4s  %s" % (scan["id"], when, scan["status"], scan["profile"], total, scan["target"]))
    return 0


def cmd_export(args):
    cfg = _config(args)
    store = _store(cfg)
    scan_id = args.scan_id or store.latest_scan_id()
    if not scan_id:
        print("No scans found.")
        return 1
    _write_report(cfg, store, scan_id, args.output, args.format)
    return 0


def cmd_delete(args):
    cfg = _config(args)
    store = _store(cfg)
    store.delete_scan(args.scan_id)
    print("Deleted scan %s" % args.scan_id)
    return 0


def cmd_intel_update(args):
    cfg = _config(args)
    intel = _intel(cfg, required=True)

    def say(msg):
        if not args.quiet:
            sys.stderr.write("\r%s%s" % (msg, " " * 10))
            sys.stderr.flush()

    total = sync_nvd(intel, cfg, since_year=args.since_year, days=args.days, full=args.full, progress=say)
    say("")
    print("\nNVD: %d records updated." % total)
    kev_count = sync_kev(intel, say)
    say("")
    print("KEV catalog: %d entries." % kev_count)
    return 0


def cmd_intel_search(args):
    cfg = _config(args)
    intel = _intel(cfg, required=True)
    results = intel.search(args.query or "", limit=args.limit, product=args.product, version=args.version)
    if args.json:
        print(json.dumps(results, indent=2, default=str))
        return 0
    for cve in results:
        kev = " [KNOWN EXPLOITED]" if cve["known_exploited"] else ""
        print("%s  %-8s %5s  %s%s" % (cve["id"], cve["severity"], cve["cvss_score"] or "-", cve["description"][:100], kev))
    print("\n%d results" % len(results))
    return 0


def cmd_intel_status(args):
    cfg = _config(args)
    intel = _intel(cfg, required=True)
    stats = intel.stats()
    freshness = intel.freshness(cfg.data["intel"]["stale_after_days"])
    print("CVE records: %d   CPE match entries: %d   KEV entries: %d   OSV cached: %d" % (
        stats["cves"], stats["cpe_entries"], stats["kev"], stats["osv_cached"]))
    print("Database size: %.1f MB" % (stats["size_bytes"] / (1024 * 1024)))
    print("Last NVD sync: %s   Freshness: %s" % (stats["nvd_last_sync"] or "never", freshness))
    print("Last KEV sync: %s" % (stats["kev_last_sync"] or "never"))
    return 0


def cmd_dashboard(args):
    from vulnscope.dashboard.app import run_dashboard

    cfg = _config(args)
    run_dashboard(cfg, host=args.host, port=args.port)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="vulnscope", description="Free, open-source, offline-capable vulnerability assessment framework.")
    parser.add_argument("--home", help="override the VulnScope data directory")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="show platform diagnostics and plugin availability")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("plugins", help="list scanner plugins")
    p.add_argument("--target-type", help="filter by target type (url, host, source, apk, ipa, local)")
    p.set_defaults(func=cmd_plugins)

    p = sub.add_parser("scan", help="run a vulnerability assessment")
    p.add_argument("target", help="URL, host/CIDR, local source directory, or APK/IPA file")
    p.add_argument("--target-type", dest="target_type", choices=["url", "host", "source", "apk", "ipa", "archive", "local"])
    p.add_argument("--profile", choices=plugin_mod.PROFILES, default="standard")
    p.add_argument("--scope", action="append", help="additional authorized host, domain or CIDR (repeatable)")
    p.add_argument("--allow-private", action="store_true", help="permit scanning RFC1918/loopback addresses")
    p.add_argument("--header", action="append", help="authenticated session header 'Name: value' (repeatable)")
    p.add_argument("--cookie", help="authenticated session Cookie header value")
    p.add_argument("--only", action="append", help="restrict to these plugin IDs (repeatable)")
    p.add_argument("--exclude", action="append", help="skip these plugin IDs (repeatable)")
    p.add_argument("--authorized-by", help="free-text record of who authorized this assessment")
    p.add_argument("--output", "-o", help="write a report to this path")
    p.add_argument("--format", choices=["html", "json", "csv"], default="html")
    p.add_argument("--lite", action="store_true", help="use lightweight settings for low-memory devices")
    p.add_argument("--offline", action="store_true", help="do not contact external vulnerability feeds")
    p.add_argument("--yes", action="store_true", help="skip the interactive authorization prompt")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("results", help="show findings for a scan")
    p.add_argument("scan_id", nargs="?")
    p.add_argument("--severity", choices=["critical", "high", "medium", "low", "info", "unknown"])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_results)

    p = sub.add_parser("history", help="list past scans")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("export", help="export a report for a past scan")
    p.add_argument("scan_id", nargs="?")
    p.add_argument("--output", "-o", required=True)
    p.add_argument("--format", choices=["html", "json", "csv"], default="html")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("delete", help="delete a scan and its findings")
    p.add_argument("scan_id")
    p.set_defaults(func=cmd_delete)

    intel = sub.add_parser("intel", help="vulnerability intelligence database")
    intel_sub = intel.add_subparsers(dest="intel_command", required=True)

    p = intel_sub.add_parser("update", help="synchronize NVD and CISA KEV data")
    p.add_argument("--since-year", type=int)
    p.add_argument("--days", type=int, help="only fetch records modified in the last N days")
    p.add_argument("--full", action="store_true", help="perform a full historical sync (large and slow)")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_intel_update)

    p = intel_sub.add_parser("search", help="search the local CVE database")
    p.add_argument("query", nargs="?", default="")
    p.add_argument("--product")
    p.add_argument("--version")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_intel_search)

    p = intel_sub.add_parser("status", help="show vulnerability database statistics")
    p.set_defaults(func=cmd_intel_status)

    p = sub.add_parser("dashboard", help="start the local web dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.set_defaults(func=cmd_dashboard)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
