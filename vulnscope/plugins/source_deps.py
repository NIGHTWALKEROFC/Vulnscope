import json
import os
import re

from vulnscope.intel.osv import OsvClient
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._source import read_text, walk_files

_ECOSYSTEMS = {
    "package.json": ("npm", "dependencies"), "package-lock.json": ("npm", "lock"),
    "requirements.txt": ("PyPI", "requirements"), "composer.lock": ("Packagist", "composer"),
    "gemfile.lock": ("RubyGems", "gemfile"), "go.mod": ("Go", "gomod"), "cargo.lock": ("crates.io", "cargolock"),
}
_PY_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)")
_GEMFILE = re.compile(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)")
_GOMOD = re.compile(r"^\s*([A-Za-z0-9_./\-]+)\s+v(\d[\w.\-+]*)")
_CARGO = re.compile(r'name = "([^"]+)"\nversion = "([^"]+)"')


def parse_npm_package(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            match = re.search(r"\d[\w.\-]*", str(spec))
            if match:
                out.append((name, match.group(0)))
    return out


def parse_npm_lock(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or "node_modules" not in path:
                continue
            name = path.split("node_modules/")[-1]
            version = info.get("version")
            if name and version:
                out.append((name, version))
    else:
        for name, info in (data.get("dependencies") or {}).items():
            version = info.get("version")
            if version:
                out.append((name, version))
    return out


def parse_requirements(text):
    out = []
    for line in text.splitlines():
        match = _PY_LINE.match(line)
        if match:
            out.append((match.group(1).lower(), match.group(2)))
    return out


def parse_composer_lock(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []) or []:
            name, version = pkg.get("name"), (pkg.get("version") or "").lstrip("v")
            if name and version:
                out.append((name, version))
    return out


def parse_gemfile_lock(text):
    out = []
    for line in text.splitlines():
        match = _GEMFILE.match(line)
        if match:
            out.append((match.group(1), match.group(2)))
    return out


def parse_gomod(text):
    out = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block or stripped.startswith("require "):
            match = _GOMOD.search(stripped)
            if match:
                out.append((match.group(1), match.group(2)))
    return out


def parse_cargo_lock(text):
    return [(m[0], m[1]) for m in _CARGO.findall(text)]


PARSERS = {
    ("package.json", "dependencies"): parse_npm_package, ("package-lock.json", "lock"): parse_npm_lock,
    ("requirements.txt", "requirements"): parse_requirements, ("composer.lock", "composer"): parse_composer_lock,
    ("gemfile.lock", "gemfile"): parse_gemfile_lock, ("go.mod", "gomod"): parse_gomod,
    ("cargo.lock", "cargolock"): parse_cargo_lock,
}


@register
class SourceDependencies(Plugin):
    id = "source.deps"
    name = "Dependency vulnerability scan (OSV)"
    description = "Parses manifest and lock files and checks every package version against the OSV.dev advisory database."
    target_types = ("source",)
    categories = ("Software supply chain", "Known vulnerable component")
    requires = ()
    timeout = 300

    def run(self, ctx):
        if ctx.intel is None:
            return
        root = ctx.target.value
        packages, found_files = [], []
        for name, (eco, kind) in _ECOSYSTEMS.items():
            for dirpath, _, filenames in os.walk(root):
                if "node_modules" in dirpath or ".git" in dirpath:
                    continue
                if name in [f.lower() for f in filenames]:
                    actual = next(f for f in filenames if f.lower() == name)
                    path = os.path.join(dirpath, actual)
                    text = read_text(path, 4096)
                    parser = PARSERS.get((name, kind))
                    if not parser:
                        continue
                    for pkg_name, version in parser(text):
                        packages.append((eco, pkg_name, version, os.path.relpath(path, root)))
                    found_files.append(os.path.relpath(path, root))
                    break
        if not packages:
            return
        ctx.asset("dependency-manifests", root, {"files": found_files, "package_count": len(packages)})
        client = OsvClient(ctx.intel, ctx.config)
        queries = [(eco, name, version) for eco, name, version, _ in packages]
        results = client.query(queries)
        all_ids = set()
        for ids in results.values():
            all_ids.update(ids)
        if not all_ids:
            return
        details = client.vulns(all_ids)
        for idx, (eco, name, version, source_file) in enumerate(packages):
            ctx.check()
            for vid in results.get(idx, []):
                vuln = details.get(vid)
                if not vuln:
                    continue
                severity = vuln["severity"]
                status = "version_match" if vuln["fixed"] else "potential"
                remediation = "Upgrade %s to %s or later." % (name, vuln["fixed"][0]) if vuln["fixed"] else "Review the advisory; no fixed version is listed yet."
                yield ctx.finding(
                    "%s %s (%s): %s" % (name, version, eco, vid), severity, status, "Software supply chain",
                    target=root, rule_id="osv:" + vid, confidence="high",
                    rule_basis="OSV.dev advisory matched by ecosystem, package name and exact version",
                    evidence="%s declares %s %s (source: %s)." % (source_file, name, version, source_file),
                    impact=vuln["summary"], remediation=remediation, cve=[a for a in vuln["aliases"] if a.startswith("CVE-")],
                    cvss_score=vuln["score"], cvss_vector=vuln["vector"] or "", cvss_version="3.1" if vuln["vector"] else "",
                    references=vuln["refs"][:6] + ["https://osv.dev/vulnerability/" + vid], location=source_file,
                )
        if client.errors:
            yield ctx.finding(
                "OSV.dev lookup incomplete", "info", "informational", "Software supply chain",
                rule_id="source.deps.osv-error", confidence="medium",
                evidence="; ".join(client.errors[:3]), remediation="Re-run when network access to osv.dev is available, or rely on cached results.",
            )
