import os
import re
import subprocess

from vulnscope.intel.matcher import cve_findings
from vulnscope.intel.osv import OsvClient
from vulnscope.plugin import Plugin, register
from vulnscope.platform_info import detect_os, has_binary

CWE = "https://cwe.mitre.org/data/definitions/%s.html"


def _run(cmd, timeout=20):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


@register
class LocalPackages(Plugin):
    id = "os.packages"
    name = "Local installed package inventory"
    description = "Lists installed OS packages on the machine running the scan (dpkg, rpm or pacman) and checks them against OSV ecosystem advisories."
    target_types = ("local",)
    categories = ("Operating system and installed software", "Missing security updates")
    platforms = ("linux", "android")
    timeout = 180

    def run(self, ctx):
        os_name = detect_os()
        packages = []
        ecosystem = None
        if has_binary("dpkg-query"):
            out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
            ecosystem = "Debian"
            for line in out.splitlines():
                if "\t" in line:
                    name, version = line.split("\t", 1)
                    packages.append((name.strip(), version.strip()))
        elif has_binary("rpm"):
            out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
            ecosystem = "Red Hat"
            for line in out.splitlines():
                if "\t" in line:
                    name, version = line.split("\t", 1)
                    packages.append((name.strip(), version.strip()))
        elif has_binary("pacman"):
            out = _run(["pacman", "-Q"])
            ecosystem = "Arch"
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2:
                    packages.append((parts[0], parts[1]))
        elif has_binary("pkg") and os_name == "android":
            out = _run(["pkg", "list-installed"])
            ecosystem = "Termux"
            for line in out.splitlines():
                if "/" in line:
                    name_ver = line.split()[0]
                    if "/" in name_ver:
                        packages.append((name_ver.split("/")[0], ""))
        if not packages:
            yield ctx.finding(
                "No supported local package manager found", "info", "informational", "Operating system and installed software",
                rule_id="os.packages.unsupported", confidence="high",
                evidence="Checked for dpkg, rpm, pacman and Termux pkg; none produced output.",
                remediation="This module currently supports Debian/Ubuntu, Red Hat family, Arch and Termux package lists.",
            )
            return
        ctx.asset("local-packages", ecosystem or "unknown", {"count": len(packages)})
        checked = 0
        limit = ctx.config.data["scan"]["max_pages"] * 20 or 2000
        for name, version in packages:
            ctx.check()
            if not version or checked >= limit:
                continue
            clean_version = re.sub(r"^\d+:", "", version).split("-")[0].split("+")[0]
            checked += 1
            for f in cve_findings(ctx, name, clean_version, "Installed package reported by the local package manager (%s)." % ecosystem,
                                  "low", target="localhost", location="%s %s" % (name, version)):
                yield f
        yield ctx.finding(
            "Installed package inventory collected", "info", "informational", "Operating system and installed software",
            rule_id="os.packages.inventory", confidence="high",
            evidence="%d packages listed via %s; version matching is approximate and local distribution patches are not accounted for." % (len(packages), ecosystem),
            remediation="Keep the system updated using its native package manager.",
            notes="CVE matching against OS packages does not know about vendor back-ports, so treat matches as potential unless independently confirmed.",
        )


@register
class LocalDiagnostics(Plugin):
    id = "os.diagnostics"
    name = "Local security configuration indicators"
    description = "Flags a small set of common local misconfigurations: world-writable sensitive files, missing disk encryption hints."
    target_types = ("local",)
    categories = ("Operating system and installed software", "Insecure configuration")
    platforms = ("linux",)
    timeout = 60

    def run(self, ctx):
        for path in ("/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa"):
            try:
                mode = oct(os.stat(path).st_mode)[-3:]
            except OSError:
                continue
            if path.endswith("id_rsa") and mode != "600":
                yield ctx.finding(
                    "SSH private key has loose permissions", "medium", "confirmed", "Insecure configuration",
                    rule_id="os.diagnostics.key-perms", confidence="high", evidence="%s has mode %s." % (path, mode),
                    remediation="chmod 600 the private key file.", references=[CWE % "276"], location=path,
                )
            if path == "/etc/shadow" and mode not in ("600", "640", "000"):
                yield ctx.finding(
                    "/etc/shadow has unusually permissive mode", "medium", "confirmed", "Insecure configuration",
                    rule_id="os.diagnostics.shadow-perms", confidence="high", evidence="/etc/shadow has mode %s." % mode,
                    remediation="Restrict /etc/shadow to root with mode 640 or stricter.", references=[CWE % "276"], location=path,
                )
