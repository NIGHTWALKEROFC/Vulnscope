import re

from vulnscope.http import HttpError
from vulnscope.intel.matcher import cve_findings
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._web import parse_product_header
from vulnscope.versions import compare_versions

_COOKIE_TECH = {"phpsessid": "php", "jsessionid": "java", "asp.net_sessionid": "asp.net", "laravel_session": "laravel",
                "csrftoken": "django", "connect.sid": "express", "_rails": "rails"}
_EOL = [
    ("php", "8.1", "PHP releases before 8.1 no longer receive security fixes"),
    ("apache", "2.4", "Apache HTTP Server 2.2 and earlier are end of life"),
]
_NAME_MAP = {"apache": "apache", "nginx": "nginx", "microsoft-iis": "iis", "php": "php", "openssl": "openssl",
             "lighttpd": "lighttpd", "openresty": "openresty", "tomcat": "tomcat", "jetty": "jetty",
             "express": "express", "phusion passenger": None, "litespeed": None, "caddy": "caddy"}


@register
class TechFingerprint(Plugin):
    id = "web.tech"
    name = "Technology fingerprint and version matching"
    description = "Identifies server, language and CMS versions from headers and markup and matches them to the local CVE database."
    categories = ("Known vulnerable component", "Information disclosure")
    timeout = 120

    def run(self, ctx):
        resp = ctx.base()
        found = {}
        for header in ("Server", "X-Powered-By", "X-Generator"):
            for name, version in parse_product_header(resp.header(header)):
                mapped = _NAME_MAP.get(name, name)
                if mapped:
                    found[mapped] = (version, "%s header: %s" % (header, resp.header(header)[:120]), "medium")
        if resp.is_html:
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text, re.I)
            if gen:
                match = re.match(r"(WordPress|Drupal|Joomla!?|Magento|Hugo|Ghost)\s*(\d+(?:\.\d+)+)?", gen.group(1), re.I)
                if match:
                    name = match.group(1).lower().rstrip("!")
                    if match.group(2):
                        found[name] = (match.group(2), "Generator meta tag: %s" % gen.group(1)[:100], "high")
                    else:
                        ctx.asset("technology", name, {"version": None})
            if "/wp-content/" in resp.text or "/wp-includes/" in resp.text:
                ctx.asset("technology", "wordpress", {"version": found.get("wordpress", (None,))[0]})
                plugins = sorted(set(re.findall(r"/wp-content/plugins/([a-z0-9_-]+)/", resp.text, re.I)))
                for slug in plugins[:30]:
                    ctx.asset("wordpress-plugin", slug, {})
                if plugins:
                    yield ctx.finding(
                        "WordPress plugins identified", "info", "informational", "Information disclosure",
                        rule_id="web.tech.wp-plugins", confidence="high",
                        evidence="Plugins referenced in markup: %s" % ", ".join(plugins[:15]),
                        remediation="Keep plugins updated and remove unused ones; versions require manual verification.",
                        references=["https://wordpress.org/plugins/"],
                    )
        for cookie in resp.set_cookies:
            tech = _COOKIE_TECH.get(cookie.split("=", 1)[0].strip().lower())
            if tech:
                ctx.asset("technology", tech, {"source": "cookie"})
        for name, (version, evidence, confidence) in found.items():
            ctx.asset("technology", name, {"version": version, "evidence": evidence})
            for key, floor, message in _EOL:
                if key == name and compare_versions(version, floor) < 0:
                    yield ctx.finding(
                        "End-of-life %s version %s" % (name, version), "medium", "version_match", "Known vulnerable component",
                        rule_id="web.tech.eol.%s" % name, confidence=confidence,
                        rule_basis="Vendor lifecycle policy: %s" % message, evidence=evidence,
                        impact="Unsupported releases do not receive security patches.",
                        remediation="Upgrade to a supported %s release." % name, notes="Distribution packages may back-port fixes.",
                    )
            for f in cve_findings(ctx, name, version, evidence + ".", confidence):
                yield f
        if ctx.intel is None:
            yield ctx.finding(
                "Local CVE database unavailable: version matching skipped", "info", "informational", "Known vulnerable component",
                rule_id="web.tech.no-intel", confidence="high",
                evidence="Run 'vulnscope intel update' to download vulnerability data.",
                remediation="Synchronize the local vulnerability database.",
            )
