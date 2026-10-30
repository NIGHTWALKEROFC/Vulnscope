import os

from vulnscope.plugin import Plugin, register
from vulnscope.plugins._source import read_text, walk_files
from vulnscope.rules import secrets


@register
class SourceSecrets(Plugin):
    id = "source.secrets"
    name = "Secret and credential exposure in source"
    description = "Scans a local source tree or extracted package for hardcoded API keys, tokens and credentials."
    target_types = ("source",)
    categories = ("Secrets management", "Secret and credential exposure")
    timeout = 300

    def run(self, ctx):
        root = ctx.target.value
        cfg = ctx.config.data["limits"]
        count = 0
        for path, _ in walk_files(root, ctx.config.data["scan"]["max_pages"] * 50 or 4000, cfg["max_scan_file_kb"]):
            ctx.check()
            text = read_text(path, cfg["max_scan_file_kb"])
            if not text:
                continue
            rel = os.path.relpath(path, root)
            for hit in secrets.scan_text(text, 20):
                count += 1
                yield ctx.finding(
                    "%s found in source" % hit["label"], hit["severity"], "confirmed", "Secrets management",
                    target=root, rule_id="source.secrets." + hit["rule_id"], confidence="high",
                    rule_basis="Pattern match for %s; value masked in this report" % hit["label"],
                    evidence="%s:%d matched %s: %s" % (rel, hit["line"], hit["label"], hit["masked"]),
                    impact="Anyone with repository or package access can use this credential.",
                    remediation="Revoke and rotate the credential, remove it from history, and load secrets from environment variables or a secret manager.",
                    references=["https://cwe.mitre.org/data/definitions/798.html"], location="%s:%d" % (rel, hit["line"]),
                )
        if count == 0:
            yield ctx.finding(
                "No obvious hardcoded secrets found", "info", "informational", "Secrets management",
                rule_id="source.secrets.none", confidence="medium", evidence="Pattern-based scan completed without matches.",
                remediation="Pattern-based scanning cannot catch every secret; review sensitive files manually.",
            )
