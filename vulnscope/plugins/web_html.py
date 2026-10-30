import re
from urllib.parse import urlsplit

from vulnscope.crawler import crawl
from vulnscope.htmlparse import parse_html
from vulnscope.http import HttpError
from vulnscope.intel.matcher import cve_findings
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._web import CWE, OWASP_TOP10, OWASP_WSTG, host_of, parse_set_cookie, scheme_of, short
from vulnscope.rules import jslibs, secrets
from vulnscope.versions import in_range

_CSRF_NAME = re.compile(r"csrf|xsrf|_token|authenticity|verification|nonce|__requestverificationtoken", re.I)
_ID_URL = re.compile(r"(?:[?&](?:id|uid|user_id|account|order|invoice|doc|file)=\d+|/(?:users?|accounts?|orders?|invoices?|documents?|profiles?)/\d+)", re.I)


def _pages(ctx):
    base = ctx.base()
    pages = {base.url: base}
    if ctx.profile != "passive":
        for url, resp in crawl(ctx).pages.items():
            pages[url] = resp
    return pages


@register
class HtmlChecks(Plugin):
    id = "web.html"
    name = "HTML forms and resources"
    description = "Analyses forms, third-party resources, mixed content and identifier patterns in fetched pages."
    categories = ("Cross-site request forgery", "Authentication", "Software supply chain", "Insecure direct object reference")
    timeout = 180

    def run(self, ctx):
        pages = _pages(ctx)
        base_host = host_of(ctx.target.value)
        cookies_lax = True
        for resp in pages.values():
            for raw in resp.set_cookies:
                attrs = parse_set_cookie(raw)["attrs"]
                if attrs.get("samesite", "").lower() not in ("lax", "strict"):
                    cookies_lax = False
        third_party, mixed, id_urls = {}, [], set()
        for url, resp in pages.items():
            ctx.check()
            if _ID_URL.search(url):
                id_urls.add(url)
            if not resp.is_html:
                continue
            info = parse_html(resp.text, resp.url)
            page_https = scheme_of(resp.url) == "https"
            for form in info.forms:
                inputs = form["inputs"]
                has_password = any(i["type"] == "password" for i in inputs)
                has_file = any(i["type"] == "file" for i in inputs)
                action_http = scheme_of(form["action"]) == "http"
                if has_password:
                    ctx.asset("login-form", form["action"], {"page": url, "method": form["method"]})
                    if action_http or not page_https:
                        yield ctx.finding(
                            "Login form submits credentials over cleartext HTTP", "high", "confirmed", "Authentication",
                            target=url, rule_id="web.html.password-http", rule_basis="Password input in form served from or posting to http",
                            confidence="high", evidence="Form action %s on page %s" % (form["action"], url),
                            impact="Credentials can be captured on the network.", remediation="Serve and submit login forms over HTTPS only.",
                            references=[CWE % "319"], location=form["action"],
                        )
                    if form["method"] == "get":
                        yield ctx.finding(
                            "Password submitted using GET method", "medium", "confirmed", "Authentication",
                            target=url, rule_id="web.html.password-get", rule_basis="Form with password field uses GET",
                            confidence="high", evidence="Form action %s uses method GET" % form["action"],
                            impact="Passwords appear in URLs, browser history and server logs.", remediation="Use POST for credential forms.",
                            references=[CWE % "598"], location=form["action"],
                        )
                if has_file:
                    yield ctx.finding(
                        "File upload functionality detected", "info", "potential", "File upload security",
                        target=url, rule_id="web.html.upload", rule_basis="Form contains a file input", confidence="medium",
                        evidence="Upload form posts to %s" % form["action"],
                        impact="Unrestricted upload handling can lead to code execution, stored XSS or denial of service.",
                        remediation="Validate type by content, limit size, store outside the web root, randomize names and scan uploads.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
                        location=form["action"], notes="Upload handling requires manual verification; no upload was attempted.",
                    )
                if form["method"] == "post" and not has_password:
                    names = [i["name"] for i in inputs]
                    if not any(_CSRF_NAME.search(n) for n in names) and any(i["type"] not in ("hidden", "submit") for i in inputs):
                        yield ctx.finding(
                            "POST form without anti-CSRF token", "low" if cookies_lax else "medium", "potential",
                            "Cross-site request forgery", target=url, rule_id="web.html.csrf",
                            rule_basis="POST form has no field resembling a CSRF token; severity lowered when cookies use SameSite Lax or Strict",
                            confidence="low", evidence="Form action %s fields: %s" % (form["action"], ", ".join(names[:10])),
                            impact="A malicious site may submit this form on behalf of a signed-in user.",
                            remediation="Add per-session anti-CSRF tokens or validate Origin/Referer and use SameSite cookies.",
                            references=[CWE % "352", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
                            location=form["action"], notes="Header-based or server-side Origin checks are not visible from HTML.",
                        )
            for tag in info.scripts:
                host = host_of(tag["src"])
                if host and host != base_host and not tag["integrity"]:
                    third_party[tag["src"]] = "script"
                if page_https and tag["src"].startswith("http://"):
                    mixed.append(("script", tag["src"]))
            for tag in info.stylesheets:
                host = host_of(tag["href"])
                if host and host != base_host and not tag["integrity"]:
                    third_party[tag["href"]] = "stylesheet"
                if page_https and tag["href"].startswith("http://"):
                    mixed.append(("stylesheet", tag["href"]))
            for frame in info.iframes:
                if page_https and frame.startswith("http://"):
                    mixed.append(("iframe", frame))
            for comment in info.comments:
                if re.search(r"(?i)(password|passwd|secret|api[_ -]?key|todo.*(?:fix|remove)|debug|credentials)", comment):
                    yield ctx.finding(
                        "Sensitive wording in HTML comment", "low", "potential", "Information disclosure", target=url,
                        rule_id="web.html.comment", rule_basis="HTML comment matches sensitive keywords", confidence="low",
                        evidence="<!-- %s -->" % short(comment.strip(), 160), remediation="Remove developer comments from production output.",
                        references=[CWE % "615"], location=url,
                    )
                    break
            if resp.content_type in ("application/xml", "text/xml") or "<?xml" in resp.text[:100]:
                yield ctx.finding(
                    "XML-processing endpoint observed", "info", "informational", "XML external entity",
                    target=url, rule_id="web.html.xml", rule_basis="Response is XML", confidence="low",
                    evidence="Content-Type: %s" % resp.content_type,
                    remediation="Ensure XML parsers disable DTDs and external entities; test manually for XXE.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
                    location=url,
                )
        if third_party:
            sample = list(third_party)[:8]
            yield ctx.finding(
                "Third-party resources loaded without Subresource Integrity", "low", "potential", "Software supply chain",
                rule_id="web.html.sri", rule_basis="Cross-origin script or stylesheet without integrity attribute", confidence="medium",
                evidence="%d resources, e.g. %s" % (len(third_party), "; ".join(sample)),
                impact="A compromised third-party host could inject code into this site.",
                remediation="Add integrity and crossorigin attributes or self-host the resources.",
                references=["https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity", CWE % "829"],
            )
        if mixed:
            active = [m for m in mixed if m[0] in ("script", "iframe", "stylesheet")]
            yield ctx.finding(
                "Mixed content: HTTPS page loads active content over HTTP", "medium", "confirmed", "Transport security",
                rule_id="web.html.mixed", rule_basis="http:// subresource referenced from https page", confidence="high",
                evidence="; ".join("%s %s" % m for m in active[:6]),
                impact="Active content over HTTP can be tampered with, compromising the page.",
                remediation="Load all subresources over HTTPS.", references=[CWE % "311"],
            )
        if id_urls:
            yield ctx.finding(
                "Predictable object identifiers in URLs", "info", "potential", "Insecure direct object reference",
                rule_id="web.html.idor-pattern", rule_basis="Numeric identifier in path or query", confidence="low",
                evidence="; ".join(sorted(id_urls)[:5]),
                impact="If access control is missing, other users' records may be reachable by changing the identifier.",
                remediation="Enforce object-level authorization on the server for every identifier.",
                references=[OWASP_WSTG, "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                notes="Pattern detection only. Verify with two authenticated sessions (see the web.authz plugin).",
            )


def lib_findings(ctx, lib, version, where):
    out = []
    for rule in jslibs.RULES.get(lib, []):
        if not in_range(version, start_incl=rule.get("start"), end_excl=rule["end"]):
            continue
        cves = rule["cve"] or [None]
        for cve_id in cves:
            record = ctx.intel.get_cve(cve_id) if (ctx.intel and cve_id) else None
            out.append(ctx.finding(
                "%s %s: %s" % (lib, version, cve_id or "end-of-life version"), rule["sev"] if not record or not record["severity"] or record["severity"] == "unknown" else record["severity"],
                "version_match", "Vulnerable client-side library", target=where,
                rule_id=("cve:" + cve_id) if cve_id else "jslib-eol:%s" % lib, confidence="high",
                rule_basis="Built-in advisory range for %s (<%s); score taken from the local CVE database when present" % (lib, rule["end"]),
                evidence="%s version %s detected at %s" % (lib, version, where), impact=rule["summary"],
                remediation="Upgrade %s to %s or later." % (lib, rule["fix"]), cve=[cve_id] if cve_id else [],
                cvss_score=record["cvss_score"] if record else None, cvss_vector=(record["cvss_vector"] or "") if record else "",
                cvss_version=(record["cvss_version"] or "") if record else "",
                references=(["https://nvd.nist.gov/vuln/detail/" + cve_id] if cve_id else []),
                location=where, known_exploited=bool(record and record["known_exploited"]),
            ))
    return out


@register
class JsAnalysis(Plugin):
    id = "web.js"
    name = "JavaScript libraries and exposed secrets"
    description = "Identifies client-side libraries and versions, scans same-origin scripts for keys and source maps."
    categories = ("Vulnerable client-side library", "Secrets management", "Information disclosure")
    timeout = 240

    def run(self, ctx):
        base_host = host_of(ctx.target.value)
        urls = set()
        for resp in _pages(ctx).values():
            if resp.is_html:
                for tag in parse_html(resp.text, resp.url).scripts:
                    urls.add(tag["src"])
        seen_libs = set()
        fetched = 0
        for src in sorted(urls):
            ctx.check()
            clean = src.split("?")[0]
            for lib, version in jslibs.detect_from_name(clean):
                if (lib, version, src) not in seen_libs:
                    seen_libs.add((lib, version, src))
                    ctx.asset("js-library", "%s %s" % (lib, version), {"url": src})
                    for f in lib_findings(ctx, lib, version, src):
                        yield f
            if host_of(src) != base_host or fetched >= 20:
                continue
            fetched += 1
            try:
                resp = ctx.http.get(src)
            except HttpError:
                continue
            if resp.status != 200:
                continue
            text = resp.text
            for lib, version in jslibs.detect_from_content(text):
                if (lib, version, src) not in seen_libs:
                    seen_libs.add((lib, version, src))
                    ctx.asset("js-library", "%s %s" % (lib, version), {"url": src})
                    for f in lib_findings(ctx, lib, version, src):
                        yield f
                    for f in cve_findings(ctx, lib, version, "Detected in %s." % src, "high", target=src, location=src):
                        yield f
            for hit in secrets.scan_text(text, 10):
                public_hint = hit["rule_id"] in ("google-api-key", "jwt")
                yield ctx.finding(
                    "%s exposed in JavaScript" % hit["label"], "low" if public_hint else hit["severity"],
                    "potential" if public_hint else "confirmed", "Secrets management", target=src,
                    rule_id="web.js.secret." + hit["rule_id"], confidence="medium" if public_hint else "high",
                    rule_basis="Pattern match for %s; value masked in this report" % hit["label"],
                    evidence="%s at line %d: %s" % (hit["label"], hit["line"], hit["masked"]),
                    impact="Anyone who loads the script can read this value.",
                    remediation="Revoke and rotate the credential and keep secrets on the server side.",
                    references=[CWE % "798"], location="%s:%d" % (src, hit["line"]),
                    notes="Some keys (for example browser-restricted Google API keys) are designed to be public; check restrictions." if public_hint else "",
                )
            if re.search(r"//[#@]\s*sourceMappingURL=", text[-2000:]):
                yield ctx.finding(
                    "JavaScript source map reference present", "info", "informational", "Information disclosure", target=src,
                    rule_id="web.js.sourcemap", rule_basis="sourceMappingURL comment in production script", confidence="medium",
                    evidence="Script %s references a source map." % src,
                    impact="Source maps can expose original source code and internal structure.",
                    remediation="Do not publish source maps for production builds or restrict access to them.",
                    references=[CWE % "540"], location=src,
                )
