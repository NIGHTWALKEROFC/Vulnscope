import re
import uuid

from vulnscope.http import HttpError
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._web import (CWE, MDN_CSP, MDN_HSTS, OWASP_HEADERS, OWASP_TOP10, OWASP_WSTG, host_of,
                                    parse_set_cookie, scheme_of, short)

_SESSION_NAME = re.compile(r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf)", re.I)


@register
class SecurityHeaders(Plugin):
    id = "web.headers"
    name = "HTTP security headers"
    description = "Checks response headers for missing or weak browser protections, cleartext delivery and version disclosure."
    categories = ("Security misconfiguration", "Transport security", "Information disclosure")
    timeout = 60

    def run(self, ctx):
        resp = ctx.base()
        h = resp.headers
        final = resp.url
        https = scheme_of(final) == "https"
        html = resp.is_html
        refs = [OWASP_HEADERS, OWASP_TOP10]
        if not https:
            yield ctx.finding(
                "Page delivered over unencrypted HTTP", "medium", "confirmed", "Transport security",
                rule_id="web.headers.cleartext", rule_basis="Final URL after redirects uses http",
                confidence="high", evidence="Final URL: %s (status %d)" % (final, resp.status),
                impact="Traffic can be read or modified by network attackers.",
                remediation="Serve the site over HTTPS and redirect all HTTP requests to HTTPS.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels"],
            )
        elif not h.get("Strict-Transport-Security"):
            yield ctx.finding(
                "Strict-Transport-Security header missing", "low", "confirmed", "Transport security",
                rule_id="web.headers.hsts-missing", rule_basis="Header absent on HTTPS response", confidence="high",
                evidence="Response from %s has no Strict-Transport-Security header." % final,
                impact="Browsers can be downgraded to HTTP by an on-path attacker on first or later visits.",
                remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", references=[MDN_HSTS],
            )
        else:
            hsts = h.get("Strict-Transport-Security", "")
            age = re.search(r"max-age=(\d+)", hsts, re.I)
            if not age or int(age.group(1)) < 15552000:
                yield ctx.finding(
                    "Strict-Transport-Security max-age is short", "low", "confirmed", "Transport security",
                    rule_id="web.headers.hsts-weak", rule_basis="max-age below 180 days", confidence="high",
                    evidence="Strict-Transport-Security: %s" % hsts,
                    remediation="Use max-age of at least 15552000 seconds, preferably 31536000.", references=[MDN_HSTS],
                )
        if html:
            csp = h.get("Content-Security-Policy", "")
            if not csp:
                yield ctx.finding(
                    "Content-Security-Policy header missing", "low", "confirmed", "Security misconfiguration",
                    rule_id="web.headers.csp-missing", rule_basis="Header absent on HTML response", confidence="high",
                    evidence="No Content-Security-Policy header on %s." % final,
                    impact="No browser-enforced mitigation if a cross-site scripting flaw exists.",
                    remediation="Define a restrictive Content-Security-Policy without unsafe-inline for scripts.",
                    references=[MDN_CSP],
                )
            else:
                weak = []
                for directive in csp.split(";"):
                    name, _, value = directive.strip().partition(" ")
                    if name in ("script-src", "default-src", "script-src-elem"):
                        if "'unsafe-inline'" in value and "nonce-" not in value and "'strict-dynamic'" not in value:
                            weak.append("%s allows 'unsafe-inline'" % name)
                        if "'unsafe-eval'" in value:
                            weak.append("%s allows 'unsafe-eval'" % name)
                        if re.search(r"(^|\s)(\*|https?:|data:)(\s|$)", value):
                            weak.append("%s allows broad sources" % name)
                if weak:
                    yield ctx.finding(
                        "Content-Security-Policy is weak", "low", "confirmed", "Security misconfiguration",
                        rule_id="web.headers.csp-weak", rule_basis="Directive values permit inline or wildcard script sources",
                        confidence="high", evidence="; ".join(weak) + " | " + short(csp),
                        remediation="Remove unsafe-inline and wildcards from script directives; use nonces or hashes.",
                        references=[MDN_CSP],
                    )
            framed = "frame-ancestors" in csp.lower() or h.get("X-Frame-Options")
            if not framed:
                yield ctx.finding(
                    "Clickjacking protection missing", "medium", "confirmed", "Security misconfiguration",
                    rule_id="web.headers.clickjacking", rule_basis="Neither X-Frame-Options nor CSP frame-ancestors present",
                    confidence="high", evidence="Page can be embedded in a frame by any origin.",
                    impact="Users can be tricked into clicking hidden interface elements.",
                    remediation="Send Content-Security-Policy: frame-ancestors 'none' (or 'self') and X-Frame-Options: DENY.",
                    references=[CWE % "1021", OWASP_HEADERS],
                )
        if "nosniff" not in h.get("X-Content-Type-Options", "").lower():
            yield ctx.finding(
                "X-Content-Type-Options header missing", "low", "confirmed", "Security misconfiguration",
                rule_id="web.headers.nosniff", rule_basis="Header absent or not nosniff", confidence="high",
                evidence="X-Content-Type-Options: %s" % (h.get("X-Content-Type-Options") or "(absent)"),
                remediation="Send X-Content-Type-Options: nosniff.", references=refs,
            )
        if html and not h.get("Referrer-Policy"):
            yield ctx.finding(
                "Referrer-Policy header missing", "info", "informational", "Security misconfiguration",
                rule_id="web.headers.referrer", rule_basis="Header absent", confidence="high",
                evidence="No Referrer-Policy header.", remediation="Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
                references=refs,
            )
        if html and not h.get("Permissions-Policy"):
            yield ctx.finding(
                "Permissions-Policy header missing", "info", "informational", "Security misconfiguration",
                rule_id="web.headers.permissions", rule_basis="Header absent", confidence="high",
                evidence="No Permissions-Policy header.", remediation="Restrict unused browser features with Permissions-Policy.",
                references=refs,
            )
        for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
            value = h.get(name)
            if value and re.search(r"\d", value):
                yield ctx.finding(
                    "Software version disclosed in %s header" % name, "low", "confirmed", "Information disclosure",
                    rule_id="web.headers.version-" + name.lower(), rule_basis="Header contains version digits",
                    confidence="high", evidence="%s: %s" % (name, short(value)),
                    impact="Helps attackers select exploits for the disclosed version.",
                    remediation="Remove or genericize version information in server configuration.",
                    references=[CWE % "200", OWASP_WSTG],
                )
        if h.get("X-XSS-Protection", "").strip().startswith("1"):
            yield ctx.finding(
                "Deprecated X-XSS-Protection filter enabled", "info", "informational", "Security misconfiguration",
                rule_id="web.headers.xxss", rule_basis="Header value enables legacy XSS auditor", confidence="high",
                evidence="X-XSS-Protection: %s" % h.get("X-XSS-Protection"),
                remediation="Set X-XSS-Protection: 0 and rely on Content-Security-Policy.", references=refs,
            )
        sets_cookie = bool(resp.set_cookies)
        cache = h.get("Cache-Control", "").lower()
        if html and sets_cookie and not ("no-store" in cache or "private" in cache):
            yield ctx.finding(
                "Cacheable response sets cookies", "low", "potential", "Cache and transport security",
                rule_id="web.headers.cache-cookie", rule_basis="Set-Cookie on response without no-store or private",
                confidence="low", evidence="Cache-Control: %s" % (h.get("Cache-Control") or "(absent)"),
                impact="Shared caches may store responses that contain session material.",
                remediation="Send Cache-Control: no-store on responses that set cookies or contain user data.",
                references=[CWE % "525"],
            )
        for header in ("Access-Control-Allow-Origin",):
            if h.get(header) == "*" and sets_cookie:
                yield ctx.finding(
                    "Wildcard CORS on response that sets cookies", "low", "potential", "Insecure CORS policy",
                    rule_id="web.headers.cors-wildcard-cookie", rule_basis="ACAO * with Set-Cookie", confidence="low",
                    evidence="Access-Control-Allow-Origin: *", remediation="Restrict CORS to specific trusted origins.",
                    references=[CWE % "942"],
                )
        private_ip = re.findall(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
                                resp.text[:200000] + " ".join("%s: %s" % kv for kv in h.items()))
        if private_ip:
            yield ctx.finding(
                "Internal IP address disclosed", "low", "confirmed", "Information disclosure",
                rule_id="web.headers.internal-ip", rule_basis="RFC 1918 address in response", confidence="medium",
                evidence="Addresses: %s" % ", ".join(sorted(set(private_ip))[:5]),
                remediation="Remove internal addressing from headers, comments and error output.", references=[CWE % "200"],
            )


@register
class CookieChecks(Plugin):
    id = "web.cookies"
    name = "Cookie attributes"
    description = "Inspects Set-Cookie attributes for missing Secure, HttpOnly, SameSite and prefix violations."
    categories = ("Session management", "Authentication")
    timeout = 60

    def run(self, ctx):
        resp = ctx.base()
        responses = list(resp.history) + [resp]
        seen = {}
        for r in responses:
            for raw in r.set_cookies:
                cookie = parse_set_cookie(raw)
                seen[cookie["name"]] = (cookie, scheme_of(r.url))
        for name, (cookie, scheme) in seen.items():
            attrs = cookie["attrs"]
            sessionish = bool(_SESSION_NAME.search(name))
            ctx.asset("cookie", name, {"attributes": sorted(attrs)})
            problems = []
            if scheme == "https" and "secure" not in attrs:
                problems.append(("Secure", "Cookie can be sent over unencrypted HTTP."))
            if "httponly" not in attrs:
                problems.append(("HttpOnly", "Cookie is readable by client-side scripts."))
            if "samesite" not in attrs:
                problems.append(("SameSite", "Cookie is sent on cross-site requests depending on browser defaults."))
            elif attrs["samesite"].lower() == "none" and "secure" not in attrs:
                problems.append(("SameSite=None without Secure", "Browsers reject or mishandle such cookies."))
            if name.startswith("__Host-") and not ("secure" in attrs and attrs.get("path") == "/" and "domain" not in attrs):
                problems.append(("__Host- prefix rules violated", "Prefix requires Secure, Path=/ and no Domain."))
            if name.startswith("__Secure-") and "secure" not in attrs:
                problems.append(("__Secure- prefix requires Secure", "Prefix requires the Secure attribute."))
            for flag, impact in problems:
                high = sessionish and flag in ("Secure", "HttpOnly")
                yield ctx.finding(
                    "Cookie '%s': %s" % (name, flag if ("prefix" in flag or "=" in flag) else "%s attribute missing" % flag),
                    "medium" if high else "low", "confirmed", "Session management",
                    rule_id="web.cookies." + re.sub(r"\W+", "-", flag.lower()), confidence="high",
                    rule_basis="Set-Cookie attributes; severity raised when the name suggests a session or auth cookie",
                    evidence="Set-Cookie: %s (value redacted); attributes: %s" % (name, ", ".join(sorted(attrs)) or "none"),
                    impact=impact, remediation="Set the Secure, HttpOnly and SameSite=Lax (or Strict) attributes on session cookies.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
                                CWE % "614"],
                    location=name,
                )


@register
class CorsChecks(Plugin):
    id = "web.cors"
    name = "CORS policy"
    description = "Tests whether the server reflects arbitrary origins, trusts null, or accepts look-alike origins."
    categories = ("Insecure CORS policy", "Broken access control")
    active = True
    risk = "low"
    timeout = 60
    min_profile = "standard"

    def run(self, ctx):
        host = host_of(ctx.target.value)
        probes = [
            ("arbitrary origin", "https://vulnscope-probe.invalid"),
            ("null origin", "null"),
            ("suffix look-alike", "https://%s.vulnscope-probe.invalid" % host),
            ("prefix look-alike", "https://vulnscope-probe%s" % host if not host[0].isdigit() else "https://x" + host),
        ]
        for label, origin in probes:
            ctx.check()
            try:
                resp = ctx.http.get(ctx.target.value, headers={"Origin": origin}, follow=False)
            except HttpError:
                continue
            acao = resp.header("Access-Control-Allow-Origin")
            acac = resp.header("Access-Control-Allow-Credentials").lower() == "true"
            if acao == origin:
                sev = "high" if acac else "medium"
                yield ctx.finding(
                    "CORS policy trusts %s%s" % (label, " with credentials" if acac else ""), sev, "confirmed",
                    "Insecure CORS policy", rule_id="web.cors." + label.replace(" ", "-"),
                    rule_basis="Server echoed the attacker-chosen Origin in Access-Control-Allow-Origin", confidence="high",
                    evidence="Origin: %s -> Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %s" % (origin, acao, acac),
                    impact="Other websites can read responses from this origin%s." % (" using the visitor's cookies" if acac else ""),
                    remediation="Validate Origin against an exact allow-list and avoid allowing credentials for untrusted origins.",
                    references=[CWE % "942", "https://portswigger.net/web-security/cors"],
                )
                break
            if acao == "*" and label == "arbitrary origin":
                yield ctx.finding(
                    "CORS allows any origin", "low" if not acac else "medium", "confirmed", "Insecure CORS policy",
                    rule_id="web.cors.wildcard", rule_basis="Access-Control-Allow-Origin is *", confidence="high",
                    evidence="Access-Control-Allow-Origin: *", impact="Any site can read unauthenticated responses.",
                    remediation="Restrict to required origins if the content is not public.", references=[CWE % "942"],
                )
                break


@register
class HttpMethods(Plugin):
    id = "web.methods"
    name = "HTTP methods"
    description = "Checks advertised methods and confirms TRACE echo without sending state-changing requests."
    categories = ("Security misconfiguration",)
    active = True
    timeout = 60
    min_profile = "standard"

    def run(self, ctx):
        try:
            resp = ctx.http.request("OPTIONS", ctx.target.value, follow=False)
        except HttpError:
            resp = None
        if resp is not None:
            allow = resp.header("Allow") or resp.header("Access-Control-Allow-Methods")
            risky = [m for m in ("PUT", "DELETE", "PATCH", "CONNECT") if re.search(r"\b%s\b" % m, allow, re.I)]
            if risky:
                yield ctx.finding(
                    "Server advertises state-changing HTTP methods", "low", "potential", "Security misconfiguration",
                    rule_id="web.methods.advertised", rule_basis="Allow header lists methods; no request using them was sent",
                    confidence="low", evidence="Allow: %s" % allow,
                    remediation="Disable methods that the application does not need.", references=[CWE % "650"],
                )
        marker = uuid.uuid4().hex[:12]
        try:
            trace = ctx.http.request("TRACE", ctx.target.value, headers={"X-VulnScope-Probe": marker}, follow=False)
        except HttpError:
            return
        if trace.status == 200 and marker in trace.text:
            yield ctx.finding(
                "HTTP TRACE method enabled", "low", "confirmed", "Security misconfiguration",
                rule_id="web.methods.trace", rule_basis="Server echoed the request including a unique marker header",
                confidence="high", evidence="TRACE returned status 200 and echoed header X-VulnScope-Probe: %s" % marker,
                impact="Can aid cross-site tracing attacks that expose headers.", remediation="Disable the TRACE method.",
                references=[CWE % "693"],
            )
