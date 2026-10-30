import socket

from vulnscope.plugin import Plugin, register
from vulnscope.scope import ScopeError

try:
    import dns.resolver
    import dns.exception
    import dns.query
    import dns.zone
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

CWE = "https://cwe.mitre.org/data/definitions/%s.html"


def _resolver():
    res = dns.resolver.Resolver()
    res.lifetime = 5
    res.timeout = 5
    return res


def _txt_records(res, name):
    try:
        answer = res.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    out = []
    for rdata in answer:
        out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
    return out


@register
class EmailSecurity(Plugin):
    id = "net.email"
    name = "Email authentication (SPF/DKIM/DMARC)"
    description = "Checks SPF, DMARC policy strength and common DKIM selectors for the target domain."
    target_types = ("url", "host")
    categories = ("Email security configuration",)
    requires = ("py:dns",)
    timeout = 60

    def run(self, ctx):
        if not HAVE_DNS:
            return
        domain = ctx.target.host
        if not domain or domain.replace(".", "").isdigit():
            return
        try:
            domain.encode("idna")
        except UnicodeError:
            return
        res = _resolver()
        spf = [t for t in _txt_records(res, domain) if t.lower().startswith("v=spf1")]
        if not spf:
            yield ctx.finding(
                "SPF record missing", "low", "confirmed", "Email security configuration",
                rule_id="net.email.spf-missing", confidence="high", evidence="No v=spf1 TXT record found for %s." % domain,
                impact="Without SPF, receiving servers cannot verify that mail claiming to be from this domain was sent by an authorized server.",
                remediation="Publish an SPF TXT record listing authorized sending hosts and ending in -all.",
                references=["https://www.rfc-editor.org/rfc/rfc7208", CWE % "290"],
            )
        else:
            record = spf[0]
            if "+all" in record:
                yield ctx.finding(
                    "SPF record allows any sender (+all)", "medium", "confirmed", "Email security configuration",
                    rule_id="net.email.spf-permissive", confidence="high", evidence=record,
                    remediation="Replace +all with -all (or ~all while testing) once all legitimate senders are listed.",
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                )
            elif "all" not in record:
                yield ctx.finding(
                    "SPF record has no 'all' mechanism", "low", "confirmed", "Email security configuration",
                    rule_id="net.email.spf-no-all", confidence="high", evidence=record,
                    remediation="Add -all or ~all at the end of the SPF record.", references=["https://www.rfc-editor.org/rfc/rfc7208"],
                )
            lookups = record.count("include:") + record.count("redirect=") + record.count("a:") + record.count("mx")
            if lookups > 10:
                yield ctx.finding(
                    "SPF record likely exceeds the 10 DNS lookup limit", "low", "potential", "Email security configuration",
                    rule_id="net.email.spf-too-many-lookups", confidence="low", evidence=record,
                    impact="SPF evaluation fails open or closed unpredictably once the lookup limit is exceeded.",
                    remediation="Flatten includes or reduce mechanisms that trigger DNS lookups.",
                    references=["https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"],
                )
        dmarc = _txt_records(res, "_dmarc." + domain)
        dmarc_rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
        if not dmarc_rec:
            yield ctx.finding(
                "DMARC record missing", "medium", "confirmed", "Email security configuration",
                rule_id="net.email.dmarc-missing", confidence="high", evidence="No DMARC TXT record at _dmarc.%s." % domain,
                impact="Without DMARC, spoofed mail using this domain is not reported or blocked by policy.",
                remediation="Publish a DMARC record, starting with p=none while monitoring, then moving to quarantine or reject.",
                references=["https://www.rfc-editor.org/rfc/rfc7489", CWE % "290"],
            )
        else:
            policy = dict(p.strip().split("=", 1) for p in dmarc_rec.split(";") if "=" in p)
            if policy.get("p", "").lower() == "none":
                yield ctx.finding(
                    "DMARC policy is 'none' (monitor only)", "low", "confirmed", "Email security configuration",
                    rule_id="net.email.dmarc-none", confidence="high", evidence=dmarc_rec,
                    remediation="Move to p=quarantine or p=reject once SPF/DKIM alignment is confirmed via DMARC reports.",
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                )
            if "rua" not in policy:
                yield ctx.finding(
                    "DMARC record has no aggregate reporting address", "info", "informational", "Email security configuration",
                    rule_id="net.email.dmarc-no-rua", confidence="high", evidence=dmarc_rec,
                    remediation="Add rua=mailto:dmarc-reports@%s to receive aggregate reports." % domain,
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                )
        found_dkim = []
        for selector in ("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "smtp", "mandrill", "sendgrid"):
            ctx.check()
            if _txt_records(res, "%s._domainkey.%s" % (selector, domain)):
                found_dkim.append(selector)
        if found_dkim:
            ctx.asset("dkim-selector", domain, {"selectors": found_dkim})
        try:
            mx = res.resolve(domain, "MX")
            has_mx = len(mx) > 0
        except dns.exception.DNSException:
            has_mx = False
        if has_mx and not dmarc_rec and not spf:
            yield ctx.finding(
                "Mail-capable domain has neither SPF nor DMARC", "medium", "confirmed", "Email security configuration",
                rule_id="net.email.no-auth", confidence="high", evidence="MX records present; no SPF or DMARC records found.",
                remediation="Publish SPF and DMARC records for this domain.", references=["https://www.rfc-editor.org/rfc/rfc7489"],
            )


@register
class DnsConfig(Plugin):
    id = "net.dns"
    name = "DNS configuration"
    description = "Tests DNS zone transfer exposure, CAA records and nameserver diversity for the target domain."
    target_types = ("url", "host")
    categories = ("DNS and domain configuration",)
    active = True
    requires = ("py:dns",)
    timeout = 60
    min_profile = "standard"

    def run(self, ctx):
        if not HAVE_DNS:
            return
        domain = ctx.target.host
        if not domain or domain.replace(".", "").isdigit():
            return
        res = _resolver()
        try:
            ns_answer = res.resolve(domain, "NS")
            nameservers = sorted(str(r.target).rstrip(".") for r in ns_answer)
        except dns.exception.DNSException:
            nameservers = []
        if len(nameservers) == 1:
            yield ctx.finding(
                "Only one authoritative name server configured", "low", "confirmed", "DNS and domain configuration",
                rule_id="net.dns.single-ns", confidence="high", evidence="NS records: %s" % ", ".join(nameservers),
                impact="A single point of failure can take the domain offline.", remediation="Configure at least two independent name servers.",
            )
        caa = _txt_records(res, domain)
        try:
            caa_answer = res.resolve(domain, "CAA")
            has_caa = len(caa_answer) > 0
        except dns.exception.DNSException:
            has_caa = False
        if not has_caa:
            yield ctx.finding(
                "No CAA record published", "info", "informational", "DNS and domain configuration",
                rule_id="net.dns.no-caa", confidence="high", evidence="No CAA record found for %s." % domain,
                remediation="Publish a CAA record restricting which certificate authorities may issue for this domain.",
                references=["https://www.rfc-editor.org/rfc/rfc8659"],
            )
        for ns in nameservers:
            ctx.check()
            try:
                ns_ip = ctx.scope.resolve_checked(ns, 53) if ctx.scope.host_allowed(ns) else socket.gethostbyname(ns)
            except (ScopeError, socket.gaierror):
                continue
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5, lifetime=8))
                count = len(list(zone.nodes))
            except Exception:
                continue
            if count:
                yield ctx.finding(
                    "DNS zone transfer (AXFR) allowed", "high", "confirmed", "DNS and domain configuration",
                    rule_id="net.dns.axfr", confidence="high", evidence="Name server %s returned %d records for an AXFR request." % (ns, count),
                    impact="The entire DNS zone, including internal host names, is exposed to anyone.",
                    remediation="Restrict zone transfers to authorized secondary name servers only.",
                    references=[CWE % "200"], location=ns,
                )
