import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

from vulnscope.intel.matcher import cve_findings
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._net import COMMON_PORTS, NO_AUTH_PROBES, SERVICE_NAMES, VULNERABLE_SERVICES
from vulnscope.scope import ScopeError, is_ip

_BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 587, 3306, 5432, 6379, 11211, 25565, 27017}
_HTTP_LIKE = {80, 443, 8000, 8008, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 3000}


def _connect(scope, host, port, timeout):
    ip = scope.resolve_checked(host, port)
    sock = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((ip, port))
    return sock


def probe_port(scope, host, port, timeout):
    try:
        sock = _connect(scope, host, port, timeout)
    except ScopeError:
        raise
    except (OSError, socket.timeout):
        return None
    banner, tls_info = "", None
    try:
        sock.settimeout(timeout)
        if port in (443, 8443, 9443, 465, 993, 995, 990, 636, 5986, 3269):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock)
                tls_info = tls_sock.version()
                sock = tls_sock
            except (ssl.SSLError, OSError):
                pass
        if port in _HTTP_LIKE or tls_info:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" % host.encode())
                banner = sock.recv(1024).decode("latin1", "replace")
            except OSError:
                pass
        elif port in _BANNER_PORTS:
            try:
                data = sock.recv(256)
                banner = data.decode("latin1", "replace")
            except OSError:
                pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return {"banner": banner.strip()[:300], "tls": tls_info}


def probe_unauth(scope, host, port, timeout, service):
    payload = NO_AUTH_PROBES.get(service)
    if not payload:
        return None
    try:
        sock = _connect(scope, host, port, timeout)
    except ScopeError:
        raise
    except OSError:
        return None
    try:
        sock.sendall(payload[0])
        sock.settimeout(timeout)
        data = sock.recv(256)
        return payload[1] in data
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


@register
class PortScan(Plugin):
    id = "net.ports"
    name = "TCP port and service scan"
    description = "Connects to common TCP ports on an authorized host, grabs banners and flags unauthenticated high-risk services."
    target_types = ("host",)
    categories = ("Network asset inventory", "Exposed service", "Weak protocol")
    active = True
    timeout = 300

    def run(self, ctx):
        host = ctx.target.host
        if "/" in host:
            yield from self._network(ctx, host)
            return
        yield from self._host(ctx, host)

    def _host(self, ctx, host):
        cfg = ctx.config.data["scan"]
        timeout, workers = cfg["port_timeout"], cfg["port_concurrency"]
        ports = COMMON_PORTS
        open_ports = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(probe_port, ctx.scope, host, port, timeout): port for port in ports}
            for future in futures:
                ctx.check()
                port = futures[future]
                try:
                    result = future.result()
                except ScopeError as exc:
                    yield ctx.finding(
                        "Port scan blocked by scope policy", "info", "informational", "Network asset inventory",
                        rule_id="net.ports.scope-block", confidence="high", evidence=str(exc),
                        remediation="Expand the authorized scope with --allow-private if this target is intentional.",
                    )
                    return
                except Exception:
                    result = None
                if result is not None:
                    open_ports[port] = result
        for port in sorted(open_ports):
            info = open_ports[port]
            service = SERVICE_NAMES.get(port, "unknown")
            ctx.asset("open-port", "%s:%d" % (host, port), {"service": service, "banner": info["banner"], "tls": info["tls"]})
            yield ctx.finding(
                "Open port %d/tcp (%s)" % (port, service), "info", "informational", "Network asset inventory",
                target="%s:%d" % (host, port), rule_id="net.ports.open", confidence="high",
                evidence="TCP connect succeeded on port %d.%s" % (port, (" Banner: %s" % info["banner"]) if info["banner"] else ""),
                location="%s:%d" % (host, port),
            )
            risk = VULNERABLE_SERVICES.get(service)
            if risk:
                sev, impact, cwes = risk
                unauth = probe_unauth(ctx.scope, host, port, timeout, service)
                status = "confirmed" if unauth else "potential"
                evidence = "Service %s identified on port %d." % (service, port)
                if unauth:
                    evidence += " Responded to an unauthenticated protocol probe."
                yield ctx.finding(
                    "%s exposed on port %d" % (service, port), sev if unauth else _downgrade(sev), status,
                    "Exposed service", target="%s:%d" % (host, port), rule_id="net.ports.risk." + service,
                    confidence="high" if unauth else "medium", rule_basis="Service identified by well-known port and banner",
                    evidence=evidence, impact=impact, location="%s:%d" % (host, port),
                    remediation="Restrict access with a firewall or VPN, require authentication, and disable the service if unused.",
                    references=["https://nvd.nist.gov/vuln-metrics/cvss"],
                    notes="" if unauth else "Authentication was not verified; the service may already require credentials.",
                )
            if info["banner"] and ctx.intel:
                yield from _banner_cves(ctx, host, port, service, info["banner"])

    def _network(self, ctx, cidr):
        import ipaddress

        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
        limit = ctx.config.data["scan"]["max_hosts"]
        if len(hosts) > limit:
            yield ctx.finding(
                "Network too large for a single scan", "info", "informational", "Network asset inventory",
                rule_id="net.ports.too-large", confidence="high",
                evidence="%s contains %d hosts; the configured limit is %d." % (cidr, len(hosts), limit),
                remediation="Scan smaller subnets or raise scan.max_hosts in the configuration.",
            )
            hosts = hosts[:limit]
        live = []
        timeout = ctx.config.data["scan"]["port_timeout"]
        with ThreadPoolExecutor(max_workers=min(64, ctx.config.data["scan"]["port_concurrency"])) as pool:
            quick_ports = (80, 443, 22)
            futures = {}
            for host in hosts:
                for port in quick_ports:
                    futures[pool.submit(probe_port, ctx.scope, str(host), port, min(timeout, 1.2))] = str(host)
            for future in futures:
                ctx.check()
                try:
                    if future.result() is not None:
                        live.append(futures[future])
                except (ScopeError, Exception):
                    continue
        live = sorted(set(live))
        for host in live:
            ctx.asset("live-host", host, {})
            yield ctx.finding(
                "Host %s is reachable" % host, "info", "informational", "Network asset inventory", target=host,
                rule_id="net.ports.live-host", confidence="medium", evidence="Responded on a common port during discovery.",
                location=host,
            )
        for host in live:
            yield from self._host(ctx, host)


def _downgrade(sev):
    order = ["critical", "high", "medium", "low", "info"]
    idx = order.index(sev) if sev in order else len(order) - 1
    return order[min(idx + 1, len(order) - 1)]


def _banner_cves(ctx, host, port, service, banner):
    from vulnscope.versions import extract_version

    label_map = {"ssh": "openssh", "http": None, "https": None, "ftp": None, "smtp": None}
    text = banner
    product = None
    for name in ("OpenSSH", "nginx", "Apache", "ProFTPD", "vsftpd", "Pure-FTPd", "Postfix", "Exim", "Dovecot",
                 "MySQL", "MariaDB", "PostgreSQL", "Redis", "lighttpd", "OpenSSL"):
        if name.lower() in text.lower():
            product = name.lower()
            break
    if not product:
        return
    version = extract_version(text)
    if not version:
        return
    for f in cve_findings(ctx, product, version, "Service banner on %s:%d: %s" % (host, port, text[:120]), "medium",
                          target="%s:%d" % (host, port), location="%s:%d" % (host, port)):
        yield f
