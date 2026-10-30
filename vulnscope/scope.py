import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

_METADATA = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "168.63.129.16"}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_PRIVATE_REASONS = {"loopback", "private", "link-local", "shared-address-space"}


class ScopeError(Exception):
    pass


class Cancelled(Exception):
    pass


def normalize_url(raw):
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty target")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise ValueError("only http and https targets are supported")
    host = parts.hostname
    if not host:
        raise ValueError("missing host")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("invalid host name")
    port = parts.port
    shown = "[%s]" % host if ":" in host else host
    default = 443 if parts.scheme == "https" else 80
    netloc = shown if port in (None, default) else "%s:%d" % (shown, port)
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def split_url(url):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, parts.hostname or "", port


def blocked_reason(ip_text):
    ip = ipaddress.ip_address(ip_text)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if str(ip) in _METADATA:
        return "cloud-metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.version == 4 and ip in _CGNAT:
        return "shared-address-space"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return None


def is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class Scope:
    def __init__(self, hosts=(), networks=(), allow_private=False, allow_subdomains=False):
        self.hosts = {h.lower().strip(".") for h in hosts if h}
        self.networks = []
        for net in networks:
            self.networks.append(ipaddress.ip_network(net, strict=False))
        self.allow_private = allow_private
        self.allow_subdomains = allow_subdomains

    def host_allowed(self, host):
        host = (host or "").lower().strip(".")
        if not host:
            return False
        if host in self.hosts:
            return True
        if self.allow_subdomains and not is_ip(host):
            for allowed in self.hosts:
                if host.endswith("." + allowed):
                    return True
        if is_ip(host):
            ip = ipaddress.ip_address(host)
            for net in self.networks:
                if ip.version == net.version and ip in net:
                    return True
        return False

    def validate_ip(self, ip_text):
        reason = blocked_reason(ip_text)
        if reason is None:
            return
        if reason in _PRIVATE_REASONS and self.allow_private:
            return
        raise ScopeError("destination %s blocked (%s)" % (ip_text, reason))

    def resolve(self, host, port=None):
        if is_ip(host):
            return [host]
        try:
            infos = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScopeError("cannot resolve %s: %s" % (host, exc))
        seen = []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.append(addr)
        return seen

    def resolve_checked(self, host, port=None):
        if not self.host_allowed(host):
            raise ScopeError("host %s is outside the authorized scope" % host)
        ips = self.resolve(host, port)
        if not ips:
            raise ScopeError("no addresses for %s" % host)
        for ip in ips:
            self.validate_ip(ip)
        return ips[0]

    def check_url(self, url):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScopeError("scheme %s not permitted" % parts.scheme)
        if not parts.hostname:
            raise ScopeError("missing host")
        if not self.host_allowed(parts.hostname):
            raise ScopeError("host %s is outside the authorized scope" % parts.hostname)
        if is_ip(parts.hostname):
            self.validate_ip(parts.hostname)


def build_scope(target, extra=(), allow_private=False, allow_subdomains=False):
    hosts, networks = [], []
    if target.host:
        if is_ip(target.host):
            networks.append(target.host)
        else:
            hosts.append(target.host)
    for item in extra:
        item = item.strip()
        if not item:
            continue
        if "/" in item or is_ip(item):
            networks.append(item)
        else:
            hosts.append(item)
    return Scope(hosts, networks, allow_private, allow_subdomains)
