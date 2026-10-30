import socket
import ssl
import time
from urllib.parse import urlsplit

from vulnscope.plugin import Plugin, register
from vulnscope.scope import ScopeError, is_ip

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError:
    x509 = None

REF_RFC8996 = "https://www.rfc-editor.org/rfc/rfc8996"
CIPHER_TESTS = [
    ("RC4", "RC4", "high", "RC4 is broken and prohibited by RFC 7465", ["https://www.rfc-editor.org/rfc/rfc7465"], []),
    ("3DES", "3DES:!aNULL", "medium", "64-bit block ciphers are vulnerable to birthday attacks (SWEET32)", ["https://sweet32.info/"], ["CVE-2016-2183"]),
    ("export-grade", "EXPORT", "high", "Export-grade ciphers allow downgrade attacks such as FREAK and Logjam", ["https://weakdh.org/"], ["CVE-2015-0204", "CVE-2015-4000"]),
    ("NULL encryption", "eNULL", "critical", "Traffic is not encrypted", [], []),
    ("anonymous key exchange", "aNULL", "high", "Server identity is not authenticated", [], []),
    ("single DES", "DES:!3DES", "high", "56-bit keys can be brute-forced", [], []),
]


def _client_context(min_v=None, max_v=None, ciphers=None, verify=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) if not verify else ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if ciphers:
        ctx.set_ciphers(ciphers)
    if min_v is not None:
        ctx.minimum_version = min_v
    if max_v is not None:
        ctx.maximum_version = max_v
    return ctx


def _handshake(scope, host, port, sslctx, timeout=8):
    ip = scope.resolve_checked(host, port)
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock = sslctx.wrap_socket(raw, server_hostname=None if is_ip(host) else host)
    except Exception:
        raw.close()
        raise
    return sock


@register
class TlsChecks(Plugin):
    id = "web.tls"
    name = "TLS configuration"
    description = "Validates certificates and tests protocol versions and weak cipher families by completing real handshakes."
    target_types = ("url", "host")
    categories = ("Transport security", "Cryptographic configuration", "Certificate problems")
    active = True
    timeout = 120
    min_profile = "standard"

    def run(self, ctx):
        host, port = ctx.target.host, ctx.target.port or 443
        if ctx.target.kind == "url" and ctx.target.scheme == "http":
            port = 443
        if ctx.target.kind == "host" and ("/" in host):
            return
        location = "%s:%d" % (host, port)
        try:
            probe = _handshake(ctx.scope, host, port, _client_context())
            probe.close()
        except ScopeError:
            raise
        except (OSError, ssl.SSLError):
            return
        try:
            sock = _handshake(ctx.scope, host, port, _client_context(verify=True))
            cert = sock.getpeercert()
            sock.close()
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
            days = (expires - time.time()) / 86400.0
            if days < 30:
                yield ctx.finding(
                    "Certificate expires in %d days" % max(int(days), 0), "low" if days > 7 else "medium", "confirmed",
                    "Certificate problems", rule_id="web.tls.expiring", rule_basis="notAfter within 30 days", confidence="high",
                    evidence="notAfter: %s" % cert["notAfter"], remediation="Renew the certificate and automate renewal.",
                    location=location, references=["https://letsencrypt.org/docs/integration-guide/"],
                )
            ctx.asset("certificate", location, {"subject": str(cert.get("subject")), "notAfter": cert["notAfter"],
                                               "san": [v for _, v in cert.get("subjectAltName", [])][:20]})
        except ssl.SSLCertVerificationError as exc:
            code = exc.verify_code
            kinds = {10: ("Certificate has expired", "high"), 18: ("Self-signed certificate", "medium"),
                     19: ("Certificate chain contains a self-signed root that is not trusted", "medium"),
                     20: ("Certificate issuer is not trusted", "medium"), 21: ("Certificate chain is incomplete", "medium"),
                     62: ("Certificate does not match the host name", "medium")}
            title, sev = kinds.get(code, ("Certificate validation failed", "medium"))
            yield ctx.finding(
                title, sev, "confirmed", "Certificate problems", rule_id="web.tls.verify-%s" % code,
                rule_basis="Python ssl verification against the system trust store", confidence="high",
                evidence="verify code %s: %s" % (code, exc.verify_message), location=location,
                impact="Clients cannot authenticate the server and may be exposed to interception.",
                remediation="Install a certificate from a trusted CA that matches the host name and includes intermediates.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"],
            )
        except (OSError, ssl.SSLError):
            pass
        for f in self._certificate_details(ctx, host, port, location):
            yield f
        accepted = {}
        for name, version in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                              ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
            ctx.check()
            try:
                sslctx = _client_context(version, version, "ALL:@SECLEVEL=0" if name in ("TLSv1.0", "TLSv1.1") else None)
                sock = _handshake(ctx.scope, host, port, sslctx)
                accepted[name] = True
                sock.close()
            except ScopeError:
                raise
            except (ssl.SSLError, OSError, ValueError):
                accepted[name] = False
        ctx.asset("tls-protocols", location, accepted)
        for name in ("TLSv1.0", "TLSv1.1"):
            if accepted.get(name):
                yield ctx.finding(
                    "Deprecated protocol %s supported" % name, "medium", "confirmed", "Cryptographic configuration",
                    rule_id="web.tls.proto-" + name.lower().replace(".", ""), rule_basis="Completed a %s handshake" % name,
                    confidence="high", evidence="Server completed a handshake using %s." % name,
                    impact="Older protocol versions have known weaknesses and are prohibited by RFC 8996.",
                    remediation="Disable TLS 1.0 and 1.1; support TLS 1.2 and 1.3 only.", location=location, references=[REF_RFC8996],
                )
        if accepted.get("TLSv1.2") and not accepted.get("TLSv1.3"):
            yield ctx.finding(
                "TLS 1.3 not supported", "info", "informational", "Cryptographic configuration",
                rule_id="web.tls.no-tls13", rule_basis="TLS 1.3 handshake failed while TLS 1.2 succeeded", confidence="medium",
                evidence="Only TLS 1.2 handshakes completed.", remediation="Enable TLS 1.3 where the stack supports it.", location=location,
            )
        for label, spec, sev, impact, refs, cves in CIPHER_TESTS:
            ctx.check()
            try:
                sslctx = _client_context(None, ssl.TLSVersion.TLSv1_2, "%s:@SECLEVEL=0" % spec)
            except (ssl.SSLError, ValueError):
                ctx.asset("tls-untested", label, {"reason": "local OpenSSL build lacks these ciphers"})
                continue
            try:
                sock = _handshake(ctx.scope, host, port, sslctx)
                chosen = sock.cipher()
                sock.close()
            except ScopeError:
                raise
            except (ssl.SSLError, OSError):
                continue
            yield ctx.finding(
                "Weak cipher family accepted: %s" % label, sev, "confirmed", "Cryptographic configuration",
                rule_id="web.tls.cipher-" + label.replace(" ", "-"), rule_basis="Completed a handshake restricted to this cipher family",
                confidence="high", evidence="Negotiated cipher: %s" % (chosen[0] if chosen else "unknown"), impact=impact,
                remediation="Remove these cipher suites from the server configuration.", location=location,
                references=refs, cve=cves,
            )

    def _certificate_details(self, ctx, host, port, location):
        if x509 is None:
            return
        try:
            sock = _handshake(ctx.scope, host, port, _client_context())
            der = sock.getpeercert(binary_form=True)
            sock.close()
            cert = x509.load_der_x509_certificate(der)
        except ScopeError:
            raise
        except Exception:
            return
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            yield ctx.finding(
                "Certificate uses a %d-bit RSA key" % key.key_size, "high", "confirmed", "Certificate problems",
                rule_id="web.tls.weak-rsa", rule_basis="RSA modulus shorter than 2048 bits", confidence="high",
                evidence="Public key size: %d bits" % key.key_size, remediation="Reissue the certificate with RSA 2048 or larger or ECDSA P-256.",
                location=location,
            )
        if isinstance(key, ec.EllipticCurvePublicKey) and key.key_size < 224:
            yield ctx.finding(
                "Certificate uses a weak elliptic curve", "high", "confirmed", "Certificate problems",
                rule_id="web.tls.weak-ec", rule_basis="Curve smaller than 224 bits", confidence="high",
                evidence="Key size: %d bits" % key.key_size, remediation="Use P-256 or stronger.", location=location,
            )
        algo = cert.signature_hash_algorithm
        if algo is not None and isinstance(algo, (hashes.SHA1, hashes.MD5)):
            yield ctx.finding(
                "Certificate signed with %s" % algo.name.upper(), "medium", "confirmed", "Certificate problems",
                rule_id="web.tls.weak-signature", rule_basis="Signature hash algorithm is collision-prone", confidence="high",
                evidence="Signature hash: %s" % algo.name, remediation="Reissue the certificate with SHA-256 or stronger.", location=location,
            )
