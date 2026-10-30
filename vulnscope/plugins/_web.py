import re
from urllib.parse import urlsplit

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
MDN_CSP = "https://developer.mozilla.org/docs/Web/HTTP/CSP"
MDN_HSTS = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
OWASP_TOP10 = "https://owasp.org/Top10/"
OWASP_WSTG = "https://owasp.org/www-project-web-security-testing-guide/"
OWASP_API = "https://owasp.org/API-Security/"
CWE = "https://cwe.mitre.org/data/definitions/%s.html"

_SERVER = re.compile(r"([A-Za-z][A-Za-z0-9_.\- ]*?)[/ _-]v?(\d+(?:\.\d+){1,4}[a-z0-9]*)")


def parse_product_header(value):
    out = []
    for token in re.split(r"[,\s]\s*(?=[A-Za-z])", value or ""):
        match = _SERVER.match(token.strip().split("(")[0].strip())
        if match:
            out.append((match.group(1).strip().lower(), match.group(2)))
    return out


def parse_set_cookie(raw):
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return {"name": name.strip(), "value": value, "attrs": attrs}


def scheme_of(url):
    return urlsplit(url).scheme


def host_of(url):
    return (urlsplit(url).hostname or "").lower()


def short(text, limit=300):
    text = str(text).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


def body_hash(text):
    import hashlib

    normalized = re.sub(r"\s+", " ", text)
    return hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()
