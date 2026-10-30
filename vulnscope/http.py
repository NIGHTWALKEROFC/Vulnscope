import threading
import time
from urllib.parse import urljoin

import requests
import urllib3
import urllib3.util.connection as _uc

from vulnscope.scope import Cancelled, ScopeError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_local = threading.local()
_original_connect = _uc.create_connection


def _guarded_connect(address, *args, **kwargs):
    scope = getattr(_local, "scope", None)
    if scope is None:
        return _original_connect(address, *args, **kwargs)
    host, port = address
    ip = scope.resolve_checked(host, port)
    return _original_connect((ip, port), *args, **kwargs)


_uc.create_connection = _guarded_connect


class HttpError(Exception):
    pass


class Resp:
    def __init__(self, url, status, headers, body, elapsed, set_cookies, truncated, reason=""):
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed = elapsed
        self.set_cookies = set_cookies
        self.truncated = truncated
        self.reason = reason
        self.history = []
        self._text = None

    def header(self, name, default=""):
        value = self.headers.get(name)
        return default if value is None else value

    @property
    def text(self):
        if self._text is None:
            charset = "utf-8"
            ctype = self.header("Content-Type").lower()
            if "charset=" in ctype:
                charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
            try:
                self._text = self.body.decode(charset, "replace")
            except LookupError:
                self._text = self.body.decode("utf-8", "replace")
        return self._text

    @property
    def content_type(self):
        return self.header("Content-Type").split(";")[0].strip().lower()

    @property
    def is_html(self):
        return self.content_type in ("text/html", "application/xhtml+xml")


class SafeSession:
    def __init__(self, scope, cfg, cancel=None, headers=None, cookies=None, version="0"):
        http = cfg.data["http"]
        self.scope = scope
        self.timeout = http["timeout"]
        self.max_bytes = http["max_response_bytes"]
        rate = float(http["rate_limit_per_sec"]) or 1.0
        self.interval = 1.0 / rate
        self.retries = int(http["retries"])
        self.max_redirects = int(http["max_redirects"])
        self.verify = bool(http["verify_tls"])
        self.tls_error = ""
        self.cancel = cancel or (lambda: False)
        self.count = 0
        self._lock = threading.Lock()
        self._next = 0.0
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": http["user_agent"].format(version=version), "Accept": "*/*"})
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.headers["Cookie"] = cookies

    def _throttle(self):
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.interval
        if wait:
            time.sleep(wait)

    def _check_cancel(self):
        if self.cancel():
            raise Cancelled()

    def _send(self, method, url, headers, data, json_body, timeout):
        attempt = 0
        while True:
            self._check_cancel()
            self._throttle()
            _local.scope = self.scope
            started = time.monotonic()
            try:
                resp = self.session.request(
                    method, url, headers=headers, data=data, json=json_body,
                    timeout=timeout or self.timeout, allow_redirects=False,
                    stream=True, verify=self.verify,
                )
                try:
                    body = bytearray()
                    truncated = False
                    for chunk in resp.iter_content(8192):
                        body.extend(chunk)
                        if len(body) > self.max_bytes:
                            truncated = True
                            del body[self.max_bytes:]
                            break
                    raw = resp.raw.headers
                    cookies = raw.getlist("Set-Cookie") if hasattr(raw, "getlist") else []
                    result = Resp(url, resp.status_code, resp.headers, bytes(body),
                                  time.monotonic() - started, list(cookies), truncated, resp.reason or "")
                finally:
                    resp.close()
                self.count += 1
                return result
            except ScopeError:
                raise
            except requests.exceptions.SSLError as exc:
                if self.verify:
                    self.verify = False
                    self.tls_error = str(exc)[:300]
                    continue
                raise HttpError(str(exc)[:300])
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError) as exc:
                attempt += 1
                if attempt > self.retries:
                    raise HttpError(str(exc)[:300])
                time.sleep(0.4 * attempt)
            except requests.exceptions.RequestException as exc:
                raise HttpError(str(exc)[:300])
            finally:
                _local.scope = None

    def request(self, method, url, headers=None, data=None, json=None, follow=True, timeout=None):
        history = []
        current = url
        verb = method.upper()
        for _ in range(self.max_redirects + 1):
            self.scope.check_url(current)
            resp = self._send(verb, current, headers, data, json, timeout)
            location = resp.header("Location")
            if follow and resp.status in (301, 302, 303, 307, 308) and location:
                history.append(resp)
                current = urljoin(current, location)
                if resp.status in (301, 302, 303) and verb not in ("GET", "HEAD"):
                    verb, data, json = "GET", None, None
                continue
            resp.history = history
            return resp
        raise HttpError("too many redirects")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)
