from collections import deque
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from vulnscope.htmlparse import parse_html
from vulnscope.http import HttpError

_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tar", ".rar", ".7z", ".pdf", ".mp4", ".mp3", ".avi", ".mov", ".exe", ".apk", ".dmg", ".iso",
}
_TEXT_TYPES = {"text", "email", "search", "url", "tel", "number", "hidden", "textarea", "select", "password"}


class CrawlResult:
    def __init__(self):
        self.pages = {}
        self.forms = []
        self.points = []
        self.scripts = set()
        self.errors = []


def _strip(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _skip(url):
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in _SKIP_EXT)


def crawl(ctx):
    cached = ctx.shared_get("crawl")
    if cached is not None:
        return cached
    with ctx.shared_lock("crawl"):
        cached = ctx.shared_get("crawl")
        if cached is not None:
            return cached
        result = _crawl(ctx)
        ctx.shared_set("crawl", result)
        return result


def _crawl(ctx):
    cfg = ctx.config.data["scan"]
    limit, depth_limit = cfg["max_pages"], cfg["max_depth"]
    allow_post = ctx.profile == "comprehensive"
    start = ctx.target.value
    result = CrawlResult()
    queue = deque([(start, 0)])
    seen = {_strip(start)}
    seen_points = set()

    def add_point(url, method, params):
        key = (urlsplit(url).path, method, tuple(sorted(params)))
        if params and key not in seen_points:
            seen_points.add(key)
            result.points.append({"url": url, "method": method, "params": dict(params)})

    while queue and len(result.pages) < limit:
        ctx.check()
        url, depth = queue.popleft()
        try:
            resp = ctx.http.get(url)
        except HttpError as exc:
            result.errors.append("%s: %s" % (url, exc))
            continue
        result.pages[url] = resp
        query = urlsplit(url).query
        if query:
            add_point(url.split("?", 1)[0], "GET", dict(parse_qsl(query, keep_blank_values=True)))
        if not resp.is_html:
            continue
        info = parse_html(resp.text, resp.url)
        for script in info.scripts:
            result.scripts.add(script["src"])
        for form in info.forms:
            result.forms.append({"page": url, **form})
            names = {i["name"]: (i["value"] or "1") for i in form["inputs"] if i["type"] in _TEXT_TYPES}
            has_sensitive = any(i["type"] in ("password", "file") for i in form["inputs"])
            if form["method"] == "get":
                add_point(form["action"].split("?", 1)[0], "GET", names)
            elif allow_post and not has_sensitive:
                add_point(form["action"], "POST", names)
        if depth >= depth_limit:
            continue
        for link in info.links:
            clean = _strip(link)
            if clean in seen or _skip(clean):
                continue
            if not ctx.scope.host_allowed(urlsplit(clean).hostname):
                continue
            seen.add(clean)
            queue.append((clean, depth + 1))
    return result
