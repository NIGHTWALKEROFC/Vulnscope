from html.parser import HTMLParser
from urllib.parse import urljoin


class PageInfo:
    def __init__(self):
        self.title = ""
        self.links = []
        self.scripts = []
        self.stylesheets = []
        self.forms = []
        self.meta = {}
        self.iframes = []
        self.inline_scripts = []
        self.comments = []


class _Parser(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.info = PageInfo()
        self._form = None
        self._in_title = False
        self._in_script = False
        self._script_buf = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        info = self.info
        if tag == "a" and a.get("href"):
            info.links.append(urljoin(self.base, a["href"]))
        elif tag == "script":
            if a.get("src"):
                info.scripts.append({"src": urljoin(self.base, a["src"]), "raw": a["src"],
                                     "integrity": a.get("integrity", ""), "crossorigin": a.get("crossorigin", "")})
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            info.stylesheets.append({"href": urljoin(self.base, a["href"]), "raw": a["href"],
                                     "integrity": a.get("integrity", "")})
        elif tag == "iframe" and a.get("src"):
            info.iframes.append(urljoin(self.base, a["src"]))
        elif tag == "meta":
            key = (a.get("name") or a.get("http-equiv") or "").lower()
            if key:
                info.meta[key] = a.get("content", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {"action": urljoin(self.base, a.get("action", "") or self.base),
                          "method": (a.get("method") or "get").lower(),
                          "enctype": a.get("enctype", "").lower(), "inputs": []}
            info.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append({"name": name, "type": (a.get("type") or "text").lower() if tag == "input" else tag,
                                             "value": a.get("value", ""), "autocomplete": a.get("autocomplete", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_script:
            self._in_script = False
            self.info.inline_scripts.append("".join(self._script_buf))

    def handle_data(self, data):
        if self._in_title:
            self.info.title += data
        if self._in_script:
            self._script_buf.append(data)

    def handle_comment(self, data):
        self.info.comments.append(data)


def parse_html(text, base):
    parser = _Parser(base)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass
    return parser.info
