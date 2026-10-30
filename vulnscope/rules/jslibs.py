import re

DETECTORS = [
    ("jquery", re.compile(r"jquery[-.@/ v]*(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I), re.compile(r"jQuery(?: JavaScript Library)? v?(\d+\.\d+(?:\.\d+)?)")),
    ("jquery-ui", re.compile(r"jquery-ui[-.@/ v]*(\d+\.\d+(?:\.\d+)?)", re.I), re.compile(r"jQuery UI - v(\d+\.\d+(?:\.\d+)?)")),
    ("bootstrap", re.compile(r"bootstrap[-.@/ v]*(\d+\.\d+\.\d+)", re.I), re.compile(r"Bootstrap v(\d+\.\d+\.\d+)")),
    ("angularjs", re.compile(r"angular(?:js)?[-.@/ v]*(1\.\d+\.\d+)", re.I), re.compile(r"AngularJS v(1\.\d+\.\d+)")),
    ("lodash", re.compile(r"lodash[-.@/ v]*(\d+\.\d+\.\d+)", re.I), re.compile(r"lodash(?:\.js)?[ @v]*(\d+\.\d+\.\d+)|VERSION\s*=\s*['\"](4\.\d+\.\d+)['\"]")),
    ("moment", re.compile(r"moment(?:\.min)?[-.@/ v]*(\d+\.\d+\.\d+)", re.I), re.compile(r"version\s*:\s*(\d+\.\d+\.\d+)")),
    ("handlebars", re.compile(r"handlebars[-.@/ v]*(\d+\.\d+\.\d+)", re.I), re.compile(r"Handlebars\.VERSION\s*=\s*[\"'](\d+\.\d+\.\d+)|handlebars v(\d+\.\d+\.\d+)", re.I)),
    ("underscore", re.compile(r"underscore[-.@/ v]*(\d+\.\d+\.\d+)", re.I), re.compile(r"Underscore\.js (\d+\.\d+\.\d+)")),
    ("axios", re.compile(r"axios[-.@/ v]*(\d+\.\d+\.\d+)", re.I), re.compile(r"axios v(\d+\.\d+\.\d+)")),
]

RULES = {
    "jquery": [
        {"start": "1.2.0", "end": "3.5.0", "cve": ["CVE-2020-11022", "CVE-2020-11023"], "sev": "medium",
         "summary": "Cross-site scripting through HTML passed to DOM manipulation methods", "fix": "3.5.0"},
        {"end": "3.4.0", "cve": ["CVE-2019-11358"], "sev": "medium",
         "summary": "Prototype pollution in jQuery.extend", "fix": "3.4.0"},
        {"end": "3.0.0", "cve": ["CVE-2015-9251"], "sev": "medium",
         "summary": "Cross-site scripting in cross-domain Ajax requests", "fix": "3.0.0"},
    ],
    "jquery-ui": [
        {"end": "1.13.0", "cve": ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"], "sev": "medium",
         "summary": "Cross-site scripting in several widget options", "fix": "1.13.0"},
    ],
    "bootstrap": [
        {"end": "3.4.1", "cve": ["CVE-2019-8331"], "sev": "medium", "summary": "Cross-site scripting in tooltip and popover data-template", "fix": "3.4.1"},
        {"start": "4.0.0", "end": "4.3.1", "cve": ["CVE-2019-8331"], "sev": "medium", "summary": "Cross-site scripting in tooltip and popover data-template", "fix": "4.3.1"},
    ],
    "angularjs": [
        {"end": "1.8.0", "cve": ["CVE-2020-7676"], "sev": "medium", "summary": "Cross-site scripting through sanitizer bypass", "fix": "1.8.0"},
        {"end": "2.0.0", "cve": [], "sev": "low", "summary": "AngularJS 1.x reached end of life and receives no security fixes", "fix": "a supported framework"},
    ],
    "lodash": [
        {"end": "4.17.12", "cve": ["CVE-2019-10744"], "sev": "critical", "summary": "Prototype pollution in defaultsDeep", "fix": "4.17.21"},
        {"end": "4.17.19", "cve": ["CVE-2020-8203"], "sev": "high", "summary": "Prototype pollution in zipObjectDeep", "fix": "4.17.21"},
        {"end": "4.17.21", "cve": ["CVE-2021-23337"], "sev": "high", "summary": "Command injection through template", "fix": "4.17.21"},
    ],
    "moment": [
        {"end": "2.29.2", "cve": ["CVE-2022-24785"], "sev": "high", "summary": "Path traversal in locale loading", "fix": "2.29.4"},
        {"end": "2.29.4", "cve": ["CVE-2022-31129"], "sev": "high", "summary": "Regular expression denial of service in date parsing", "fix": "2.29.4"},
    ],
    "handlebars": [
        {"end": "4.3.0", "cve": ["CVE-2019-19919"], "sev": "critical", "summary": "Prototype pollution leading to remote code execution", "fix": "4.7.7"},
        {"end": "4.7.7", "cve": ["CVE-2021-23369"], "sev": "critical", "summary": "Remote code execution through crafted templates", "fix": "4.7.7"},
    ],
    "underscore": [
        {"start": "1.3.2", "end": "1.12.1", "cve": ["CVE-2021-23358"], "sev": "high", "summary": "Arbitrary code execution through the template function", "fix": "1.12.1"},
    ],
    "axios": [
        {"end": "0.21.1", "cve": ["CVE-2020-28168"], "sev": "medium", "summary": "Server-side request forgery through redirect handling", "fix": "1.6.0"},
        {"end": "1.6.0", "cve": ["CVE-2023-45857"], "sev": "medium", "summary": "Cross-site request forgery token leakage", "fix": "1.6.0"},
    ],
}


def detect_from_name(url):
    out = []
    for lib, name_re, _ in DETECTORS:
        match = name_re.search(url)
        if match:
            out.append((lib, match.group(1)))
    return out


def detect_from_content(text):
    head = text[:6000]
    out = []
    for lib, _, content_re in DETECTORS:
        match = content_re.search(head)
        if match:
            version = next((g for g in match.groups() if g), None)
            if version:
                out.append((lib, version))
    return out
