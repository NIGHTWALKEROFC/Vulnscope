import re

_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic|token)?\s*[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)[^\r\n]+"),
    re.compile(r"(?i)((?:api[_-]?key|secret|token|passwd|password|pwd)\s*[:=]\s*[\"']?)[^\s\"'&]{6,}"),
    re.compile(r"(?i)(://[^/\s:@]+:)[^/\s@]+(@)"),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
]


def mask(value):
    value = str(value)
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-2:]


def redact_text(text):
    out = str(text)
    out = _PATTERNS[0].sub(lambda m: m.group(1) + "[redacted]", out)
    out = _PATTERNS[1].sub(lambda m: m.group(1) + "[redacted]", out)
    out = _PATTERNS[2].sub(lambda m: m.group(1) + "[redacted]", out)
    out = _PATTERNS[3].sub(lambda m: m.group(1) + "[redacted]" + m.group(2), out)
    for pat in _PATTERNS[4:]:
        out = pat.sub("[redacted]", out)
    return out
