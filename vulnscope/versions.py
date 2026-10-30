import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_PRE = {"dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "preview": 3, "rc": 4, "cr": 4, "m": 3}
_ZERO = (1, 0, "")


def parse_version(value):
    text = str(value or "").strip().lower()
    if text.startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    key = []
    for tok in _TOKEN.findall(text):
        if tok.isdigit():
            key.append((1, int(tok), ""))
        elif tok in _PRE:
            key.append((-1, _PRE[tok], ""))
        else:
            key.append((2, 0, tok))
    return key


def compare_versions(a, b):
    ka, kb = parse_version(a), parse_version(b)
    size = max(len(ka), len(kb))
    ka = ka + [_ZERO] * (size - len(ka))
    kb = kb + [_ZERO] * (size - len(kb))
    if ka < kb:
        return -1
    if ka > kb:
        return 1
    return 0


def in_range(version, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
    if start_incl and compare_versions(version, start_incl) < 0:
        return False
    if start_excl and compare_versions(version, start_excl) <= 0:
        return False
    if end_incl and compare_versions(version, end_incl) > 0:
        return False
    if end_excl and compare_versions(version, end_excl) >= 0:
        return False
    return True


def extract_version(text):
    match = re.search(r"\d+(?:\.\d+){0,4}(?:[a-z]\d*|-?(?:rc|beta|alpha)\d*)?", str(text or ""), re.I)
    return match.group(0) if match else None
