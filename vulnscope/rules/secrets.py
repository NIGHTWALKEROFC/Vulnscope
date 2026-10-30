import math
import re

from vulnscope.redact import mask

RULES = [
    ("aws-access-key", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "high", False),
    ("aws-secret-key", "AWS secret access key", re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"), "critical", False),
    ("github-token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), "high", False),
    ("gitlab-token", "GitLab personal access token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"), "high", False),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high", False),
    ("stripe-live-key", "Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "critical", False),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium", False),
    ("private-key", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critical", False),
    ("sendgrid-key", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "high", False),
    ("twilio-key", "Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high", False),
    ("npm-token", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high", False),
    ("pypi-token", "PyPI upload token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"), "high", False),
    ("telegram-bot-token", "Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), "high", False),
    ("discord-bot-token", "Discord bot token", re.compile(r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"), "high", False),
    ("supabase-service-key", "Supabase service role JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*c2VydmljZV9yb2xl[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{20,}\b"), "critical", False),
    ("jwt", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium", False),
    ("db-url", "Database URL with credentials", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^/\s@]{3,}@[^\s\"']+"), "high", False),
    ("basic-auth-url", "Credentials embedded in URL", re.compile(r"\bhttps?://[^/\s:@\"']{2,}:[^/\s:@\"']{3,}@[A-Za-z0-9.-]+"), "medium", False),
    ("generic-secret", "Hardcoded credential assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"), "medium", True),
]

_PLACEHOLDER = re.compile(r"(?i)(example|changeme|change_me|your[_-]|xxxx|<.*>|\$\{|\{\{|dummy|sample|placeholder|test|todo|password|secret|null|none|undefined|process\.env|getenv|\*{4,})")


def entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / len(text)) * math.log2(c / len(text)) for c in counts.values())


def scan_text(text, max_hits=50):
    hits = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for rule_id, label, regex, severity, needs_entropy in RULES:
            for match in regex.finditer(line):
                secret = match.group(1) if match.groups() and match.group(1) else match.group(0)
                if needs_entropy and (_PLACEHOLDER.search(secret) or entropy(secret) < 3.0):
                    continue
                if rule_id == "jwt" and any(h["rule_id"] == "supabase-service-key" and h["line"] == line_no for h in hits):
                    continue
                hits.append({"rule_id": rule_id, "label": label, "severity": severity, "line": line_no, "masked": mask(secret)})
                if len(hits) >= max_hits:
                    return hits
    return hits
