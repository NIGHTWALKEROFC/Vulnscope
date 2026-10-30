import os
import re

from vulnscope.plugin import Plugin, register
from vulnscope.plugins._source import read_text, walk_files

CWE = "https://cwe.mitre.org/data/definitions/%s.html"

_PATTERNS = [
    ("sql-concat", "medium", "SQL query built by string concatenation", "Injection-prone code",
     re.compile(r"(?i)(execute|cursor\.execute|query|createQuery|raw)\s*\(\s*(?:f?[\"'].*(SELECT|INSERT|UPDATE|DELETE).*[\"']\s*\+|[\"'].*%s.*[\"']\s*%)"),
     "Use parameterized queries or an ORM instead of concatenating SQL.", "89"),
    ("sql-fstring", "medium", "SQL query built with an f-string or template literal", "Injection-prone code",
     re.compile(r"(?i)(execute|cursor\.execute|query)\s*\(\s*f[\"'].*(SELECT|INSERT|UPDATE|DELETE).*\{"),
     "Use parameterized queries instead of interpolating values into SQL text.", "89"),
    ("shell-true", "high", "Subprocess invoked with shell=True", "Command injection",
     re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
     "Avoid shell=True, or pass a list of arguments and validate/escape any user input.", "78"),
    ("os-system", "medium", "os.system call with string formatting", "Command injection",
     re.compile(r"os\.system\s*\(\s*(f[\"']|[\"'][^\"']*%s|[\"'][^\"']*\+)"),
     "Use subprocess with an argument list instead of os.system with concatenated input.", "78"),
    ("exec-eval", "high", "Dynamic code execution (eval/exec)", "Injection-prone code",
     re.compile(r"\b(eval|exec)\s*\(\s*(?!['\"])"),
     "Avoid eval/exec on data that is not fully trusted and constant.", "95"),
    ("php-eval", "high", "PHP eval() on dynamic input", "Injection-prone code",
     re.compile(r"\beval\s*\(\s*\$"),
     "Avoid eval(); use safe parsing or dedicated functions instead.", "95"),
    ("yaml-unsafe", "high", "Unsafe YAML load", "Insecure deserialization",
     re.compile(r"yaml\.(load)\s*\((?!.*Loader=yaml\.SafeLoader)"),
     "Use yaml.safe_load or pass Loader=yaml.SafeLoader.", "502"),
    ("pickle-load", "high", "Pickle deserialization of external data", "Insecure deserialization",
     re.compile(r"pickle\.(loads?|Unpickler)\s*\("),
     "Avoid unpickling data from untrusted sources; use JSON or a safe serializer.", "502"),
    ("php-unserialize", "high", "PHP unserialize() on external input", "Insecure deserialization",
     re.compile(r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
     "Use json_decode instead of unserialize for untrusted input.", "502"),
    ("md5-password", "medium", "MD5 used for password hashing", "Insecure cryptographic configuration",
     re.compile(r"(?i)(password|passwd|pwd).{0,30}\bmd5\s*\("),
     "Use bcrypt, scrypt or Argon2 for password hashing.", "327"),
    ("sha1-password", "medium", "SHA1 used for password hashing", "Insecure cryptographic configuration",
     re.compile(r"(?i)(password|passwd|pwd).{0,30}\bsha1\s*\("),
     "Use bcrypt, scrypt or Argon2 for password hashing.", "327"),
    ("des-cipher", "medium", "DES or weak block cipher referenced", "Insecure cryptographic configuration",
     re.compile(r"(?i)\b(DES|RC4|ECB)\b.{0,20}(cipher|encrypt)"),
     "Use AES-GCM or ChaCha20-Poly1305 instead of DES, RC4 or ECB mode.", "327"),
    ("insecure-random", "low", "Non-cryptographic random used for a security purpose", "Insecure cryptographic configuration",
     re.compile(r"(?i)(token|password|secret|otp|session).{0,25}\b(Math\.random\(\)|random\.random\(\)|rand\(\))"),
     "Use a cryptographically secure random generator (secrets, crypto.randomBytes, random_bytes).", "330"),
    ("path-traversal", "medium", "File path built from unsanitized input", "Path traversal",
     re.compile(r"(?i)open\s*\(\s*(?:os\.path\.join\([^)]*request|.*request\.(args|params|GET|POST))"),
     "Validate and normalize file paths; reject '..' segments and use an allow-list of directories.", "22"),
    ("debug-true", "medium", "Debug mode enabled in source", "Debug mode and verbose error exposure",
     re.compile(r"(?i)\bDEBUG\s*=\s*True\b|app\.config\[.DEBUG.\]\s*=\s*True"),
     "Disable debug mode in production configuration.", "489"),
    ("cors-wildcard", "low", "Wildcard CORS configured in source", "Insecure CORS policy",
     re.compile(r"(?i)Access-Control-Allow-Origin.{0,10}[\"']\*[\"']"),
     "Restrict CORS to specific trusted origins.", "942"),
    ("disabled-tls-verify", "high", "TLS certificate verification disabled", "Insecure cryptographic configuration",
     re.compile(r"(?i)(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*.0.|rejectUnauthorized:\s*false|CURLOPT_SSL_VERIFYPEER,\s*false)"),
     "Keep certificate verification enabled; pin certificates if needed instead.", "295"),
    ("hardcoded-iv", "low", "Static initialization vector for encryption", "Insecure cryptographic configuration",
     re.compile(r"(?i)\biv\s*=\s*[\"'][0-9a-fA-F]{16,}[\"']"),
     "Generate a random IV for every encryption operation.", "329"),
    ("weak-jwt-alg", "high", "JWT configured to accept the 'none' algorithm", "Authentication",
     re.compile(r"(?i)algorithms?\s*=\s*\[?[\"']none[\"']"),
     "Reject tokens signed with 'none' and require a specific strong algorithm.", "347"),
    ("xxe-enabled", "high", "XML parser configured without disabling external entities", "XML external entity",
     re.compile(r"(?i)(XMLInputFactory|DocumentBuilderFactory|SAXParserFactory).{0,200}(?!DISALLOW_DOCTYPE_DECL)"),
     "Disable DTDs and external entity resolution in the XML parser configuration.", "611"),
]

_IAC_PATTERNS = [
    ("docker-root", "medium", "Container runs as root (no USER instruction)", "Container configuration",
     None, "Add a non-root USER instruction to the Dockerfile.", "250"),
    ("docker-latest", "low", "Base image uses the 'latest' tag", "Container configuration",
     re.compile(r"(?im)^FROM\s+\S+:latest\b"), "Pin base images to a specific digest or version tag.", "1104"),
    ("docker-secret-build-arg", "high", "Secret passed as a Docker build ARG", "Secrets management",
     re.compile(r"(?i)ARG\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*"), "Use Docker BuildKit secrets instead of build ARGs for credentials.", "798"),
    ("tf-public-sg", "high", "Terraform security group open to the internet", "Cloud configuration assessment",
     re.compile(r"(?i)cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']"), "Restrict ingress CIDR ranges to known networks.", "284"),
    ("tf-public-bucket", "high", "Terraform storage bucket may be publicly readable", "Cloud configuration assessment",
     re.compile(r"(?i)(acl\s*=\s*[\"']public-read|block_public_acls\s*=\s*false)"), "Block public access on storage buckets unless intentionally public.", "284"),
    ("k8s-privileged", "high", "Kubernetes container runs in privileged mode", "Container configuration",
     re.compile(r"(?i)privileged:\s*true"), "Remove privileged: true unless strictly required.", "250"),
    ("k8s-host-network", "medium", "Kubernetes pod uses the host network namespace", "Container configuration",
     re.compile(r"(?i)hostNetwork:\s*true"), "Avoid hostNetwork unless required; it bypasses network policy isolation.", "668"),
]


@register
class SourcePatterns(Plugin):
    id = "source.patterns"
    name = "Static code and IaC pattern analysis"
    description = "Scans source files for unsafe code patterns and container or infrastructure-as-code misconfiguration."
    target_types = ("source",)
    categories = ("Injection-prone code", "Insecure deserialization", "Insecure cryptographic configuration",
                 "Container and orchestration security", "Infrastructure as code")
    timeout = 300

    def run(self, ctx):
        root = ctx.target.value
        limit_kb = ctx.config.data["limits"]["max_scan_file_kb"]
        per_rule_cap = 40
        counters = {}
        for path, lower_name in walk_files(root, 6000, limit_kb):
            ctx.check()
            text = read_text(path, limit_kb)
            if not text:
                continue
            rel = os.path.relpath(path, root)
            for rule_id, sev, title, category, regex, fix, cwe in _PATTERNS:
                if counters.get(rule_id, 0) >= per_rule_cap:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if regex.search(line):
                        counters[rule_id] = counters.get(rule_id, 0) + 1
                        yield ctx.finding(
                            title, sev, "potential", category, target=root, rule_id="source.pattern." + rule_id,
                            confidence="low", rule_basis="Regular-expression pattern match; manual review recommended",
                            evidence="%s:%d: %s" % (rel, lineno, line.strip()[:200]), remediation=fix,
                            references=[CWE % cwe], location="%s:%d" % (rel, lineno),
                        )
                        if counters[rule_id] >= per_rule_cap:
                            break
            if lower_name == "dockerfile" or lower_name.endswith(".dockerfile"):
                has_user = bool(re.search(r"(?im)^USER\s+(?!root\b)", text))
                if not has_user:
                    yield ctx.finding(
                        "Container runs as root (no USER instruction)", "medium", "potential", "Container configuration",
                        target=root, rule_id="source.pattern.docker-root", confidence="low",
                        evidence="%s has no USER instruction switching away from root." % rel,
                        remediation="Add a non-root USER instruction to the Dockerfile.", references=[CWE % "250"], location=rel,
                    )
                for rule_id, sev, title, category, regex, fix, cwe in _IAC_PATTERNS:
                    if regex and regex.search(text):
                        yield ctx.finding(
                            title, sev, "potential", category, target=root, rule_id="source.pattern." + rule_id,
                            confidence="low", evidence="Pattern found in %s." % rel, remediation=fix,
                            references=[CWE % cwe], location=rel,
                        )
            elif lower_name.endswith((".tf", ".yml", ".yaml")):
                for rule_id, sev, title, category, regex, fix, cwe in _IAC_PATTERNS:
                    if regex and rule_id.startswith(("tf-", "k8s-")) and regex.search(text):
                        yield ctx.finding(
                            title, sev, "potential", category, target=root, rule_id="source.pattern." + rule_id,
                            confidence="low", evidence="Pattern found in %s." % rel, remediation=fix,
                            references=[CWE % cwe], location=rel,
                        )
