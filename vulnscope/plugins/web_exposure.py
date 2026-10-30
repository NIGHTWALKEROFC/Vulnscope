import re
import uuid

from vulnscope.http import HttpError
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._web import CWE, body_hash, short


def _has(pattern, status=(200,), flags=re.I | re.M):
    rx = re.compile(pattern, flags)

    def check(resp):
        if resp.status not in status:
            return None
        match = rx.search(resp.text[:60000])
        return short(match.group(0), 90) if match else None
    return check


def _magic(prefix):
    def check(resp):
        if resp.status == 200 and resp.body.startswith(prefix) and resp.content_type != "text/html":
            return "file signature %r" % prefix[:8]
        return None
    return check


def _not_html(check):
    def wrapped(resp):
        return None if resp.is_html else check(resp)
    return wrapped


SECRET = ("Secrets management", "Credentials or configuration values are downloadable.", "Remove the file from the web root and rotate every secret it contained.")
SOURCE = ("Information disclosure", "Source code, history or repository metadata is downloadable.", "Block access to version-control and build artifacts and remove them from deployments.")
BACKUP = ("Information disclosure", "Backups often contain data, source code and credentials.", "Remove backup and dump files from the web root.")
DEBUG = ("Security misconfiguration", "Diagnostic interfaces expose internal state and may allow code execution.", "Disable diagnostic endpoints in production or restrict them to trusted networks.")
ADMIN = ("Exposed administrative interface", "Administrative login pages invite credential attacks.", "Restrict administrative interfaces by network or VPN and enforce multi-factor authentication.")
DOCS = ("Information disclosure", "API documentation reveals endpoints and parameters.", "Restrict documentation endpoints in production if the API is not public.")
LISTING = ("Directory listing", "Directory contents are browsable.", "Disable automatic directory indexes.")

ENTRIES = [
    ("/.git/HEAD", _has(r"^ref: refs/heads/"), "high", "Git repository exposed", SOURCE),
    ("/.git/config", _has(r"^\[core\]"), "high", "Git configuration exposed", SOURCE),
    ("/.svn/wc.db", _magic(b"SQLite format 3"), "high", "Subversion metadata exposed", SOURCE),
    ("/.hg/hgrc", _has(r"^\[paths\]"), "medium", "Mercurial metadata exposed", SOURCE),
    ("/.DS_Store", _magic(b"\x00\x00\x00\x01Bud1"), "low", "macOS .DS_Store file exposed", SOURCE),
    ("/.env", _not_html(_has(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+")), "high", "Environment file exposed", SECRET),
    ("/.env.local", _not_html(_has(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+")), "high", "Environment file exposed", SECRET),
    ("/.env.production", _not_html(_has(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+")), "high", "Environment file exposed", SECRET),
    ("/.aws/credentials", _has(r"aws_access_key_id\s*="), "critical", "AWS credentials file exposed", SECRET),
    ("/.npmrc", _has(r"_authToken\s*="), "high", "npm credentials file exposed", SECRET),
    ("/.git-credentials", _has(r"https?://[^/\s:@]+:[^/\s@]+@"), "critical", "Git credentials file exposed", SECRET),
    ("/.docker/config.json", _has(r"\"auths\""), "high", "Docker credentials file exposed", SECRET),
    ("/id_rsa", _has(r"BEGIN [A-Z ]*PRIVATE KEY"), "critical", "SSH private key exposed", SECRET),
    ("/.ssh/id_rsa", _has(r"BEGIN [A-Z ]*PRIVATE KEY"), "critical", "SSH private key exposed", SECRET),
    ("/.htpasswd", _has(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13})"), "high", "Password file .htpasswd exposed", SECRET),
    ("/.htaccess", _has(r"(RewriteEngine|AuthType|Require |Options )"), "low", ".htaccess file exposed", SECRET),
    ("/web.config", _has(r"<configuration"), "medium", "web.config exposed", SECRET),
    ("/WEB-INF/web.xml", _has(r"<web-app"), "medium", "WEB-INF/web.xml exposed", SECRET),
    ("/sftp-config.json", _has(r"\"(host|user|password)\""), "high", "SFTP configuration exposed", SECRET),
    ("/wp-config.php.bak", _has(r"DB_(PASSWORD|NAME)"), "critical", "WordPress configuration backup exposed", SECRET),
    ("/wp-config.php~", _has(r"DB_(PASSWORD|NAME)"), "critical", "WordPress configuration backup exposed", SECRET),
    ("/wp-config.php.old", _has(r"DB_(PASSWORD|NAME)"), "critical", "WordPress configuration backup exposed", SECRET),
    ("/config.php.bak", _has(r"(password|passwd|db_)", flags=re.I), "high", "Configuration backup exposed", SECRET),
    ("/index.php.bak", _has(r"<\?php"), "high", "Application source backup exposed", SOURCE),
    ("/index.php~", _has(r"<\?php"), "high", "Application source backup exposed", SOURCE),
    ("/index.php.old", _has(r"<\?php"), "high", "Application source backup exposed", SOURCE),
    ("/backup.sql", _has(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), "critical", "Database dump exposed", BACKUP),
    ("/dump.sql", _has(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), "critical", "Database dump exposed", BACKUP),
    ("/db.sql", _has(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), "critical", "Database dump exposed", BACKUP),
    ("/database.sql", _has(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), "critical", "Database dump exposed", BACKUP),
    ("/backup.zip", _magic(b"PK\x03\x04"), "high", "Backup archive exposed", BACKUP),
    ("/site.zip", _magic(b"PK\x03\x04"), "high", "Backup archive exposed", BACKUP),
    ("/www.zip", _magic(b"PK\x03\x04"), "high", "Backup archive exposed", BACKUP),
    ("/backup.tar.gz", _magic(b"\x1f\x8b"), "high", "Backup archive exposed", BACKUP),
    ("/phpinfo.php", _has(r"phpinfo\(\)|PHP Version \d"), "medium", "phpinfo page exposed", DEBUG),
    ("/info.php", _has(r"phpinfo\(\)|PHP Version \d"), "medium", "phpinfo page exposed", DEBUG),
    ("/server-status", _has(r"Apache Server Status"), "medium", "Apache server-status exposed", DEBUG),
    ("/server-info", _has(r"Apache Server Information"), "medium", "Apache server-info exposed", DEBUG),
    ("/actuator/env", _has(r"\"propertySources\""), "high", "Spring Boot actuator env exposed", DEBUG),
    ("/env", _has(r"\"propertySources\""), "high", "Spring Boot env endpoint exposed", DEBUG),
    ("/actuator/heapdump", lambda r: "heap dump downloadable" if r.status == 200 and (r.body.startswith(b"JAVA PROFILE") or "octet-stream" in r.content_type) else None, "critical", "Spring Boot heap dump exposed", DEBUG),
    ("/actuator/mappings", _has(r"\"dispatcherServlets\""), "medium", "Spring Boot mappings exposed", DEBUG),
    ("/actuator", _has(r"\"_links\""), "low", "Spring Boot actuator index exposed", DEBUG),
    ("/jolokia/version", _has(r"\"agent\""), "high", "Jolokia JMX endpoint exposed", DEBUG),
    ("/console", _has(r"(Werkzeug|Interactive Console|Console Locked)"), "high", "Werkzeug debugger console reachable", DEBUG),
    ("/_profiler/", _has(r"Symfony Profiler"), "medium", "Symfony profiler exposed", DEBUG),
    ("/telescope", _has(r"Laravel Telescope"), "medium", "Laravel Telescope exposed", DEBUG),
    ("/__debug__/", _has(r"djdt|Django Debug"), "medium", "Django debug toolbar exposed", DEBUG),
    ("/elmah.axd", _has(r"Error Log for"), "high", "ELMAH error log exposed", DEBUG),
    ("/trace.axd", _has(r"Application Trace"), "high", "ASP.NET trace exposed", DEBUG),
    ("/_cat/indices", _has(r"(green|yellow|red)\s+open"), "high", "Elasticsearch accessible without authentication", DEBUG),
    ("/_cluster/health", _has(r"\"cluster_name\""), "high", "Elasticsearch accessible without authentication", DEBUG),
    ("/v2/_catalog", _has(r"\"repositories\""), "high", "Docker registry catalog exposed", DEBUG),
    ("/api/v1/pods", _has(r"\"kind\"\s*:\s*\"PodList\""), "critical", "Kubernetes API accessible without authentication", DEBUG),
    ("/storage/logs/laravel.log", _has(r"(local\.ERROR|Stack trace:|^\[\d{4}-\d\d-\d\d)"), "high", "Application log exposed", DEBUG),
    ("/error_log", _has(r"(PHP (Warning|Fatal)|\[error\]|Stack trace)"), "medium", "Error log exposed", DEBUG),
    ("/debug.log", _has(r"(DEBUG|ERROR|Exception)"), "medium", "Debug log exposed", DEBUG),
    ("/.bash_history", _not_html(_has(r"^(cd|ls|sudo|ssh|mysql|git|cat) ")), "high", "Shell history exposed", SECRET),
    ("/composer.json", _has(r"\"require\""), "low", "Dependency manifest exposed", SOURCE),
    ("/composer.lock", _has(r"\"packages\""), "low", "Dependency lock file exposed", SOURCE),
    ("/package.json", _has(r"\"(dependencies|devDependencies|scripts)\""), "low", "Dependency manifest exposed", SOURCE),
    ("/requirements.txt", _not_html(_has(r"^[A-Za-z0-9_.-]+==\d")), "low", "Dependency manifest exposed", SOURCE),
    ("/Dockerfile", _not_html(_has(r"^FROM\s+\S+")), "low", "Dockerfile exposed", SOURCE),
    ("/docker-compose.yml", _not_html(_has(r"^services:")), "medium", "Docker Compose file exposed", SOURCE),
    ("/.gitlab-ci.yml", _not_html(_has(r"(stages:|script:)")), "low", "CI configuration exposed", SOURCE),
    ("/Jenkinsfile", _not_html(_has(r"pipeline\s*\{")), "low", "Jenkinsfile exposed", SOURCE),
    ("/crossdomain.xml", _has(r"allow-access-from[^>]+domain=\"\*\""), "medium", "Permissive crossdomain.xml", ("Insecure CORS policy", "Flash and legacy clients may read data cross-origin.", "Restrict allowed domains or remove the file.")),
    ("/clientaccesspolicy.xml", _has(r"domain uri=\"\*\""), "medium", "Permissive clientaccesspolicy.xml", ("Insecure CORS policy", "Legacy clients may read data cross-origin.", "Restrict allowed domains or remove the file.")),
    ("/swagger.json", _has(r"\"(swagger|openapi)\"\s*:"), "info", "API specification exposed", DOCS),
    ("/openapi.json", _has(r"\"(swagger|openapi)\"\s*:"), "info", "API specification exposed", DOCS),
    ("/v2/api-docs", _has(r"\"(swagger|openapi)\"\s*:"), "info", "API specification exposed", DOCS),
    ("/v3/api-docs", _has(r"\"(swagger|openapi)\"\s*:"), "info", "API specification exposed", DOCS),
    ("/swagger-ui.html", _has(r"swagger-ui|SwaggerUIBundle"), "info", "Swagger UI exposed", DOCS),
    ("/docs", _has(r"swagger-ui|SwaggerUIBundle|redoc"), "info", "API documentation UI exposed", DOCS),
    ("/phpmyadmin/", _has(r"phpMyAdmin"), "medium", "phpMyAdmin exposed", ADMIN),
    ("/pma/", _has(r"phpMyAdmin"), "medium", "phpMyAdmin exposed", ADMIN),
    ("/adminer.php", _has(r"Adminer"), "medium", "Adminer database tool exposed", ADMIN),
    ("/wp-login.php", _has(r"(user_login|wp-submit)"), "low", "WordPress login page exposed", ADMIN),
    ("/administrator/", _has(r"Joomla|com_login"), "low", "Joomla administrator login exposed", ADMIN),
    ("/user/login", _has(r"Drupal|drupal"), "low", "Drupal login page exposed", ADMIN),
    ("/manager/html", _has(r"Tomcat", status=(200, 401, 403)), "medium", "Tomcat manager exposed", ADMIN),
    ("/solr/", _has(r"Solr Admin"), "medium", "Solr admin interface exposed", ADMIN),
    ("/jenkins/", _has(r"Jenkins"), "medium", "Jenkins exposed", ADMIN),
    ("/grafana/login", _has(r"Grafana"), "low", "Grafana login exposed", ADMIN),
]

LISTING_PATHS = [("/", "low"), ("/uploads/", "medium"), ("/backup/", "high"), ("/backups/", "high"), ("/files/", "medium"),
                 ("/logs/", "high"), ("/tmp/", "medium"), ("/images/", "low"), ("/static/", "low"), ("/assets/", "low"), ("/admin/", "medium")]
_LISTING_RX = re.compile(r"(<title>Index of /|<h1>Index of|Directory listing for|<title>Directory listing|Parent Directory</a>)", re.I)

ERROR_SIGNS = [
    ("Python traceback", r"Traceback \(most recent call last\)"),
    ("Django debug page", r"DEBUG = True|You're seeing this error because"),
    ("Werkzeug debugger", r"Werkzeug Debugger|The debugger caught an exception"),
    ("Laravel debug page", r"Whoops! There was an error|facade/ignition"),
    ("Symfony exception page", r"Symfony Exception|symfony/http-kernel"),
    ("PHP error output", r"(Warning|Fatal error|Notice|Parse error):\s.{0,200}\sin\s+(<b>)?/[\w/.-]+(</b>)?\s+on line"),
    ("Java stack trace", r"at (?:[\w$]+\.){2,}[\w$<>]+\([\w]+\.java:\d+\)"),
    ("ASP.NET detailed error", r"Server Error in '/[^']*' Application|<b>Stack Trace:</b>"),
    ("Node.js stack trace", r"at (?:Object|Module|Function)\.<anonymous> \(|node_modules/"),
    ("Rails exception page", r"ActionController::RoutingError|Rails\.root:"),
    ("SQL error text", r"SQLSTATE\[|mysqli_sql_exception|ORA-\d{5}|PG::\w+Error"),
]


@register
class ExposedFiles(Plugin):
    id = "web.exposure"
    name = "Exposed files, interfaces and verbose errors"
    description = "Requests well-known sensitive paths and validates the content, detects directory listing and verbose error output."
    categories = ("Information disclosure", "Exposed administrative interface", "Directory listing", "Security misconfiguration")
    active = True
    timeout = 300
    min_profile = "standard"

    def run(self, ctx):
        root = ctx.target.value.split("?")[0]
        base_url = re.match(r"https?://[^/]+", root).group(0)
        try:
            ghost = ctx.http.get(base_url + "/vulnscope-%s.html" % uuid.uuid4().hex[:10], follow=False)
        except HttpError:
            return
        soft = body_hash(ghost.text) if ghost.status == 200 else None
        for label, pattern in ERROR_SIGNS:
            if re.search(pattern, ghost.text[:60000]):
                yield self._error(ctx, label, ghost.url)
                break
        base = ctx.base()
        for label, pattern in ERROR_SIGNS:
            if re.search(pattern, base.text[:60000]):
                yield self._error(ctx, label, base.url)
                break
        for path, sev in LISTING_PATHS:
            ctx.check()
            try:
                resp = ctx.http.get(base_url + path, follow=False)
            except HttpError:
                continue
            if resp.status == 200 and _LISTING_RX.search(resp.text[:20000]):
                yield ctx.finding(
                    "Directory listing enabled at %s" % path, sev, "confirmed", "Directory listing",
                    target=base_url + path, rule_id="web.exposure.listing", rule_basis="Response matches a server directory index template",
                    confidence="high", evidence=short(resp.text[:200]), impact=LISTING[1], remediation=LISTING[2],
                    references=[CWE % "548"], location=path,
                )
        for path, check, sev, title, (category, impact, fix) in ENTRIES:
            ctx.check()
            try:
                resp = ctx.http.get(base_url + path, follow=False)
            except HttpError:
                continue
            if resp.status in (301, 302, 303, 307, 308) or resp.status >= 500 or resp.status == 404:
                continue
            if soft and resp.status == 200 and body_hash(resp.text) == soft:
                continue
            proof = check(resp)
            if not proof:
                continue
            ctx.asset("exposed-path", path, {"status": resp.status, "severity": sev})
            yield ctx.finding(
                "%s: %s" % (title, path), sev, "confirmed", category, target=base_url + path,
                rule_id="web.exposure" + path, rule_basis="HTTP %d with content matching the expected file signature" % resp.status,
                confidence="high", evidence="GET %s -> %d; matched: %s" % (path, resp.status, proof), impact=impact,
                remediation=fix, references=[CWE % "538", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                location=path,
            )
        try:
            robots = ctx.http.get(base_url + "/robots.txt", follow=False)
        except HttpError:
            robots = None
        if robots is not None and robots.status == 200 and "disallow" in robots.text.lower() and not robots.is_html:
            hits = re.findall(r"(?im)^disallow:\s*(\S*(?:admin|backup|private|secret|internal|config|db|sql|\.git|upload)\S*)", robots.text)
            if hits:
                yield ctx.finding(
                    "robots.txt references sensitive paths", "info", "informational", "Information disclosure",
                    target=base_url + "/robots.txt", rule_id="web.exposure.robots", rule_basis="Disallow entries with sensitive keywords",
                    confidence="medium", evidence="Disallowed: %s" % ", ".join(hits[:8]),
                    impact="Listed paths advertise where sensitive content may live.",
                    remediation="Protect sensitive paths with authentication instead of relying on robots.txt.", references=[CWE % "200"],
                )

    @staticmethod
    def _error(ctx, label, url):
        return ctx.finding(
            "Verbose error output: %s" % label, "medium" if label in ("Django debug page", "Werkzeug debugger", "Laravel debug page") else "low",
            "confirmed", "Security misconfiguration", target=url, rule_id="web.exposure.error." + label.lower().replace(" ", "-"),
            rule_basis="Response body matches a framework error or debug template", confidence="high",
            evidence="Pattern for %s found in response from %s" % (label, url),
            impact="Stack traces and debug pages disclose internal paths, queries and configuration.",
            remediation="Disable debug mode and return generic error pages in production.", references=[CWE % "209"],
        )
