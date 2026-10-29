# VulnScope

VulnScope is a free, open-source, cross-platform vulnerability assessment
framework. It combines website and API scanning, network service discovery,
source-code and dependency analysis, and mobile app (APK/IPA) static
analysis behind one plugin-based engine, a CLI, and a local web dashboard —
with no AI integration, no paid services, and no mandatory cloud account.

It draws on the same category of checks as tools like Nmap, Burp Suite and
OWASP ZAP, backed by a local, offline-capable CVE database synchronized from
NVD, OSV.dev and the CISA Known Exploited Vulnerabilities catalog.

## Features

- **Web & API scanning** — security headers, cookies, CORS, TLS/certificate
  configuration, exposed files and admin interfaces, directory listing,
  verbose errors, vulnerable JavaScript libraries, CSRF/upload patterns,
  REST and GraphQL checks, and OWASP Top 10 / API Security Top 10 coverage.
- **Network scanning** — TCP port and service discovery, banner-based
  version matching, unauthenticated high-risk service detection, DNS zone
  transfer and CAA checks, SPF/DKIM/DMARC email security.
- **Source code & dependency analysis** — hardcoded secrets, unsafe code
  patterns (injection, insecure deserialization, weak crypto), container and
  infrastructure-as-code misconfiguration, and dependency vulnerability
  matching against OSV.dev across npm, PyPI, RubyGems, Packagist, Go and
  crates.io.
- **Mobile app analysis** — Android APK and iOS IPA static analysis:
  dangerous permissions, debuggable builds, cleartext traffic settings,
  network security config, and embedded secrets.
- **Local CVE intelligence** — a local, offline-capable SQLite database
  synchronized from NVD, OSV.dev and the CISA KEV catalog, with version-range
  matching, confidence labeling, and known-exploited-vulnerability flags.
- **Reporting** — HTML, JSON and CSV export, with severity, CVSS, evidence,
  confidence, and remediation for every finding.
- **CLI and dashboard** — a full command-line interface and a local-only web
  dashboard (new scan, live progress, findings, asset inventory, CVE search,
  scan history, plugin manager, diagnostics).
- Runs on **Windows, Linux, and Android (Termux)**, with a lightweight mode
  for low-memory devices.

## Quick start

```bash
git clone https://github.com/<your-username>/vulnscope.git
cd vulnscope
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e .

vulnscope check                    # show platform diagnostics and available plugins
vulnscope intel update             # download CVE/KEV data (optional, see below)
vulnscope scan https://example.com --profile standard -o report.html
vulnscope dashboard                # open http://127.0.0.1:8787
```

Full platform-specific setup: [Windows](docs/INSTALL_WINDOWS.md) ·
[Linux](docs/INSTALL_LINUX.md) · [Android/Termux](docs/INSTALL_TERMUX.md)

## Usage

```bash
# Website / API assessment
vulnscope scan https://example.com --profile comprehensive -o report.html

# Network / host assessment (you must be authorized for this target)
vulnscope scan 192.168.1.10 --allow-private -o report.html

# Local source code and dependencies
vulnscope scan ./my-project --target-type source -o report.html

# Android APK
vulnscope scan ./app-release.apk --target-type apk -o report.html

# Search the local CVE database
vulnscope intel search --product nginx --version 1.18.0
vulnscope intel search CVE-2021-44228

# List and inspect past scans
vulnscope history
vulnscope results <scan-id> --severity high
vulnscope export <scan-id> -o report.json --format json
```

Scan profiles: `passive` (no extra requests beyond the base page),
`standard` (default; adds safe active checks like CORS/TLS probing and path
enumeration), `comprehensive` (adds heavier checks like GraphQL batching and
light rate-limit probing). See `vulnscope plugins` for the full list and
which profile each one requires.

Every scan requires an explicit authorization acknowledgement — see
[docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md).

## How CVE matching works

VulnScope never claims a target is vulnerable just because software of a
given name is present. It extracts version evidence (HTTP headers, banners,
markup, manifests) and matches it against affected-version ranges from the
local database, labeling each result:

- `confirmed` — directly observed and verified (e.g. a response pattern
  specific to a known issue)
- `version_match` — the installed version falls in a known-affected range
- `potential` — a pattern suggests an issue but needs manual confirmation
- `informational` — observation only, not a vulnerability claim

Findings include severity, CVSS (only when sourced from NVD/OSV, never
invented), the rule basis, confidence level, evidence, and remediation.

## Keeping the vulnerability database current

```bash
vulnscope intel update              # incremental sync (recommended routine use)
vulnscope intel update --days 7     # just the last week
vulnscope intel update --full       # full historical sync (large, slow, one-time)
vulnscope intel status              # see record counts and last sync time
```

An optional free NVD API key raises the sync rate substantially — see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md). Without network access,
scans still run using whatever is already cached locally, and the dashboard
and CLI both show when the local data is stale.

## Documentation

- [Installation: Windows](docs/INSTALL_WINDOWS.md) ·
  [Linux](docs/INSTALL_LINUX.md) · [Termux](docs/INSTALL_TERMUX.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Writing a plugin](docs/PLUGIN_DEVELOPMENT.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Security and authorization policy](docs/SECURITY_POLICY.md)
- [Platform compatibility matrix](docs/COMPATIBILITY.md)
- [Known limitations](docs/COMPATIBILITY.md#known-limitations)

## Project layout

```
vulnscope/
  cli.py            command-line interface
  engine.py          scan scheduler (plugin selection, timeouts, cancellation)
  plugin.py           plugin base class and registry
  context.py           per-scan/per-plugin execution context
  scope.py              authorization scope and SSRF/private-network guards
  http.py                scope-enforcing HTTP client
  db.py                    scan/findings SQLite store
  intel/                   NVD / OSV.dev / CISA KEV sync and local CVE database
  plugins/                  all scanner plugins (web, net, source, mobile, local)
  rules/                      built-in vulnerable-library and secret-pattern rules
  report/                       HTML/JSON/CSV report export
  dashboard/                     local Flask dashboard (API + single-page UI)
tests/                            pytest suite, including a live scan test
docs/                              installation, configuration and policy docs
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

## License

MIT — see [LICENSE](LICENSE). Third-party data sources (NVD, OSV.dev, CISA
KEV) are attributed in [NOTICE.md](NOTICE.md); no third-party code is
bundled.
