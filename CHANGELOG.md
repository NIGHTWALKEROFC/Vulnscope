# Changelog

## 0.1.0 — Initial release

First public release of VulnScope.

- Core engine: plugin registry, scan scheduler with per-plugin timeouts and
  cancellation, authorized-scope enforcement, SQLite scan/findings store.
- Vulnerability intelligence: NVD, OSV.dev and CISA KEV synchronization into
  a local SQLite database, with version-range CVE matching and a built-in
  CVSS v3.1 calculator for sources that only provide a vector string.
- Web & API plugins: security headers, cookies, CORS, HTTP methods, HTML
  form/CSRF/upload analysis, exposed files and admin interfaces, directory
  listing, verbose error detection, vulnerable JavaScript library detection,
  technology fingerprinting with CVE matching, TLS/certificate checks
  (real handshakes, no simulated results), REST/GraphQL API checks.
- Network plugins: TCP port and service scan with banner grabbing and
  unauthenticated-service probing, DNS zone-transfer and CAA checks,
  SPF/DKIM/DMARC email security checks.
- Source code plugins: secret/credential pattern scanning, dependency
  vulnerability matching via OSV.dev (npm, PyPI, RubyGems, Packagist, Go,
  crates.io), static code pattern analysis (injection, insecure
  deserialization, weak crypto) and container/IaC misconfiguration checks.
- Mobile plugins: Android APK and iOS IPA static analysis (permissions,
  debuggable builds, cleartext traffic, network security config, embedded
  secrets), with zip-slip-safe extraction.
- Local host plugin: installed OS package inventory (Debian/Ubuntu, Red Hat,
  Arch, Termux) with CVE matching.
- Reporting: HTML, JSON and CSV export.
- Interfaces: full CLI (`scan`, `results`, `history`, `export`, `delete`,
  `intel update/search/status`, `plugins`, `check`, `dashboard`) and a local
  Flask-based dashboard with a single-page UI covering overview, new scan
  with live progress, scan history, CVE search, plugin status and platform
  diagnostics.
- Safety: scope-enforcing HTTP/socket layer blocking private, loopback and
  cloud-metadata destinations by default; secret redaction in logs and
  reports; explicit authorization acknowledgement required before scanning.
- Tests: pytest suite covering version comparison, CVSS scoring, scope
  enforcement, the finding/report models, secret and library detection
  rules, the plugin registry, report export, the dashboard API, source-code
  plugins, and a full end-to-end scan against a live local HTTP fixture.
