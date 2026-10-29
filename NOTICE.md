# Third-party data sources and attribution

VulnScope does not bundle any third-party source code. At runtime, with
network access, it downloads and caches data from the following free public
services. Each is subject to its own terms of use.

- **National Vulnerability Database (NVD)** — U.S. NIST. https://nvd.nist.gov
  CVE records and CVSS scores. NVD is a product of NIST and does not endorse
  this project.
- **CVE Program** — MITRE / CVE.org. https://www.cve.org — CVE identifiers
  and summaries are sourced indirectly through the NVD API.
- **OSV.dev (Open Source Vulnerabilities)** — Google / Open Source Security
  Foundation. https://osv.dev — package ecosystem advisories.
- **CISA Known Exploited Vulnerabilities (KEV) Catalog** — U.S. CISA.
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

VulnScope's own code is released under the MIT License (see `LICENSE`).
