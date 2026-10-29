# Platform compatibility matrix

| Module | Windows | Linux | Termux (Android) |
|---|---|---|---|
| Web/API assessment (`web.*`) | Yes | Yes | Yes |
| TLS configuration (`web.tls`) | Yes | Yes | Yes |
| Network port scan (`net.ports`) | Yes | Yes | Yes (smaller ranges recommended) |
| DNS / email security (`net.dns`, `net.email`) | Yes (needs `dnspython`) | Yes | Yes |
| Source code & dependency scan (`source.*`) | Yes | Yes | Yes |
| Mobile APK/IPA static analysis (`mobile.*`) | Yes | Yes | Yes |
| Local OS package inventory (`os.packages`) | Not yet implemented | Yes (dpkg/rpm/pacman) | Yes (Termux `pkg`) |
| Local dashboard | Yes | Yes | Yes |

Run `vulnscope check` on your machine for the authoritative, live list of
which plugins are available given your installed dependencies.

## Known limitations
- `os.packages` currently supports Debian/Ubuntu (dpkg), Red Hat family
  (rpm), Arch (pacman) and Termux (`pkg`). Windows installed-software
  inventory is not implemented in this release.
- Dynamic (runtime) mobile app analysis is out of scope; only static
  analysis of the APK/IPA package is performed.
- Container image and Kubernetes cluster scanning rely on patterns in
  source/IaC files (`source.patterns`); there is no live Docker/Kubernetes
  API scanner in this release.
- CVE version matching uses NVD's published affected-version ranges, which
  do not always account for vendor back-ported fixes — matches are labeled
  `version_match` or `potential` accordingly, never asserted as confirmed
  exploitable.
