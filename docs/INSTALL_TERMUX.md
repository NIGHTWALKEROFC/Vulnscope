# Installing VulnScope on Android (Termux)

VulnScope's "lite" mode is designed for phones with limited memory and
storage, and does not require root access.

## Requirements
- [Termux](https://termux.dev) installed from F-Droid or GitHub Releases
  (the Play Store build is outdated and not recommended).

## Steps
```bash
pkg update && pkg upgrade
pkg install python git
pip install --upgrade pip
git clone https://github.com/<your-username>/vulnscope.git
cd vulnscope
pip install -e .
vulnscope check
```

If a package fails to build (common for `cryptography` on some devices),
install the prebuilt Termux package first and retry:
```bash
pkg install python-cryptography
pip install -e . --no-deps
pip install requests dnspython Flask
```

## Running a lightweight scan
```bash
vulnscope scan https://example.com --profile standard --lite -o report.html
```
`--lite` reduces concurrency, page limits and request rate so the scan stays
usable on 3-4 GB of RAM.

## Storage note
The local CVE database can grow to several hundred megabytes. On a phone,
either skip `vulnscope intel update --full` (use the default incremental
sync, which only pulls recent years) or run `vulnscope intel update
--since-year 2020` to keep it smaller. You can check free space and database
size with `vulnscope check` and `vulnscope intel status`.

## Dashboard on Termux
```bash
vulnscope dashboard --host 127.0.0.1 --port 8787
```
Then open http://127.0.0.1:8787 in the phone's browser.

## Known Termux limitations
- Full TCP port scanning works, but scanning very large networks is slow on
  mobile CPUs; keep `--scope` targets small.
- Mobile app (APK/IPA) static analysis works since it is pure Python, but
  analyzing very large APKs on low-RAM devices may be slow.
- Nmap/Semgrep/Trivy are not available in Termux; the equivalent built-in
  VulnScope plugins are used automatically instead.
