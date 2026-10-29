# Installing VulnScope on Linux

## Requirements
- Python 3.9 or newer (most distributions ship this by default)
- `pip` and `venv` (Debian/Ubuntu: `sudo apt install python3-venv python3-pip`)

## Steps
```bash
git clone https://github.com/<your-username>/vulnscope.git
cd vulnscope
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
vulnscope check
```

## Optional external tools
These are not required — VulnScope's built-in scanners cover the core
checks — but if present, `vulnscope check` will report them as available for
future extension:
- **Nmap**: `sudo apt install nmap` (Debian/Ubuntu) or your distribution's
  package manager.
- **Semgrep** (static analysis): `pip install semgrep`
- **Trivy** (container/dependency scanning): see
  https://aquasecurity.github.io/trivy/latest/getting-started/installation/
- **OSV-Scanner**: see https://google.github.io/osv-scanner/installation/

None of these cost money; VulnScope works fully without any of them, using
its own built-in plugins and the free OSV.dev API for dependency scanning.

## Updating the vulnerability database
```bash
vulnscope intel update
```

## Running a scan
```bash
vulnscope scan https://example.com --profile standard -o report.html
```

## Running the dashboard
```bash
vulnscope dashboard
```
Then open http://127.0.0.1:8787 in your browser.

## Running as a systemd service (optional)
Create `/etc/systemd/system/vulnscope-dashboard.service`:
```ini
[Unit]
Description=VulnScope dashboard
After=network.target

[Service]
ExecStart=/path/to/vulnscope/.venv/bin/vulnscope dashboard --host 127.0.0.1 --port 8787
Restart=on-failure
User=youruser

[Install]
WantedBy=multi-user.target
```
Then `sudo systemctl enable --now vulnscope-dashboard`.
