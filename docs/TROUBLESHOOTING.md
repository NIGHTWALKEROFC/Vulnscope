# Troubleshooting

**`vulnscope: command not found` after installing**
The virtual environment is probably not activated. Re-run
`source .venv/bin/activate` (Linux/Termux) or `.venv\Scripts\Activate.ps1`
(Windows), or reinstall with `pip install -e .` inside the active venv.

**A scan says "host is outside the authorized scope"**
VulnScope refuses to touch hosts you have not confirmed authorization for.
Add the host with `--scope example.com` (repeatable), or make sure the
target itself matches what you typed.

**A scan says "destination ... blocked (private)" / "(loopback)"**
Private, loopback and cloud-metadata addresses are blocked by default to
prevent SSRF-style misuse. If you really intend to scan an internal address
you control, pass `--allow-private`.

**`intel update` is very slow or hits rate limits**
Without an NVD API key, NVD limits you to about 5 requests per 30 seconds.
Get a free key (see `docs/CONFIGURATION.md`) or use `--since-year 2020` /
`--days 30` for a smaller, faster sync.

**`ModuleNotFoundError: No module named 'dns'`**
Install the optional dependency: `pip install dnspython`. DNS/email checks
are skipped cleanly without it; everything else still works.

**Dashboard shows "intelligence database unavailable"**
The SQLite file for vulnerability intelligence could not be opened — check
disk space and permissions on your VulnScope home directory
(`vulnscope check` prints the path and free space).

**A plugin shows status `timeout` in scan history**
The plugin did not finish within its configured timeout (often because a
target is slow or unresponsive). Re-run with `--profile passive` to confirm
basic connectivity, or increase `scan.plugin_timeout_scale` in
`config.json`.

**Scanning a very large network is slow on a phone**
Use `--lite` and scan a smaller CIDR range (VulnScope caps network scans at
`scan.max_hosts`, default 256, specifically to keep this manageable).

**I get many "potential" findings instead of "confirmed"**
This is intentional — VulnScope distinguishes passive pattern matches
(`potential`) from checks it actually verified (`confirmed`). See the
`rule_basis` field on each finding for exactly what evidence was used.
