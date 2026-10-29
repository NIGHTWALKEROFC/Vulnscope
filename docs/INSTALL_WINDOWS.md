# Installing VulnScope on Windows

## Requirements
- Windows 10 or later
- Python 3.9 or newer — download from https://python.org/downloads and check
  **"Add python.exe to PATH"** during setup.

## Steps
1. Open PowerShell.
2. Clone or download the repository, then enter it:
   ```powershell
   git clone https://github.com/<your-username>/vulnscope.git
   cd vulnscope
   ```
3. Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks the script, run PowerShell as Administrator once and
   execute `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then retry.
4. Install VulnScope:
   ```powershell
   pip install -e .
   ```
5. Verify the installation:
   ```powershell
   vulnscope check
   ```

## Optional: Nmap
Some deeper network checks are easier with Nmap installed. Download the
installer from https://nmap.org/download.html, install it, and make sure
`nmap.exe` is on your `PATH` (the installer offers to do this). VulnScope's
built-in port scanner works without Nmap; Nmap is only used opportunistically
when `vulnscope check` reports it as available.

## Updating the vulnerability database
```powershell
vulnscope intel update
```
This downloads CVE and known-exploited-vulnerability data from NVD and CISA
(see docs/INTEL_UPDATES.md) and can take a while on the first run.

## Running a scan
```powershell
vulnscope scan https://example.com --profile standard -o report.html
```

## Running the dashboard
```powershell
vulnscope dashboard
```
Then open http://127.0.0.1:8787 in your browser.
