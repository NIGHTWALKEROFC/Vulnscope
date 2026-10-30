import importlib.util
import os
import platform
import shutil
import sys


def detect_os():
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix or os.environ.get("TERMUX_VERSION"):
        return "android"
    name = platform.system().lower()
    if name.startswith("win"):
        return "windows"
    if name == "darwin":
        return "darwin"
    return "linux"


def has_module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def has_binary(name):
    return shutil.which(name) is not None


def disk_usage(path):
    try:
        usage = shutil.disk_usage(path)
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return {"total": 0, "used": 0, "free": 0}


def diagnostics(home):
    modules = {}
    for mod in ("requests", "dns", "cryptography", "androguard", "yaml"):
        modules[mod] = has_module(mod)
    binaries = {}
    for exe in ("nmap", "semgrep", "trivy", "osv-scanner", "dpkg-query", "rpm", "npm", "pip"):
        binaries[exe] = has_binary(exe)
    return {
        "os": detect_os(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "arch": platform.machine(),
        "home": str(home),
        "disk": disk_usage(str(home) if os.path.isdir(str(home)) else os.path.expanduser("~")),
        "modules": modules,
        "binaries": binaries,
    }
