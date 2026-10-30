import os
import plistlib
import re
import shutil
import tempfile
import zipfile

from vulnscope.plugin import Plugin, register
from vulnscope.plugins._source import read_text
from vulnscope.rules import secrets

CWE = "https://cwe.mitre.org/data/definitions/%s.html"
_DANGEROUS_PERMS = {
    "android.permission.READ_SMS": "Reads all SMS messages, including one-time passcodes.",
    "android.permission.SEND_SMS": "Can send SMS, potentially incurring charges or enabling fraud.",
    "android.permission.RECEIVE_SMS": "Can intercept incoming SMS, including one-time passcodes.",
    "android.permission.READ_CALL_LOG": "Reads the device's call history.",
    "android.permission.READ_CONTACTS": "Reads the user's contact list.",
    "android.permission.ACCESS_FINE_LOCATION": "Reads precise device location.",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Reads location even when the app is not in use.",
    "android.permission.RECORD_AUDIO": "Can record audio from the microphone.",
    "android.permission.CAMERA": "Can capture photos or video.",
    "android.permission.READ_EXTERNAL_STORAGE": "Reads files from shared device storage.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Writes files to shared device storage.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps, enabling tapjacking or phishing overlays.",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can prompt installation of other APKs.",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility services can observe and control the whole device.",
    "android.permission.READ_PHONE_STATE": "Reads device and subscriber identifiers.",
}


def _extract(path, out_dir):
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        total = sum(i.file_size for i in zf.infolist())
        if total > 800 * 1024 * 1024 or len(names) > 50000:
            return None, "archive too large to analyze safely"
        for info in zf.infolist():
            target = os.path.normpath(os.path.join(out_dir, info.filename))
            if not target.startswith(os.path.normpath(out_dir)):
                return None, "archive contains unsafe path entries (zip-slip pattern)"
        zf.extractall(out_dir)
    return names, None


def _parse_binary_manifest(data):
    text = data.decode("utf-8", "ignore")
    perms = sorted(set(re.findall(r"android\.permission\.[A-Z_]+", text)))
    exported_count = len(re.findall(r"exported", text, re.I))
    debuggable = "android:debuggable" in text and re.search(r"debuggable.{0,3}true", text, re.I)
    cleartext = bool(re.search(r"usesCleartextTraffic", text))
    package = None
    match = re.search(r"package=\"([a-zA-Z0-9_.]+)\"", text)
    if match:
        package = match.group(1)
    return {"permissions": perms, "debuggable": bool(debuggable), "cleartext_hint": cleartext, "package": package}


@register
class ApkStaticAnalysis(Plugin):
    id = "mobile.apk"
    name = "Android APK static analysis"
    description = "Unpacks an APK and checks permissions, manifest flags, network security config, embedded secrets and cleartext traffic settings."
    target_types = ("apk",)
    categories = ("Mobile application security", "Insecure permissions", "Cleartext traffic", "Secrets management")
    timeout = 600

    def run(self, ctx):
        path = ctx.target.value
        if not os.path.isfile(path):
            return
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb > ctx.config.data["limits"]["max_upload_mb"]:
            yield ctx.finding(
                "APK exceeds the configured size limit", "info", "informational", "Mobile application security",
                rule_id="mobile.apk.too-large", confidence="high", evidence="File is %.1f MB." % size_mb,
                remediation="Raise limits.max_upload_mb in the configuration if this file should be analyzed.",
            )
            return
        tmp = tempfile.mkdtemp(prefix="vulnscope-apk-", dir=str(ctx.config.tmp_dir))
        try:
            try:
                names, err = _extract(path, tmp)
            except zipfile.BadZipFile:
                yield ctx.finding(
                    "File is not a valid APK/ZIP archive", "info", "informational", "Mobile application security",
                    rule_id="mobile.apk.invalid", confidence="high", evidence="zipfile could not open %s." % os.path.basename(path),
                )
                return
            if err:
                yield ctx.finding(
                    "APK could not be safely extracted", "medium", "informational", "Mobile application security",
                    rule_id="mobile.apk.extract-blocked", confidence="high", evidence=err,
                    remediation="Investigate the archive manually; automatic extraction was refused for safety.",
                )
                return
            manifest_path = os.path.join(tmp, "AndroidManifest.xml")
            manifest = {}
            if os.path.isfile(manifest_path):
                with open(manifest_path, "rb") as handle:
                    manifest = _parse_binary_manifest(handle.read())
            ctx.asset("apk-package", manifest.get("package") or os.path.basename(path), manifest)
            if manifest.get("debuggable"):
                yield ctx.finding(
                    "Application is debuggable", "high", "potential", "Mobile application security",
                    rule_id="mobile.apk.debuggable", confidence="low",
                    rule_basis="android:debuggable=true text found near the manifest flag; binary XML parsing is approximate",
                    evidence="AndroidManifest.xml appears to set android:debuggable=\"true\".",
                    impact="A debuggable release build allows attaching a debugger and extracting data on non-rooted devices.",
                    remediation="Remove android:debuggable or ensure release builds set it to false.",
                    references=[CWE % "489"], location="AndroidManifest.xml",
                )
            for perm, impact in _DANGEROUS_PERMS.items():
                if perm in manifest.get("permissions", []):
                    yield ctx.finding(
                        "Dangerous permission requested: %s" % perm.rsplit(".", 1)[-1], "low", "confirmed",
                        "Insecure permissions", rule_id="mobile.apk.perm." + perm.rsplit(".", 1)[-1].lower(),
                        confidence="high", evidence="AndroidManifest.xml declares %s." % perm, impact=impact,
                        remediation="Request only the permissions the app needs and explain their use to the user.",
                        references=["https://developer.android.com/guide/topics/permissions/overview"], location="AndroidManifest.xml",
                    )
            nsc_path = os.path.join(tmp, "res", "xml", "network_security_config.xml")
            cleartext_allowed = manifest.get("cleartext_hint", True)
            if os.path.isfile(nsc_path):
                nsc_text = read_text(nsc_path, 256)
                if re.search(r'cleartextTrafficPermitted="true"', nsc_text):
                    cleartext_allowed = True
                if re.search(r"<trust-anchors>\s*<certificates\s+src=\"user\"", nsc_text):
                    yield ctx.finding(
                        "Network security config trusts user-added certificates", "medium", "confirmed",
                        "Certificate validation weaknesses", rule_id="mobile.apk.user-ca", confidence="high",
                        evidence="network_security_config.xml includes <certificates src=\"user\"/>.",
                        impact="A user-installed CA certificate (e.g. from a proxy tool) would be trusted, enabling traffic interception.",
                        remediation="Trust only system certificates in release builds unless user CAs are explicitly required.",
                        references=[CWE % "295"], location="res/xml/network_security_config.xml",
                    )
            if cleartext_allowed:
                yield ctx.finding(
                    "Cleartext network traffic is permitted", "medium", "potential", "Cleartext traffic",
                    rule_id="mobile.apk.cleartext", confidence="low",
                    rule_basis="No network_security_config.xml restricting cleartext traffic was found, or the manifest flag suggests it is allowed",
                    evidence="usesCleartextTraffic not explicitly disabled.",
                    impact="Traffic to HTTP endpoints can be intercepted or modified on the network.",
                    remediation="Set android:usesCleartextTraffic=\"false\" and define a network security config that enforces HTTPS.",
                    references=[CWE % "319"], location="AndroidManifest.xml",
                )
            for root_dir in ("assets", "res"):
                full = os.path.join(tmp, root_dir)
                if not os.path.isdir(full):
                    continue
                scanned = 0
                for dirpath, _, filenames in os.walk(full):
                    for name in filenames:
                        if scanned >= 400:
                            break
                        ext = os.path.splitext(name)[1].lower()
                        if ext not in (".json", ".xml", ".txt", ".properties", ".js", ""):
                            continue
                        file_path = os.path.join(dirpath, name)
                        try:
                            if os.path.getsize(file_path) > 512 * 1024:
                                continue
                        except OSError:
                            continue
                        scanned += 1
                        text = read_text(file_path, 512)
                        if not text:
                            continue
                        for hit in secrets.scan_text(text, 5):
                            rel = os.path.relpath(file_path, tmp)
                            yield ctx.finding(
                                "%s found in app resources" % hit["label"], hit["severity"], "confirmed", "Secrets management",
                                rule_id="mobile.apk.secret." + hit["rule_id"], confidence="high",
                                rule_basis="Pattern match for %s in a bundled resource file" % hit["label"],
                                evidence="%s:%d matched %s: %s" % (rel, hit["line"], hit["label"], hit["masked"]),
                                impact="Anyone who extracts the APK can read this value.",
                                remediation="Remove hardcoded credentials; fetch secrets from a backend at runtime.",
                                references=[CWE % "798"], location="%s:%d" % (rel, hit["line"]),
                            )
            lib_dir = os.path.join(tmp, "lib")
            if os.path.isdir(lib_dir):
                abis = sorted(os.listdir(lib_dir))
                ctx.asset("apk-native-abis", os.path.basename(path), {"abis": abis})
            classes = [n for n in (names or []) if n.endswith(".dex")]
            if not classes:
                yield ctx.finding(
                    "No classes.dex found; APK may be encrypted or obfuscated at the container level", "info",
                    "informational", "Mobile application security", rule_id="mobile.apk.no-dex", confidence="medium",
                    evidence="Archive listing contains no .dex entries.",
                    remediation="If this is unexpected, verify the file is a standard APK.",
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@register
class IpaStaticAnalysis(Plugin):
    id = "mobile.ipa"
    name = "iOS IPA static analysis"
    description = "Unpacks an IPA and checks Info.plist transport security settings and bundled resources for hardcoded secrets."
    target_types = ("ipa",)
    categories = ("Mobile application security", "Cleartext traffic", "Secrets management")
    timeout = 600

    def run(self, ctx):
        path = ctx.target.value
        if not os.path.isfile(path):
            return
        tmp = tempfile.mkdtemp(prefix="vulnscope-ipa-", dir=str(ctx.config.tmp_dir))
        try:
            try:
                names, err = _extract(path, tmp)
            except zipfile.BadZipFile:
                yield ctx.finding(
                    "File is not a valid IPA/ZIP archive", "info", "informational", "Mobile application security",
                    rule_id="mobile.ipa.invalid", confidence="high", evidence="zipfile could not open %s." % os.path.basename(path),
                )
                return
            if err:
                yield ctx.finding(
                    "IPA could not be safely extracted", "medium", "informational", "Mobile application security",
                    rule_id="mobile.ipa.extract-blocked", confidence="high", evidence=err,
                )
                return
            payload_dir = os.path.join(tmp, "Payload")
            plist_path = None
            if os.path.isdir(payload_dir):
                for entry in os.listdir(payload_dir):
                    if entry.endswith(".app"):
                        candidate = os.path.join(payload_dir, entry, "Info.plist")
                        if os.path.isfile(candidate):
                            plist_path = candidate
                        break
            if plist_path:
                try:
                    with open(plist_path, "rb") as handle:
                        plist = plistlib.load(handle)
                except Exception:
                    plist = {}
                ats = plist.get("NSAppTransportSecurity", {})
                if ats.get("NSAllowsArbitraryLoads"):
                    yield ctx.finding(
                        "App Transport Security disabled globally", "high", "confirmed", "Cleartext traffic",
                        rule_id="mobile.ipa.ats-disabled", confidence="high",
                        evidence="Info.plist sets NSAllowsArbitraryLoads to true.",
                        impact="The app can make insecure HTTP connections to any domain.",
                        remediation="Remove NSAllowsArbitraryLoads and define per-domain exceptions only where required.",
                        references=[CWE % "319"], location="Info.plist",
                    )
                for domain, settings in (ats.get("NSExceptionDomains") or {}).items():
                    if settings.get("NSExceptionAllowsInsecureHTTPLoads"):
                        yield ctx.finding(
                            "App Transport Security exception allows insecure HTTP for %s" % domain, "medium",
                            "confirmed", "Cleartext traffic", rule_id="mobile.ipa.ats-exception", confidence="high",
                            evidence="Info.plist NSExceptionDomains.%s.NSExceptionAllowsInsecureHTTPLoads = true." % domain,
                            remediation="Remove the exception or justify it, scoping it as narrowly as possible.",
                            references=[CWE % "319"], location="Info.plist",
                        )
            else:
                yield ctx.finding(
                    "Could not locate Info.plist inside the IPA", "info", "informational", "Mobile application security",
                    rule_id="mobile.ipa.no-plist", confidence="medium", evidence="No Payload/*.app/Info.plist found.",
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
