import importlib
import pkgutil

from vulnscope import platform_info

PROFILES = ("passive", "standard", "comprehensive")
ALL_OS = ("windows", "linux", "android", "darwin")
REGISTRY = {}


class Plugin:
    id = ""
    name = ""
    description = ""
    version = "1.0.0"
    platforms = ALL_OS
    target_types = ("url",)
    requires = ()
    categories = ()
    active = False
    auth_required = False
    risk = "low"
    timeout = 120
    min_profile = "passive"
    output_schema = "finding/v1"

    def missing_requirements(self):
        missing = []
        for item in self.requires:
            kind, _, name = item.partition(":")
            if kind == "py" and not platform_info.has_module(name):
                missing.append(item)
            elif kind == "bin" and not platform_info.has_binary(name):
                missing.append(item)
        return missing

    def availability(self, os_name):
        if os_name not in self.platforms:
            return False, "not supported on %s" % os_name
        missing = self.missing_requirements()
        if missing:
            return False, "missing dependency: " + ", ".join(missing)
        return True, ""

    def run(self, ctx):
        raise NotImplementedError

    def cleanup(self, ctx):
        return None

    def describe(self, os_name=None):
        ok, reason = self.availability(os_name or platform_info.detect_os())
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "platforms": list(self.platforms),
            "target_types": list(self.target_types),
            "requires": list(self.requires),
            "categories": list(self.categories),
            "active": self.active,
            "auth_required": self.auth_required,
            "risk": self.risk,
            "timeout": self.timeout,
            "min_profile": self.min_profile,
            "output_schema": self.output_schema,
            "available": ok,
            "unavailable_reason": reason,
        }


def register(cls):
    inst = cls()
    if not inst.id:
        raise ValueError("plugin id required")
    if inst.id in REGISTRY:
        raise ValueError("duplicate plugin id %s" % inst.id)
    REGISTRY[inst.id] = inst
    return cls


def discover():
    import vulnscope.plugins as pkg

    for info in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module("vulnscope.plugins." + info.name)
    return REGISTRY


def profile_index(name):
    return PROFILES.index(name) if name in PROFILES else 1


def select(kind, profile, os_name, disabled=(), include=None, exclude=None, authenticated=False):
    discover()
    chosen, skipped = [], []
    for plugin in REGISTRY.values():
        if kind not in plugin.target_types:
            continue
        if include and plugin.id not in include and not any(plugin.id.startswith(p + ".") for p in include):
            continue
        if exclude and (plugin.id in exclude or any(plugin.id.startswith(p + ".") for p in exclude)):
            continue
        if plugin.id in disabled:
            skipped.append((plugin, "disabled in configuration"))
            continue
        if profile_index(plugin.min_profile) > profile_index(profile):
            continue
        if plugin.auth_required and not authenticated:
            skipped.append((plugin, "requires authenticated session options"))
            continue
        ok, reason = plugin.availability(os_name)
        if not ok:
            skipped.append((plugin, reason))
            continue
        chosen.append(plugin)
    return chosen, skipped
