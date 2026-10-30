import threading
import time

from vulnscope.http import SafeSession
from vulnscope.models import Finding
from vulnscope.scope import Cancelled


class Context:
    def __init__(self, scan_id, target, profile, config, store, scope, intel, options, scan_cancel, shared, version="0"):
        self.scan_id = scan_id
        self.target = target
        self.profile = profile
        self.config = config
        self.store = store
        self.scope = scope
        self.intel = intel
        self.options = options
        self.version = version
        self._scan_cancel = scan_cancel
        self._plugin_cancel = threading.Event()
        self._shared = shared
        self.plugin_id = ""
        self.deadline = None
        self.http = None
        self._sessions = []
        if target.kind == "url":
            self.http = self.new_session(options.get("headers"), options.get("cookies"))

    def new_session(self, headers=None, cookies=None):
        session = SafeSession(self.scope, self.config, self.cancelled, headers, cookies, self.version)
        self._sessions.append(session)
        return session

    def cancelled(self):
        if self._scan_cancel.is_set() or self._plugin_cancel.is_set():
            return True
        return self.deadline is not None and time.monotonic() > self.deadline

    def check(self):
        if self.cancelled():
            raise Cancelled()

    def stop_plugin(self):
        self._plugin_cancel.set()

    def bind(self, plugin):
        clone = Context.__new__(Context)
        clone.__dict__.update(self.__dict__)
        clone._plugin_cancel = threading.Event()
        clone.plugin_id = plugin.id
        clone.deadline = time.monotonic() + plugin.timeout * float(self.config.data["scan"]["plugin_timeout_scale"])
        clone.http = None
        clone._sessions = []
        if self.target.kind == "url":
            clone.http = clone.new_session(self.options.get("headers"), self.options.get("cookies"))
            base = self.http
            if base is not None and not base.verify:
                clone.http.verify = False
        return clone

    @property
    def requests_made(self):
        return sum(s.count for s in self._sessions)

    def shared_get(self, key):
        with self._shared["lock"]:
            return self._shared["data"].get(key)

    def shared_set(self, key, value):
        with self._shared["lock"]:
            self._shared["data"][key] = value

    def shared_lock(self, key):
        with self._shared["lock"]:
            locks = self._shared["data"].setdefault("__locks", {})
            return locks.setdefault(key, threading.Lock())

    def base(self):
        cached = self.shared_get("base")
        if cached is not None:
            return cached
        with self.shared_lock("base"):
            cached = self.shared_get("base")
            if cached is None:
                cached = self.http.get(self.target.value)
                self.shared_set("base", cached)
        return cached

    def finding(self, title, severity, status, category, **kw):
        kw.setdefault("target", self.target.value)
        kw.setdefault("source", self.plugin_id)
        return Finding(title=title, severity=severity, status=status, category=category, **kw)

    def asset(self, kind, value, data=None):
        self.store.add_asset(self.scan_id, kind, value, data)
