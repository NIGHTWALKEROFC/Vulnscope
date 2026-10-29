# Writing a VulnScope plugin

A plugin is a Python module under `vulnscope/plugins/` that defines one or
more subclasses of `vulnscope.plugin.Plugin`, registered with the
`@register` decorator. Plugins are auto-discovered at startup.

## Minimal example

```python
from vulnscope.plugin import Plugin, register

@register
class MyCheck(Plugin):
    id = "web.mycheck"
    name = "My custom check"
    description = "Explains what this plugin looks for and why it matters."
    target_types = ("url",)          # url, host, source, apk, ipa, local
    categories = ("Security misconfiguration",)
    active = False                   # True if it sends extra requests beyond the base page
    auth_required = False            # True if it needs --header/--cookie session options
    risk = "low"                     # low | medium | high
    timeout = 60                     # seconds before the engine cancels this plugin
    min_profile = "passive"          # passive | standard | comprehensive

    def run(self, ctx):
        resp = ctx.base()            # the already-fetched base page (cached per scan)
        if "X-My-Header" not in resp.headers:
            yield ctx.finding(
                "X-My-Header is missing", "low", "confirmed", "Security misconfiguration",
                rule_id="web.mycheck.missing", confidence="high",
                evidence="No X-My-Header on the response.",
                remediation="Add the header.",
            )
```

## The `ctx` object (`vulnscope.context.Context`)
- `ctx.http` — a `SafeSession` (see below) for making additional requests
- `ctx.base()` — cached GET of the scan target's main URL
- `ctx.finding(title, severity, status, category, **kwargs)` — build a
  `Finding` with `target`/`source` already filled in
- `ctx.asset(kind, value, data)` — record a discovered asset (technology,
  open port, cookie, etc.)
- `ctx.intel` — the local `IntelDB` (or `None` if unavailable) for CVE
  lookups via `vulnscope.intel.matcher.cve_findings`
- `ctx.check()` — raises `Cancelled` if the scan/plugin should stop; call
  this periodically in loops
- `ctx.scope` — the authorized `Scope`; always resolve/validate hosts
  through it rather than connecting directly

## Networking safely
Never use `socket` or `requests` directly against user-supplied hosts.
`ctx.http` (a `SafeSession`) and `ctx.scope.resolve_checked()` enforce the
authorization scope and block private/loopback/metadata addresses unless
`--allow-private` was set. If your plugin needs a raw socket (like
`net.ports` does), resolve through `ctx.scope.resolve_checked()` first.

## Output schema
Always populate `title`, `severity` (`critical|high|medium|low|info`),
`status` (`confirmed|potential|version_match|informational`), `category`,
`evidence`, and `remediation`. Use `rule_basis` to explain *how* you reached
the severity/status so reviewers can judge confidence. Never fabricate a
CVSS score — only set `cvss_score`/`cvss_vector` when you got them from the
local CVE database (via `cve_findings`) or OSV.

## Testing
Add a test under `tests/` that builds a `Context` against a known fixture
(see `tests/test_source_plugins.py` for a local-file example, or
`tests/conftest.py`'s `test_server` fixture for a live HTTP example) and
asserts on the findings returned by `plugin.run(ctx)`.

## Registering dependencies
If your plugin needs an external Python package or binary, declare it in
`requires = ("py:somepackage", "bin:sometool")`. The engine will skip the
plugin cleanly (with a visible reason in `scan history` / plugin runs) if the
dependency is missing, instead of crashing the scan.
