import json
import re

from vulnscope.crawler import crawl
from vulnscope.http import HttpError
from vulnscope.plugin import Plugin, register
from vulnscope.plugins._web import CWE, short

API_WSTG = "https://owasp.org/www-project-api-security/"
_API_PATHS = ["/api", "/api/v1", "/api/v2", "/graphql", "/.well-known/openapi.json"]
_VERB_TAMPER = ("GET", "POST", "PUT", "PATCH", "DELETE")


@register
class ApiDiscovery(Plugin):
    id = "web.api"
    name = "REST and GraphQL API checks"
    description = "Finds JSON API endpoints, tests verbose errors, HTTP verb handling, mass GraphQL introspection and rate limiting."
    categories = ("API security", "Broken access control", "Security misconfiguration")
    active = True
    timeout = 240
    min_profile = "standard"

    def run(self, ctx):
        base_url = re.match(r"https?://[^/]+", ctx.target.value).group(0)
        json_points = set()
        for url, resp in crawl(ctx).pages.items():
            if "json" in resp.content_type or "application/problem+json" in resp.content_type:
                json_points.add(url)
        for suffix in _API_PATHS:
            ctx.check()
            try:
                resp = ctx.http.get(base_url + suffix, follow=False)
            except HttpError:
                continue
            if resp.status < 400 and ("json" in resp.content_type or resp.text.strip().startswith(("{", "["))):
                json_points.add(base_url + suffix)
        if not json_points:
            return
        ctx.asset("api-endpoints", base_url, {"count": len(json_points), "sample": sorted(json_points)[:10]})
        sample = sorted(json_points)[0]
        for f in self._verbs(ctx, sample):
            yield f
        for f in self._verbose(ctx, json_points):
            yield f
        graphql = base_url + "/graphql"
        for f in self._graphql(ctx, graphql):
            yield f
        for f in self._rate_limit(ctx, sample):
            yield f

    def _verbs(self, ctx, url):
        try:
            baseline = ctx.http.get(url, follow=False)
        except HttpError:
            return
        allowed_status = {baseline.status}
        for verb in _VERB_TAMPER:
            if verb == "GET":
                continue
            ctx.check()
            try:
                resp = ctx.http.request(verb, url, follow=False)
            except HttpError:
                continue
            if resp.status not in (404, 405, 501) and resp.status < 500:
                allowed_status.add((verb, resp.status))
        unexpected = [a for a in allowed_status if isinstance(a, tuple) and a[1] not in (401, 403)]
        if unexpected:
            yield ctx.finding(
                "API endpoint accepts unexpected HTTP methods", "low", "potential", "API security",
                target=url, rule_id="web.api.verbs", rule_basis="Non-GET verbs returned a non-error status", confidence="low",
                evidence="; ".join("%s -> %d" % u for u in unexpected),
                impact="Endpoints may allow state-changing actions without the intended method restrictions.",
                remediation="Explicitly allow only the methods each endpoint needs and return 405 for others.",
                references=[API_WSTG], location=url,
            )

    def _verbose(self, ctx, points):
        for url in list(points)[:8]:
            ctx.check()
            try:
                resp = ctx.http.get(url.rstrip("/") + "/vulnscope-missing-resource-9f1", follow=False)
            except HttpError:
                continue
            text = resp.text[:4000]
            if re.search(r"(Traceback|Exception|stack ?trace|at [\w.]+\(.+:\d+\)|SQLSTATE|org\.\w+\.\w+Exception)", text, re.I):
                yield ctx.finding(
                    "API returns stack trace or internal error detail", "medium", "confirmed", "Security misconfiguration",
                    target=url, rule_id="web.api.verbose-error", rule_basis="Error response body contains stack trace patterns",
                    confidence="high", evidence=short(text, 200), impact="Internal implementation details are exposed to clients.",
                    remediation="Return generic error bodies and log details server-side only.", references=[CWE % "209"], location=url,
                )
                break

    def _graphql(self, ctx, url):
        query = {"query": "query IntrospectionQuery { __schema { types { name } } }"}
        try:
            resp = ctx.http.post(url, json=query, headers={"Content-Type": "application/json"}, follow=False)
        except HttpError:
            return
        if resp.status != 200:
            return
        try:
            data = json.loads(resp.text)
        except ValueError:
            return
        types = (data.get("data") or {}).get("__schema", {}).get("types")
        if types:
            yield ctx.finding(
                "GraphQL introspection is enabled", "low", "confirmed", "API security", target=url,
                rule_id="web.api.graphql-introspection", rule_basis="Introspection query returned schema type names",
                confidence="high", evidence="%d schema types returned by __schema introspection." % len(types),
                impact="The full API schema, including unlinked fields and mutations, is discoverable by anyone.",
                remediation="Disable introspection in production or require authentication for it.",
                references=["https://owasp.org/www-project-api-security/", CWE % "213"], location=url,
            )
            ctx.asset("graphql-schema", url, {"type_count": len(types)})
        batch = [{"query": "{ __typename }"} for _ in range(50)]
        try:
            resp2 = ctx.http.post(url, json=batch, headers={"Content-Type": "application/json"}, follow=False)
        except HttpError:
            return
        if resp2.status == 200:
            try:
                parsed = json.loads(resp2.text)
                if isinstance(parsed, list) and len(parsed) >= 50:
                    yield ctx.finding(
                        "GraphQL endpoint accepts unbounded batched queries", "low", "potential", "API security",
                        target=url, rule_id="web.api.graphql-batch", rule_basis="A 50-query batch was processed in one request",
                        confidence="medium", evidence="Batched array of 50 queries returned %d responses." % len(parsed),
                        impact="Batching without limits can be used to amplify denial-of-service or brute-force attempts.",
                        remediation="Limit batch size and apply per-query cost analysis.", references=[API_WSTG], location=url,
                    )
            except ValueError:
                pass

    def _rate_limit(self, ctx, url):
        if ctx.profile != "comprehensive":
            return
        statuses = []
        for _ in range(20):
            ctx.check()
            try:
                resp = ctx.http.get(url, follow=False)
            except HttpError:
                break
            statuses.append(resp.status)
            if resp.status == 429:
                return
        if statuses and 429 not in statuses and len(statuses) >= 15:
            yield ctx.finding(
                "No rate limiting observed on API endpoint", "info", "potential", "API security", target=url,
                rule_id="web.api.no-rate-limit", rule_basis="20 rapid requests all returned non-429 status", confidence="low",
                evidence="Sent 20 requests at the configured scan rate; none received HTTP 429.",
                impact="Endpoints without rate limiting are easier to brute-force or abuse.",
                remediation="Add rate limiting, especially on authentication and expensive endpoints.", references=[API_WSTG], location=url,
                notes="This is a light check at the scanner's own throttled rate, not a true load test.",
            )
