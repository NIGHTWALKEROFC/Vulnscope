# Configuration

VulnScope stores its data in `~/.vulnscope` by default (override with
`--home <path>` or the `VULNSCOPE_HOME` environment variable). On first run
it writes `config.json` there with defaults; edit that file directly, or let
the CLI flags override individual settings per run.

## Key settings (`config.json`)

| Section | Key | Meaning |
|---|---|---|
| `http` | `timeout`, `rate_limit_per_sec`, `max_response_bytes` | HTTP client behavior for web/API checks |
| `scan` | `concurrency`, `max_pages`, `max_depth`, `port_concurrency` | Crawl and scan limits |
| `scan` | `require_ack` | Whether the CLI must ask for authorization confirmation (`true` by default) |
| `intel` | `nvd_api_key` | Optional NVD API key — raises the NVD rate limit significantly |
| `intel` | `offline` | When `true`, no network calls are made; only cached/local data is used |
| `limits` | `max_upload_mb`, `max_scan_file_kb` | File and upload size ceilings |
| `plugins` | `disabled` | List of plugin IDs to always skip |

## NVD API key (optional, free)
Without a key, NVD limits requests to about 5 per 30 seconds, which makes a
full historical sync slow. A free key raises this to 50 per 30 seconds.
Request one at https://nvd.nist.gov/developers/request-an-api-key, then set
it either in `config.json` (`intel.nvd_api_key`) or as an environment
variable:
```bash
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## Environment variables
- `VULNSCOPE_HOME` — data directory (overrides the default `~/.vulnscope`)
- `NVD_API_KEY` — NVD API key
