# Configuration

## `mcp-posture.toml`

Read from the current directory (or `--config PATH`). CLI flags override the file; relative
paths resolve from the file's directory.

```toml
[scan]
targets = ["https://mcp.example.com/mcp"]
targets_file = "mcp-servers.txt"     # one URL per line, # comments
client_configs = ["auto"]            # or paths to .mcp.json / claude_desktop_config.json / ...
fail_on = "high"                     # info | low | medium | high | critical
spec = "auto"                        # or 2025-03-26 | 2025-06-18 | 2025-11-25 | 2026-07-28
enable = []                          # check IDs or families, e.g. ["PRM", "ASM04"]
disable = ["ASM08"]
timeout = 10                         # seconds per request
retries = 2                          # idempotent requests only, exponential backoff
backoff = 0.5
max_bytes = 1048576                  # response body cap
concurrency = 4                      # targets scanned in parallel
proxy = "http://proxy.internal:3128"
ca_bundle = "certs/internal-ca.pem"
user_agent = "mcp-posture (security team)"
allow_private = false                # loopback / RFC 1918 / link-local targets
tls_probe = true                     # extra TLS handshakes (legacy versions, certificate)
baseline = "mcp-posture.lock.json"
ignore_file = ".mcp-posture-ignore"
sarif_anchor = "mcp-posture.toml"    # repo file SARIF results point to by default
```

## Suppressions: `.mcp-posture-ignore`

```toml
[[ignore]]
check = "MCPP-ASM09"                 # or the short form "ASM09"
target = "https://mcp.example.com/*" # glob, default "*"
location = "*"                       # glob on the finding location
justification = "Open DCR is intended: public client registry"   # required, 10+ chars
expires = 2026-12-31                 # optional; expired suppressions resurface the finding
```

Suppressed findings stay in JSON and SARIF (with the justification) but do not count towards the
exit code.

## Rug-pull baseline

```bash
mcp-posture pin https://mcp.example.com/mcp -o mcp-posture.lock.json   # review, then commit it
mcp-posture scan https://mcp.example.com/mcp --baseline mcp-posture.lock.json
```

The lock stores a canonical hash and the security-relevant fields (name, title, description,
schemas, annotations, URIs) of every tool, prompt, resource and template. Unicode is not
normalized on purpose, so an invisible character added to a description is a change.
`MCPP-PIN03` reports a unified diff with hidden characters made visible.

## Client configs

`--from-client-config auto` reads, when present: `.mcp.json`, `.vscode/mcp.json`,
`.cursor/mcp.json` in the current directory; `~/.claude.json` (including per-project servers),
`~/.cursor/mcp.json`, Windsurf, Claude Desktop and VS Code user configs. Only remote entries
(`url` / `serverUrl`, or `mcp-remote` bridges) are scanned. Headers and environment values from
these files are never read into the scan or the report.
