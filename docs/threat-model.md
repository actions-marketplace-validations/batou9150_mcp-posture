# Threat model of the scanner

`mcp-posture` talks to servers that may be hostile. This page lists what it defends against.

| Threat | Mitigation |
|---|---|
| SSRF: a target, redirect, `resource_metadata` or `authorization_servers` URL points to internal services or cloud metadata | Every connection resolves the host and refuses loopback, private, link-local, CGNAT, multicast and reserved addresses at connect time, after DNS resolution (no TOCTOU), on every redirect hop. `--allow-private` lifts it for your own lab. With `--proxy`, every request and redirect hop is resolved and vetted locally before it is handed to the proxy; a proxy that resolves names differently (split-horizon DNS) is outside the scanner's control. |
| Credential leakage | Tokens come only from an env var, a file or stdin. They are sent only to the target origin, never forwarded on cross-origin redirects, and redacted from every report and log line (plus token-shaped strings). Headers from client configs are never read. |
| Resource exhaustion | Per-request timeout, streamed bodies capped (1 MiB by default, 64 KiB for the legacy SSE `endpoint` stream; other SSE responses get the default cap and a 5 s read limit), compression never requested and gzip/deflate inflated only up to the cap (no decompression bombs), bounded redirects (5), bounded pagination (20 pages), bounded concurrency. |
| Malicious content in reports | Server-controlled strings are neutralized: no terminal escape sequences, bidi overrides or invisible characters reach your terminal, PR comments or code scanning. |
| Parser crashes | Header and metadata parsers are property-tested (Hypothesis); a check that raises becomes an `MCPP-ERR00` finding instead of aborting the scan; malformed `Location` headers are handled without httpx's redirect parser. |
| `login`: hostile metadata, redirect interception, token leaks | Discovery refuses a PRM `resource`, issuer or PKCE mismatch before the browser opens; the browser only ever opens the HTTPS `authorization_endpoint`. PKCE S256, random `state`, RFC 9207 `iss` check. The loopback listener binds `127.0.0.1`, accepts only `GET /callback` with the right `state`, and echoes nothing. The token is never printed to a terminal without `--show-token`; token files are mode 600 and never written through a symlink; refresh tokens are discarded. DCR clients are deleted afterwards (RFC 7592) unless kept. |
| Side effects on the target | Passive mode sends only what a well-behaved MCP client sends, plus a few read-only probes ([listed below](#what-a-passive-scan-sends)). No tool is ever called. |
| Supply chain | Locked dependencies (`uv.lock`), `pip-audit` and CodeQL in CI, actions pinned by commit SHA and base images by digest, distroless nonroot image. Releases use PyPI Trusted Publishing with attestations, build provenance, a CycloneDX SBOM and keyless cosign signatures on images (see [SECURITY.md](https://github.com/batou9150/mcp-posture/blob/main/SECURITY.md)). |
| Telemetry | None. The scanner only contacts the targets and the authorization servers they advertise. |

## What a passive scan sends

Per target, with the token added to MCP requests when you pass one:

| Request | Why |
|---|---|
| `POST server/discover` (2026-07-28), else `POST initialize` and `notifications/initialized` | Protocol revision and transport, as any client does on connect |
| A second `POST initialize`, then `DELETE` of that session (2025-11-25 and earlier, when the server issues `Mcp-Session-Id`) | Compares two session IDs (TRN08). The `DELETE` only ends the session the scanner opened |
| `POST tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, at most 20 pages each | The tool surface (TOOL, PIN) |
| `DELETE` of the main session at the end | Session teardown, as a client does on exit |
| `GET` with `Accept: text/event-stream` | Legacy HTTP+SSE detection; closed after the `endpoint` event or 5 s |
| `GET` of the Protected Resource Metadata (`resource_metadata` URL, path-inserted and root well-known) and of the authorization server metadata (RFC 8414 and OpenID variants) | OAuth discovery |
| `GET /authorize`, `/token`, `/register` without parameters (2025-03-26 servers without metadata only) | Detects the spec's default endpoints (ASM13) |
| `GET http://<host><path>`, redirects not followed | Plain-HTTP behaviour (TRN04) |
| `GET /mcp-posture-nonexistent-path` | Error page content (AUTHN06) |
| TLS handshakes to each HTTPS origin, including one limited to TLS 1.0/1.1 | Certificate and legacy TLS (TRN02, TRN03); skipped with `--no-tls-probe` |

None of these creates, changes or deletes data on the server; the only state they touch is the
scanner's own MCP sessions. `login` adds the OAuth flow you go through in your browser and, with
DCR, a client registration (see [Login](login.md)).

Out of scope: protecting a target from a malicious operator of the scanner. Responsible use is
the operator's obligation.
