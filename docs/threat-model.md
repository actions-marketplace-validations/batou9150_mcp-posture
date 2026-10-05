# Threat model of the scanner

`mcp-posture` talks to servers that may be hostile. This page lists what it defends against.

| Threat | Mitigation |
|---|---|
| SSRF: a target, redirect, `resource_metadata` or `authorization_servers` URL points to internal services or cloud metadata | Every connection resolves the host and refuses loopback, private, link-local, CGNAT, multicast and reserved addresses at connect time, after DNS resolution (no TOCTOU), on every redirect hop. `--allow-private` lifts it for your own lab. With `--proxy`, every request and redirect hop is resolved and vetted locally before it is handed to the proxy; a proxy that resolves names differently (split-horizon DNS) is outside the scanner's control. |
| Credential leakage | Tokens come only from an env var, a file or stdin. They are sent only to the target origin, never forwarded on cross-origin redirects, and redacted from every report and log line (plus token-shaped strings). Headers from client configs are never read. |
| Resource exhaustion | Per-request timeout, streamed bodies capped (1 MiB by default, 64 KiB for SSE), bounded redirects (5), bounded pagination (20 pages), bounded concurrency. |
| Malicious content in reports | Server-controlled strings are neutralized: no terminal escape sequences, bidi overrides or invisible characters reach your terminal, PR comments or code scanning. |
| Parser crashes | Header and metadata parsers are property-tested (Hypothesis); a check that raises becomes an `MCPP-ERR00` finding instead of aborting the scan; malformed `Location` headers are handled without httpx's redirect parser. |
| Side effects on the target | Passive mode sends metadata `GET`s, the MCP handshake and list calls only. No tool is ever called. |
| Supply chain | Locked dependencies (`uv.lock`), `pip-audit` and CodeQL in CI, actions pinned by commit SHA and base images by digest, distroless nonroot image. Releases use PyPI Trusted Publishing with attestations, build provenance, a CycloneDX SBOM and keyless cosign signatures on images (see [SECURITY.md](https://github.com/batou9150/mcp-posture/blob/main/SECURITY.md)). |
| Telemetry | None. The scanner only contacts the targets and the authorization servers they advertise. |

Out of scope: protecting a target from a malicious operator of the scanner. Responsible use is
the operator's obligation.
