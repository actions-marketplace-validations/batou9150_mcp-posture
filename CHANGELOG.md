# Changelog

## [1.0.0](https://github.com/batou9150/mcp-posture/compare/v1.0.0-rc1...v1.0.0) (2026-10-05)


### Documentation

* install from PyPI and GHCR ([5d18acc](https://github.com/batou9150/mcp-posture/commit/5d18accb1de2f538ab302d19b91a396ffc26d954))

## [1.0.0-rc1](https://github.com/batou9150/mcp-posture/releases/tag/v1.0.0-rc1) (2026-10-05)

First release candidate.

### Features

* Passive scanner for remote MCP servers (Streamable HTTP, legacy HTTP+SSE detection), aware of
  MCP revisions 2025-03-26, 2025-06-18, 2025-11-25 and 2026-07-28.
* Checks: transport (TRN01-11), authentication challenge (AUTHN01-06), Protected Resource
  Metadata (PRM01-11), authorization server metadata (ASM01-13), Client ID Metadata Documents
  (CIMD01-02), scopes (SCP01, SCP02, SCP04), tool surface (TOOL01-10), rug-pull pinning
  (PIN01-04).
* `mcp-posture cimd lint` for your own client's metadata document (CIMD50-57).
* Reports: table, JSON (versioned schema), SARIF 2.1.0 anchored to the declaring file,
  Markdown; suppressions with justification and expiry; `mcp-posture.toml`; targets from MCP
  client configs.
* Hardened HTTP layer: connect-time SSRF guard (IPv6 forms embedding IPv4 included, also
  enforced with `--proxy`), manual redirects without cross-origin credentials, capped bodies,
  a deadline on response headers and a per-target time limit (`--target-timeout`), token
  redaction that also masks truncated fragments, bounded JSON nesting.
* Reports neutralize server-controlled text: no control, bidi or invisible characters in any
  format, and no links, images, mentions or fence breaks in the Markdown summary.
* GitHub Action, distroless container image, Claude Code skill, documentation site.
