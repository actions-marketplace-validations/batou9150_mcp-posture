# Security policy

## Reporting a vulnerability

Report vulnerabilities in `mcp-posture` itself through
[GitHub private vulnerability reporting](https://github.com/batou9150/mcp-posture/security/advisories/new).
Please do not open a public issue.

Include the version (`mcp-posture version`), how you ran it, and a minimal reproduction. A local
fixture server is the best reproduction; do not include data from servers you do not own.

You can expect an acknowledgement within 7 days and a fix or a mitigation plan within 30 days
for confirmed issues. Credit is given in the advisory unless you prefer otherwise.

## Scope

In scope, because the scanner talks to servers that may be hostile:

- SSRF: any way to make the scanner connect to a loopback, private, link-local or metadata
  address without `--allow-private` (redirects, DNS, metadata URLs, IPv6 forms).
- Credential leakage: a token sent to another origin, or appearing in a report, log or error.
- Report injection: server-controlled text that reaches a terminal, Markdown summary or SARIF
  output with control, bidi or invisible characters intact.
- Resource exhaustion: a response that makes the scanner hang or use unbounded memory.
- The GitHub Action: script injection through inputs, or token exposure.
- Release artifacts: anything that breaks provenance, signatures or the SBOM.

Out of scope: findings the scanner reports (or misses) about third-party MCP servers. A missed
or wrong check is a bug; open an issue.

## Supported versions

The latest release receives fixes. Release candidates are not supported once the final release
is out.

## Verifying releases

Python distributions on PyPI carry PEP 740 attestations from Trusted Publishing, and every
release asset has a GitHub build provenance attestation:

```bash
gh attestation verify mcp_posture-*.whl --repo batou9150/mcp-posture
```

Container images are signed keylessly with cosign and carry provenance and SBOM attestations:

```bash
cosign verify ghcr.io/batou9150/mcp-posture:<version> \
  --certificate-identity-regexp '^https://github.com/batou9150/mcp-posture/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/batou9150/mcp-posture:<version> --repo batou9150/mcp-posture
```

A CycloneDX SBOM of the runtime dependencies (`mcp-posture.cdx.json`) is attached to every
GitHub release.
