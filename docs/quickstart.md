# Quickstart

## Install

=== "uvx (no install)"

    ```bash
    uvx mcp-posture scan https://mcp.example.com/mcp
    ```

=== "pipx / uv tool"

    ```bash
    pipx install mcp-posture        # or: uv tool install mcp-posture
    mcp-posture scan https://mcp.example.com/mcp
    ```

=== "Docker"

    ```bash
    docker run --rm ghcr.io/batou9150/mcp-posture scan https://mcp.example.com/mcp
    ```

PyPI and GHCR packages are published from the first tagged release.

## Scan

```bash
mcp-posture scan https://mcp.example.com/mcp                    # table on stdout
mcp-posture scan https://mcp.example.com/mcp -f json -o report.json
mcp-posture scan --from-client-config auto                     # servers from your MCP clients
mcp-posture discover                                           # just list them
```

Servers that require authentication answer `401`: the scanner audits the challenge and the OAuth
metadata, but cannot list tools. To include the tool surface, pass a token **through the
environment** (never on the command line, never pasted in a chat):

```bash
export MCP_TOKEN=...   # e.g. from your secret manager
mcp-posture scan https://mcp.example.com/mcp --token-env MCP_TOKEN
```

For your own server, `--login` runs the OAuth flow in your browser and scans with the token
without showing it: `mcp-posture scan https://mcp.example.com/mcp --login`. See
[Log in](login.md).

## Read the results

Each finding has a stable ID (`MCPP-ASM04`), a severity, a confidence, the location (URL, issuer
or `tool:<name>`), a message and evidence. `mcp-posture checks show MCPP-ASM04` prints the
rationale, the remediation and the references.

The spec revision is negotiated during the handshake. Behind authentication without a token it
cannot be, so the latest revision is assumed and reported as `default`; pin it with
`--spec 2025-06-18` when you know better.

## Try it locally

```bash
git clone https://github.com/batou9150/mcp-posture && cd mcp-posture && uv sync
uv run python scripts/demo_servers.py &       # secure :8401, misconfigured :8402, poisoned :8403
uv run mcp-posture scan http://127.0.0.1:8402/mcp --allow-private
```
