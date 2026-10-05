# Log in to scan behind OAuth

Most MCP servers answer `tools/list` only with a token. Without one, the scanner still audits the
challenge and the OAuth metadata, but the TOOL and PIN checks have nothing to look at.
`mcp-posture login` gets a token through the same flow an MCP client uses, for **a server you own
or are authorized to test**, without you ever handling the token.

```bash
# Log in and scan in one go: the token only exists in memory.
mcp-posture scan https://mcp.example.com/mcp --login

# Or get a token for later scans.
export MCP_TOKEN="$(mcp-posture login https://mcp.example.com/mcp)"
mcp-posture scan https://mcp.example.com/mcp --token-env MCP_TOKEN

# Or keep it in a private file (created with mode 600).
mcp-posture login https://mcp.example.com/mcp --token-file ~/.cache/mcp-token
mcp-posture scan https://mcp.example.com/mcp --token-file ~/.cache/mcp-token
```

Your browser opens on the authorization server's login page; once you consent, it redirects to
a one-shot listener on `127.0.0.1` and the scanner exchanges the code for a token. The login URL
is always printed too: if the browser opens in the wrong profile or window, copy it into the
right one.

## What the flow does

1. **Discovery**: the 401 challenge, Protected Resource Metadata, then the authorization server
   metadata, exactly as `scan` reads them. MCP 2025-03-26 servers (the server is its own
   authorization server) are supported, including the default `/authorize` and `/token`
   endpoints.
2. **Refusals**: login stops before opening the browser when the PRM `resource` does not match
   the URL, the issuer does not match its metadata, PKCE `S256` is not advertised, or the issuer
   or an endpoint is not plain HTTPS. A PRM served at the root of the host
   (`/.well-known/oauth-protected-resource`) may name the origin as `resource` (RFC 9728); the
   token is then bound to the whole origin.
3. **Client identity**, in MCP's order of preference:

    | Strategy | How | Notes |
    |---|---|---|
    | Pre-registered | `--client-id ID` (`--client-secret-env VAR` for a confidential client) | Register `http://127.0.0.1/callback` (any port) or pass the registered port with `--port`. A client secret is only sent to the authorization server you name with `--authorization-server`: the server under test must not be able to redirect your secret elsewhere. |
    | Client ID Metadata Document | `--client-metadata-url URL` | A document you host; it must list `http://127.0.0.1/callback` in `redirect_uris`. It is checked with the `cimd lint` rules first. |
    | mcp-posture's own document | default when the server supports CIMD | [`oauth/client.json`](oauth/client.json) on this site: a public client with the loopback redirect and no secret, like the documents MCP clients publish. Nothing is created on the authorization server. Pass `--register` to use DCR instead. |
    | Dynamic Client Registration | `--register` | Creates a client on the authorization server, so it needs your consent: `--register`, or a yes at the prompt. The client is deleted afterwards (RFC 7592) unless `--keep-client`. |

4. **Authorization**: code flow with PKCE `S256`, a random `state`, the `resource` parameter
   (RFC 8707) and the scope from the challenge (or `--scope`). The `iss` parameter is checked
   (RFC 9207) when the server advertises it.
5. **Token**: exchanged at the token endpoint, Bearer only. The refresh token is discarded.
   If the token is a JWT whose `aud` does not include the MCP URL, you get a warning.

## Where the token goes

| Command | Token |
|---|---|
| `scan --login` | In memory only, redacted from every output. |
| `login` with stdout captured (`$(...)`, a pipe) | Printed on stdout, nothing else. |
| `login` in a terminal | Refused unless `--show-token`: the token would end up on screen and in your scrollback. |
| `login --token-file PATH` | Written with mode 600; refused if PATH is a symlink or already exists with wider permissions. |

Messages go to stderr. The authorization code, the PKCE verifier, client secrets and
registration tokens are redacted from logs and errors as soon as they exist.

## Options

| Option | Default | |
|---|---|---|
| `--client-id`, `--client-secret-env`, `--client-metadata-url`, `--register`, `--keep-client` | | Client identity, above. When registering, the grant types follow what the server advertises (`authorization_code`, plus `refresh_token` if listed). |
| `--scope` | from the challenge, else PRM `scopes_supported` | Space-separated. `offline_access` is dropped from the defaults: refresh tokens are discarded anyway. |
| `--authorization-server URL` | first in PRM | When PRM lists several. |
| `--port N` | ephemeral | Loopback port of the redirect URI. |
| `--no-browser` | | Print the authorization URL instead (SSH sessions). |
| `--login-timeout S` | 300 | Time to complete the login in the browser. |

The same settings can live in `mcp-posture.toml` (secrets never do):

```toml
[login]
client_id = "mcp-posture-local"
scope = "notes:read"
port = 8765
register = false
keep_client = false
timeout = 300
```

`scan --login` scans exactly one target and cannot be combined with `--token-env`,
`--token-file` or `--token-stdin`.

## Exit codes

| Code | `login` | `scan --login` |
|---|---|---|
| `0` | token obtained (or the server needs no authentication) | as `scan` |
| `1` | login failed: denied, timed out, refused, or an authorization server error | findings at or above `--fail-on` |
| `2` | usage error | usage error |
| `3` | server or authorization server unreachable | as `scan` |
| `4` | | login failed |

## Security notes

- Every request of the flow goes through the scanner's hardened HTTP layer (SSRF guard,
  redirect policy, size caps). The registration management token is only ever sent to the
  registration endpoint's origin.
- The only URL opened in your browser is built from the advertised `authorization_endpoint`,
  which must be HTTPS: a hostile server cannot make the scanner open other schemes.
- The loopback listener binds to `127.0.0.1` only, accepts a single `GET /callback` carrying the
  expected `state`, ignores everything else (at most 16 connections at a time, 5 s to send a
  request), and answers with a static page that echoes nothing.
- Everything printed to your terminal is redacted and stripped of control and escape
  sequences, so a hostile server cannot disguise a link or rewrite your screen.
