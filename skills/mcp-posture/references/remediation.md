# Remediation snippets

Adapt every snippet to the scanned values (resource URL, issuer, scopes). Product settings move
between versions: name the setting, and tell the user to confirm it in their version's docs.

## Protected Resource Metadata (PRM, RFC 9728): PRM01-PRM11, AUTHN02-04, SCP02

Serve at `https://<host>/.well-known/oauth-protected-resource<path>` (path inserted after the
host), `Content-Type: application/json`:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["notes:read", "notes:write"],
  "bearer_methods_supported": ["header"],
  "resource_name": "Example notes MCP server"
}
```

`resource` must be byte-for-byte the URL clients use (scheme, host, port, path, trailing slash)
and is the token audience. Every 401 from the MCP endpoint:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="notes:read"
```

No `error=` attribute when the request carried no token. Insufficient scope: `403` with
`error="insufficient_scope", scope="notes:write"`.

### MCP Python SDK (`mcp` 2.x, `MCPServer`)

Configure the server's auth settings with the issuer and the resource URL so the SDK serves PRM
and validates audience; enable DNS-rebinding protection for the Streamable HTTP app:

```python
from mcp.server.transport_security import TransportSecuritySettings

app = server.streamable_http_app(
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["mcp.example.com"],
        allowed_origins=["https://app.example.com"],
    ),
)
```

## Authorization server metadata: ASM01-ASM13, CIMD01

Whatever the product, the target metadata looks like:

```json
{
  "issuer": "https://auth.example.com",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true
}
```

### Keycloak

- Per client, *Advanced* > *Proof Key for Code Exchange Code Challenge Method*: `S256` (ASM04/05).
- Per client, disable *Implicit flow* and *Direct access grants* (password grant) (ASM06/07).
- Token audience: add an *Audience* mapper (or client scope) that puts the MCP resource URL in
  `aud`, and have the MCP server reject other audiences.
- Client registration policies: restrict *Anonymous* registration (trusted hosts, max clients)
  if DCR must stay on (ASM09).

### Auth0

- Model the MCP server as an *API* whose identifier is the resource URL; tokens then carry it in
  `aud`. Check whether your tenant accepts the RFC 8707 `resource` parameter or only `audience`.
- Application > *Advanced settings* > *Grant types*: keep Authorization Code (+ Refresh Token);
  remove Implicit and Password.
- Dynamic Client Registration is a tenant-level setting: disable it unless needed (ASM09/10).

### Okta

- Use a custom authorization server with the resource URL as *audience*.
- App integration: *Require PKCE*, grant types Authorization Code (+ Refresh Token) only.
- Access policies: scopes per client, no `*`-style broad grants (SCP01).

### Microsoft Entra ID

- *Expose an API*: set the Application ID URI and define fine-grained scopes; the token audience
  is that URI. Entra expects scopes such as `api://<id>/notes.read` rather than an RFC 8707
  `resource` parameter: document this mismatch for MCP clients.
- *Authentication*: keep implicit grant (access and ID tokens) unchecked.
- Entra does not offer open DCR; registration is pre-registration (CIMD02 reports it).

## Transport: TRN01-TRN10, AUTHN06

### nginx

```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;                       # TRN02
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;  # TRN05
    add_header X-Content-Type-Options nosniff always;     # TRN10
    server_tokens off;                                    # AUTHN06 banner
    location /mcp {
        if ($arg_access_token) { return 400; }           # PRM06 / query tokens
        proxy_pass http://mcp_upstream;
    }
}
server { listen 80; return 308 https://$host$request_uri; }   # TRN04
```

Origin validation (DNS rebinding) belongs in the MCP server itself (see SDK settings above) or
in the gateway: reject requests whose `Origin` is present and not allow-listed with `403`.

## Tool surface: TOOL01-TOOL09, PIN01-PIN04

- Rewrite descriptions to describe behaviour only; no directives about other tools, secrecy or
  data routing. Strip format/control characters at build time.
- Constrain parameters (`enum`, `pattern`, allow-listed hosts and base directories).
- Set annotations truthfully (`destructiveHint: true` on delete/overwrite tools).
- Namespace tool names (`notes_delete`, not `delete`) to avoid collisions across servers.
- Pin the reviewed surface (`mcp-posture pin`) and run `scan --baseline` in CI so changes need a
  review.

## CI: GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  mcp-posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: batou9150/mcp-posture@v1.1.1 # x-release-please-version
        with:
          targets-file: mcp-servers.txt
          baseline: mcp-posture.lock.json
          fail-on: high
```
