# Client metadata lint

`mcp-posture cimd lint` validates **your own** client's Client ID Metadata Document, the JSON an
authorization server fetches when your MCP client uses a URL as its `client_id`.

```bash
mcp-posture cimd lint https://app.example.com/oauth/client.json      # fetch it like an AS would
mcp-posture cimd lint client.json --url https://app.example.com/oauth/client.json
```

Fetching follows the authorization-server rules: no redirect is followed, the size is capped,
private addresses are refused unless `--allow-private`.

Rules `MCPP-CIMD50` to `MCPP-CIMD57` cover the identifier URL shape, the `client_id` / URL
equality, required fields, redirect URI safety, shared secrets and private keys (which must never
be published), authentication method coherence, and how the document is served. See the
[catalogue](checks/index.md#client-id-metadata-documents).
