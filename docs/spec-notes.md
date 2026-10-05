# Spec notes

Research notes behind the check catalogue. Each normative statement that a remote, black-box
scanner can observe is mapped to a check ID. Statements a scanner cannot observe are marked
**N/O** (not observable) with the reason, so the gaps are explicit.

Sources were fetched on 2026-10-04. IDs marked *(planned)* are reserved for possible opt-in active checks: they are not implemented,
so the corresponding statements are not verified by the scanner today.

## MCP specification revisions

| Revision | Status | Auth model | Transport |
|---|---|---|---|
| [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) | final | MCP server **is** the authorization server; RFC 8414 at the origin (path discarded), default `/authorize` `/token` `/register` fallbacks | Streamable HTTP introduced, HTTP+SSE kept for compatibility |
| [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | final | MCP server is an OAuth **resource server**: PRM (RFC 9728) MUST, `WWW-Authenticate` on 401 MUST, RFC 8707 audience MUST, no token passthrough | `MCP-Protocol-Version` header MUST; JSON-RPC batching removed |
| [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | final | OIDC Discovery allowed; PRM via challenge **or** well-known; `scope` in challenge SHOULD; step-up via 403 `insufficient_scope`; **CIMD SHOULD**, DCR demoted to MAY; PKCE S256 MUST, OIDC AS MUST publish `code_challenge_methods_supported` | invalid `Origin` → 403 MUST; SSE polling |
| [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/index) | **current** | auth split into four pages; DCR **deprecated**; RFC 9207 `iss` SHOULD; AS `issuer` equality MUST; `offline_access` SHOULD NOT be advertised by resources; scope hierarchies MUST | **stateless**: no `initialize`, no `Mcp-Session-Id`, no GET stream; `server/discover`; `Mcp-Method` / `Mcp-Name` headers; HTTP+SSE formally deprecated |
| draft | — | no normative change from 2026-07-28 at the time of writing | — |

The scanner detects the revision from the handshake (`server/discover` first, then
`initialize`), maps `2024-11-05` to `2025-03-26`, and falls back to the latest revision when
the server requires authentication and no token is supplied. `--spec` pins it explicitly.

## Transport (Streamable HTTP)

| Requirement | Revisions | Check |
|---|---|---|
| Servers MUST validate `Origin`; invalid → 403 (2025-11-25+) | all | MCPP-ACT01 *(planned)* |
| Local servers SHOULD bind to localhost | all | N/O (remote scanner) |
| Session ID SHOULD be globally unique and cryptographically secure | ≤ 2025-11-25 | MCPP-TRN08 |
| Session ID MUST contain only visible ASCII (0x21-0x7E) | ≤ 2025-11-25 | MCPP-TRN08 |
| Expired session → 404; missing required session → 400 | ≤ 2025-11-25 | N/O passively (needs session manipulation); candidate for ACT |
| Session IDs MUST NOT be used for authentication (Security Best Practices) | 2025-06-18+ | MCPP-ACT03/ACT04 *(planned)* cover token-per-request |
| Server SHOULD NOT mint session IDs | 2026-07-28 | MCPP-TRN09 |
| Invalid/unsupported `MCP-Protocol-Version` → 400 | 2025-06-18+ | MCPP-ACT05 *(planned)* |
| HTTP+SSE: deprecated; session carried in the endpoint URL | all | MCPP-TRN06, MCPP-TRN07 |
| TLS per BCP 195 (via RFC 9728 §7.1 / RFC 8414 §6.1) | 2025-06-18+ | MCPP-TRN01, MCPP-TRN02, MCPP-TRN03, MCPP-TRN04, MCPP-TRN05 |

## Authorization: resource server (MCP server)

| Requirement | Source | Revisions | Check |
|---|---|---|---|
| 401 when authorization is required | MCP | all | drives AUTHN/PRM; MCPP-AUTHN01 when absent |
| `WWW-Authenticate: Bearer` on 401 | RFC 6750 §3, MCP | all (MUST 2025-06-18) | MCPP-AUTHN02 |
| `resource_metadata` in the challenge, or well-known PRM | RFC 9728 §5.1, MCP | 2025-06-18 (challenge MUST), 2025-11-25+ (one of two) | MCPP-AUTHN03 |
| No `error` attribute without credentials (SHOULD NOT) | RFC 6750 §3.1 | all | MCPP-AUTHN05 |
| `scope` in the challenge (SHOULD) | MCP | 2025-11-25+ | MCPP-SCP02 |
| PRM MUST be implemented | RFC 9728, MCP | 2025-06-18+ | MCPP-PRM01 |
| PRM: 200, `application/json`, zero-valued params omitted | RFC 9728 §3.2 | 2025-06-18+ | MCPP-PRM02 |
| PRM `resource` identical to the requested URL | RFC 9728 §3.3 | 2025-06-18+ | MCPP-PRM03 |
| PRM `authorization_servers` with at least one AS | MCP | 2025-06-18+ | MCPP-PRM04 |
| AS issuer https | RFC 8414 §2 | 2025-06-18+ | MCPP-PRM05 |
| Tokens MUST NOT be in the query string | MCP, OAuth 2.1 §5.1 | all | MCPP-PRM06, MCPP-ACT02 *(planned)* |
| `scopes_supported` RECOMMENDED | RFC 9728 §2 | 2025-06-18+ | MCPP-PRM07 |
| `resource` MUST NOT have a fragment, SHOULD NOT have a query | RFC 8707 §2 | 2025-06-18+ | MCPP-PRM08 |
| `signed_metadata`: JWS with `iss`, no `alg=none` | RFC 9728 §2.2 | 2025-06-18+ | MCPP-PRM09 |
| `offline_access` SHOULD NOT be advertised | MCP | 2026-07-28 | MCPP-PRM10 |
| PRM variants consistent | (scanner policy) | 2025-06-18+ | MCPP-PRM11 |
| `resource_metadata` same-origin / HTTPS | (scanner policy; RFC 9728 does not require same origin) | 2025-06-18+ | MCPP-AUTHN04 |
| Tokens MUST be audience-validated; no token passthrough | MCP, RFC 8707, RFC 9700 §2.3 | 2025-06-18+ | MCPP-ACT03 *(planned)*; info MCPP-ASM08 when passive |
| Invalid or expired tokens → 401 | MCP, RFC 6750 §3.1 | all | MCPP-ACT04 *(planned)* |
| Insufficient scope → 403 `insufficient_scope` with `scope` | MCP, RFC 6750 §3.1 | 2025-11-25+ | MCPP-SCP03 *(planned, needs a token)* |
| Servers MUST account for scope hierarchies | MCP | 2026-07-28 | N/O |
| Error responses should not leak internals | OWASP (not spec) | all | MCPP-AUTHN06 |

## Authorization: authorization server

| Requirement | Source | Revisions | Check |
|---|---|---|---|
| RFC 8414 or OIDC Discovery MUST be provided | MCP | 2025-06-18+ (OIDC from 2025-11-25) | MCPP-ASM01 |
| 2025-03-26: metadata at the origin; else default endpoints | MCP | 2025-03-26 | MCPP-ASM13 |
| `issuer` identical to the issuer used to build the URL | RFC 8414 §3.3, OIDC §4.3, MCP 2026 | all | MCPP-ASM02 |
| `issuer` https, no query or fragment | RFC 8414 §2 | all | MCPP-ASM02, MCPP-ASM03 |
| All AS endpoints over HTTPS | MCP | all | MCPP-ASM03 |
| PKCE S256 required; `code_challenge_methods_supported` present | RFC 7636, OAuth 2.1, MCP 2025-11-25 | all | MCPP-ASM04 |
| `plain` prohibited | OAuth 2.1 §4.1.1 | all | MCPP-ASM05 |
| No implicit / password grants; `grant_types_supported` default includes implicit | OAuth 2.1 §10, RFC 9700 §2.4, RFC 8414 §2 | all | MCPP-ASM06 |
| `code` response type; no `token` | OAuth 2.1 §10.1 | all | MCPP-ASM07 |
| Audience-restricted tokens (`resource` honored, `invalid_target`) | RFC 8707 §2 | 2025-06-18+ | MCPP-ASM08 (info), MCPP-ACT06 *(planned)* |
| DCR exposure (open registration) | RFC 7591 §3 | all | MCPP-ASM09, MCPP-ACT09 *(planned, opt-in)* |
| CIMD SHOULD; DCR MAY (2025-11-25), deprecated (2026-07-28) | MCP | 2025-11-25+ | MCPP-ASM10, MCPP-CIMD01 |
| `iss` in authorization responses + `authorization_response_iss_parameter_supported` | RFC 9207, RFC 9700 §2.1, MCP 2026 | 2025-06-18+ | MCPP-ASM11 |
| `none` MUST NOT appear in auth signing alg lists | RFC 8414 §2 | all | MCPP-ASM12 |
| Exact redirect URI matching; no open redirect | OAuth 2.1 §2.3.1, RFC 9700 §4.11 | all | MCPP-ACT07 *(planned)* |
| PKCE enforced (not just advertised) | RFC 7636 §4.4.1, OAuth 2.1 §4.1.1 | all | MCPP-ACT08 *(planned)* |
| Refresh token rotation for public clients | OAuth 2.1 §4.3.1, MCP | 2025-06-18+ | N/O (needs a complete user flow) |
| Short-lived access tokens (SHOULD) | MCP | 2025-06-18+ | N/O |
| Consent page framing and CSRF protection, `__Host-` cookies (proxies) | MCP Security Best Practices 2025-11-25 | 2025-11-25+ | N/O passively (needs an interactive flow) |

## Client ID Metadata Documents

MCP 2025-11-25 and 2026-07-28 still cite draft-00. The latest IETF draft is
[draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)
(2026-07), which is stricter. The scanner uses -02 and says so in findings.

| Requirement (AS side) | Draft-02 § | Check |
|---|---|---|
| Advertise `client_id_metadata_document_supported` | §6 | MCPP-CIMD01 |
| Registration strategy (CIMD / DCR / pre-registered) | MCP | MCPP-CIMD02 |
| `client_id` URL must be https with a path, no userinfo, fragment or dot segments | §3 | MCPP-CIMD10 *(planned)* |
| MUST NOT fetch special-use IPs (SSRF) | §8.6 | MCPP-CIMD11 *(planned)* |
| Document `client_id` MUST equal its URL (simple string comparison) | §4, §3 | MCPP-CIMD12 *(planned)* |
| `redirect_uri` MUST exactly match the document | §4.2, MCP | MCPP-CIMD13 *(planned)* |
| Localhost-only redirects SHOULD warn; hostname MUST be displayed | MCP | MCPP-CIMD14 *(planned, low confidence)* |
| MUST NOT follow redirects when fetching | §5 | MCPP-CIMD15 *(planned)* |
| Limit document size (about 5 KB) | §8.7 | MCPP-CIMD16 *(planned)* |
| Respect cache headers; MUST NOT cache errors | §5.2 | MCPP-CIMD17 *(planned)* |
| Client side: no shared secrets, no private keys, required fields | §4.1 | `cimd lint` rules MCPP-CIMD50-57 |

## Tool surface

Not normative in the spec beyond the Security Best Practices and the tool annotations schema;
TOOL and PIN checks are heuristics with explicit confidence levels.

## Existing scanners (survey, 2026-10-04)

| Tool | Focus | OAuth posture | SARIF |
|---|---|---|---|
| [Snyk agent-scan](https://github.com/snyk/agent-scan) (formerly mcp-scan) | local configs, tool descriptions (remote API analysis) | no | no |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | configs, stdio, remote; YARA + LLM | no (supports OAuth login) | no |
| [Ramparts](https://github.com/highflame-ai/ramparts) | servers and configs; YARA; baseline pinning | no | yes |
| [mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) | runtime proxy, TOFU pinning | no | no |
| [Golf scanner](https://github.com/golf-mcp/golf-scanner) | IDE configs, 20 checks | presence only | no |
| [MCPJam OAuth conformance](https://docs.mcpjam.com/cli/oauth-conformance) | full live OAuth flow (needs a login) | yes (flow-level) | no (JUnit) |
| [MCP conformance suite](https://github.com/modelcontextprotocol/conformance) | protocol conformance | resource server only | no |
| [mcp-audit](https://github.com/achandra-security/mcp-audit) | offline inventory | yes (rules) | yes |

`mcp-posture` fills the remaining gap: a live, pre-login audit of a remote server's OAuth and
transport posture with spec-revision-aware, cited findings and CI-native output. It does not
try to replace runtime proxies or LLM-based tool analysis.
