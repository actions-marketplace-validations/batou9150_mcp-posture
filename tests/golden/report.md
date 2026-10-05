## ❌ mcp-posture: 1 MCP server(s) scanned

| critical | high | medium | low | info | suppressed |
|---:|---:|---:|---:|---:|---:|
| 0 | 1 | 1 | 3 | 2 | 1 |

Mode `passive` · fail on `high` · 1 blocking finding(s) · 0 unreachable target(s)

### ` https://mcp.test/mcp `

Spec `2026-07-28` (default) · transport `unknown` · auth required

| Severity | Check | Title | Details |
|---|---|---|---|
| high | [MCPP-ASM05](https://batou9150.github.io/mcp-posture/checks/mcpp-asm05/) | PKCE plain method allowed | ` code_challenge_methods_supported includes plain. ` |
| medium | [MCPP-AUTHN02](https://batou9150.github.io/mcp-posture/checks/mcpp-authn02/) | 401 without a Bearer challenge | ` The 401 response carries no Bearer challenge (schemes seen: none). ` |
| low | [MCPP-ASM11](https://batou9150.github.io/mcp-posture/checks/mcpp-asm11/) | Authorization response iss parameter not supported | ` authorization_response_iss_parameter_supported is not true. ` |
| low | [MCPP-AUTHN06](https://batou9150.github.io/mcp-posture/checks/mcpp-authn06/) | Error responses leak internals | ` Response headers disclose software versions: server: nginx/1.25.3. ` |
| low | [MCPP-TRN10](https://batou9150.github.io/mcp-posture/checks/mcpp-trn10/) | Weak security headers on discovery endpoints | ` https://mcp.test/.well-known/oauth-protected-resource/mcp: missing X-Content-Type-Options: nosniff. ` |
| info | [MCPP-ASM08](https://batou9150.github.io/mcp-posture/checks/mcpp-asm08/) | Resource indicator (RFC 8707) enforcement not verified | ` Audience restriction (RFC 8707) cannot be verified by a passive scan. ` |
| info | [MCPP-CIMD02](https://batou9150.github.io/mcp-posture/checks/mcpp-cimd02/) | Client registration strategies | ` Registration paths offered: CIMD, pre-registration. ` |

<details><summary>1 suppressed finding(s)</summary>

- `MCPP-TRN05` ` No Strict-Transport-Security header on 5 HTTPS response(s). `: ` HSTS is set by the CDN in front `

</details>
