# MCP OAuth 2.1 Authentication

OAuth 2.1 authorization layer for MCP (Model Context Protocol) clients such as
Claude Code, Cursor, and Codex. Approval notifications are delivered via Discord
webhook; the approval link itself requires an explicit button click (POST with
CSRF token) — a bare GET does nothing.

## Architecture

```
MCP Client          Go Proxy (this server)         Discord
   |                       |                          |
   |-- request /mcp ------>|                          |
   |<-- 401 + metadata ----|                          |
   |                       |                          |
   |-- discovery ----------|                          |
   |-- register ---------->|                          |
   |-- authorize (browser) |-- webhook notification ->|
   |   "waiting..." page   |                          |
   |                       |          admin clicks    |
   |                       |<--- approve link --------|
   |                       |                          |
   |   poll detects ok --->|                          |
   |   redirect to localhost callback                 |
   |                       |                          |
   |-- POST /oauth/token ->|                          |
   |<-- access_token ------|                          |
   |                       |                          |
   |-- request /mcp ------>|  (proxied to upstream)   |
   |   Authorization: Bearer ...                      |
```

The existing session-cookie login flow for browsers is untouched. The auth
middleware now checks **both** session cookies and Bearer tokens.

## Endpoints

| Path | Method | Auth | Purpose |
|------|--------|------|---------|
| `/.well-known/oauth-protected-resource` | GET | public | RFC 9728 resource metadata |
| `/.well-known/oauth-authorization-server` | GET | public | RFC 8414 auth server metadata |
| `/oauth/register` | POST | public | Dynamic client registration (RFC 7591) |
| `/oauth/authorize` | GET | public | Start authorization, show waiting page |
| `/oauth/status` | GET | public | Poll for approval status (JSON) |
| `/oauth/approve` | GET | public | Show approve/deny form |
| `/oauth/approve` | POST | CSRF | Process approval (button click required) |
| `/oauth/token` | POST | public | Code-for-token exchange with PKCE |
| `/oauth/revoke` | POST | public | Token revocation |

## Security

- **PKCE S256** is mandatory. Plain challenge method is rejected.
- **CSRF tokens** protect the approve endpoint. GET renders the form; POST with
  the embedded CSRF token is the only way to approve.
- **Token rotation**: refresh token exchange issues a new refresh token and
  invalidates the old one.
- **One-time auth codes**: consumed immediately on exchange; 60-second TTL.
- **In-memory storage**: server restart invalidates all tokens. MCP clients
  re-authenticate automatically.

## Configuration

No new environment variables required. The OAuth system uses the existing
`DISCORD_WEBHOOK_URL` for approval notifications.

| Constant | Default | Description |
|----------|---------|-------------|
| `AuthRequestTTL` | 5 min | How long an approval request stays valid |
| `AuthCodeTTL` | 60 sec | Auth code lifetime after approval |
| `AccessTokenTTL` | 24 hours | Access token lifetime |
| `RefreshTokenTTL` | 30 days | Refresh token lifetime |

## Usage

### Connect Claude Code

```bash
claude mcp add --transport http inngest-dev https://inngest-dash.gtmeasy.com/mcp
```

Claude Code handles the entire OAuth flow automatically:
1. Detects 401 from the MCP endpoint
2. Discovers OAuth metadata
3. Registers as a client
4. Opens browser for authorization
5. Waits for Discord approval
6. Exchanges code for token
7. Reconnects with Bearer token

### Approve from Discord

When a coding agent requests access, a Discord notification appears with a
"Review & Approve" link. Clicking it opens the approve page:

- **GET** shows request details (client name, IP, country) and Approve/Deny buttons
- **Approve** button submits a POST with a CSRF token — this is the only way to grant access
- **Deny** button rejects the request

The coding agent's waiting page detects the approval and completes the flow
automatically.
