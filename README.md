# Webhook Auth Proxy

A simple, robust reverse proxy written in Go that enforces a "one-time code via Discord Webhook" authentication flow.

## Features
- **Single Static Binary**: Easy to deploy.
- **Docker Ready**: Includes Dockerfile and Healthcheck.
- **Discord Auth**: Sends a 6-digit login code to a configured Discord Webhook.
- **Secure**: Uses ephemeral, rotating session keys (restarts invalidate sessions).
- **Zero Dependencies**: Uses Go standard library only.

## Configuration

Configured purely via environment variables:

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Port to listen on | No | `8080` |
| `UPSTREAM_URL` | URL to proxy authenticated requests to | **Yes** | - |
| `DISCORD_WEBHOOK_URL` | Discord Webhook URL for sending codes | **Yes** | - |

## Local Development

```bash
# Run locally
export UPSTREAM_URL="http://example.com"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
go run main.go
```

## Docker Compose

```yaml
services:
  proxy:
    image: ghcr.io/yourusername/webhook-auth-proxy:latest
    ports:
      - "8080:8080"
    environment:
      - UPSTREAM_URL=http://your-app:3000
      - DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
    depends_on:
      - your-app

  your-app:
    image: your-app-image
```
