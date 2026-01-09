# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod ./
# COPY go.sum ./ # Not created yet as no dependencies, but good practice to include if it exists
RUN go mod download

COPY . .

# Build the binary
# -ldflags="-w -s" reduces binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server .

# Final stage
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates for Discord webhook HTTPS calls
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/server .

# Create a non-root user
RUN adduser -D -g '' appuser
USER appuser

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["./server"]
