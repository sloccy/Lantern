# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

WORKDIR /build

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Build the binary (fully static, no CGO).
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o launchpad .

# ── Stage 2: final ────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

# Copy CA certificates from builder for outbound HTTPS (ipify, Cloudflare, ACME).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary.
COPY --from=builder /build/launchpad /launchpad

# Ports: 80 (HTTP redirect), 443 (HTTPS).
# NOTE: binding to ports < 1024 as nonroot requires the NET_BIND_SERVICE
# capability — see docker-compose.yml.
EXPOSE 80 443

ENTRYPOINT ["/launchpad"]
