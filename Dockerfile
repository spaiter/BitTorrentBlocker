# Multi-stage build for minimal final image
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    linux-headers \
    libpcap-dev \
    make

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Build the binary
RUN CGO_ENABLED=1 go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.Date=${DATE}" \
    -o /btblocker \
    ./cmd/btblocker

# Final minimal image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap \
    iptables \
    ipset \
    ca-certificates

# Copy binary from builder
COPY --from=builder /btblocker /usr/local/bin/btblocker

# Create non-root user (note: btblocker needs CAP_NET_ADMIN, typically run with --cap-add)
RUN addgroup -g 1000 btblocker && \
    adduser -D -u 1000 -G btblocker btblocker

# Note: The container needs to run with NET_ADMIN capability
# docker run --cap-add=NET_ADMIN ...

ENTRYPOINT ["/usr/local/bin/btblocker"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="BitTorrent Blocker"
LABEL org.opencontainers.image.description="High-performance DPI-based BitTorrent traffic blocker"
LABEL org.opencontainers.image.source="https://github.com/spaiter/BitTorrentBlocker"
LABEL org.opencontainers.image.licenses="MIT"
