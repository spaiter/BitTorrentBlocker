# Integration Test Dockerfile
FROM golang:1.20-alpine

# Install required packages
RUN apk add --no-cache \
    linux-headers \
    libnetfilter_queue-dev \
    libnfnetlink-dev \
    iptables \
    ipset \
    make \
    git \
    gcc \
    musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o /usr/local/bin/btblocker ./cmd/btblocker

# Set environment for tests
ENV CGO_ENABLED=1
ENV GOOS=linux

# Default command runs tests
CMD ["go", "test", "-tags=integration", "./test/integration", "-v"]
