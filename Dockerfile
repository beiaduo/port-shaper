# --- build stage ---
FROM golang:1.25 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o port-shaper .

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping curl ca-certificates iptables \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/port-shaper /usr/local/bin/port-shaper
ENV API_TOKEN=changeme DEV=eth0 PORT=8088 SUFFIX=api
HEALTHCHECK --interval=10s --timeout=2s --retries=3 CMD curl -fsS http://127.0.0.1:${PORT}/${SUFFIX}/health || exit 1
CMD ["port-shaper","serve"]