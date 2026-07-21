FROM golang:1.22-bookworm AS builder
ARG GOPROXY=
ENV GOPROXY=${GOPROXY}
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /transparent-proxy .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1337 -m -s /bin/false proxyuser

COPY --from=builder /transparent-proxy /app/transparent-proxy
COPY entrypoint.sh /app/entrypoint.sh
COPY iptables-init.sh /app/iptables-init.sh
COPY cert-init.sh /app/cert-init.sh
# Strip CRLF in case these were checked out on Windows with autocrlf — a
# trailing \r turns "set -euo pipefail" into an invalid option name.
RUN sed -i 's/\r$//' /app/entrypoint.sh /app/iptables-init.sh /app/cert-init.sh \
    && chmod +x /app/entrypoint.sh /app/iptables-init.sh /app/cert-init.sh

EXPOSE 15001
USER 1337
CMD ["/app/entrypoint.sh"]
