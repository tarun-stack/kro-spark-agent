# Proxy - CLAUDE.md

## Overview

Transparent credential proxy written in Go. Intercepts outbound TCP via iptables, identifies destinations via TLS SNI or HTTP Host header, and either injects credentials (credential-replace) or tunnels bytes (passthrough).

## Build

```bash
docker build -t credential-proxy:latest proxy/
# Or with GOPROXY for restricted networks:
docker build --build-arg GOPROXY=direct -t credential-proxy:latest proxy/
```

## Architecture

- Single Go binary (`main.go`) — all proxy logic in one file
- `iptables-init.sh` — configures NAT REDIRECT rules (runs as root in init container)
- `cert-init.sh` — generates ephemeral ECDSA CA cert (runs as root in init container)
- `entrypoint.sh` — exec wrapper for the Go binary
- `config.yaml` — reference config showing all domain entry fields

## Key Design Decisions

- Proxy runs as UID 1337 (excluded from iptables redirect to avoid loops)
- Uses `SO_ORIGINAL_DST` syscall to get the real destination after iptables REDIRECT
- 1-second peek timeout handles server-speaks-first protocols (SSH)
- Per-host TLS certificates generated on-the-fly and cached in memory
- HTTP/1.1 only for credential-replace connections (avoids HTTP/2 frame complexity)
- Config only contains `domains` array — port/mode have sensible defaults

## Testing

Load into Kind and run scenario 03:
```bash
make build-proxy && make load-proxy && make run-03
make proxy-logs-03  # check ALLOWED/BLOCKED/PASSTHROUGH
```
