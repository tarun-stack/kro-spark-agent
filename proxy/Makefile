# Makefile for the transparent credential proxy
#
# Usage:
#   make build              # build Docker image
#   make build GOPROXY=direct  # build with direct Go module downloads
#   make test               # compile check (cross-compile for linux)

IMAGE   ?= credential-proxy:latest
GOPROXY ?=

.PHONY: build test

build: ## Build the credential-proxy Docker image
	docker build -t $(IMAGE) $(if $(GOPROXY),--build-arg GOPROXY=$(GOPROXY)) .

test: ## Verify Go code compiles for linux/amd64
	GOOS=linux GOARCH=amd64 go build -o /dev/null .
