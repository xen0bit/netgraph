# netgraph — Makefile
#
#   make            # list targets (same as `make help`)
#   make build      # build netgraph and netgraph-sensor into ./bin
#   make test       # run the test suite with the race detector
#   make cross      # compile every release architecture (no tests)
#   make lab        # run the isolated docker-compose lab test

GO      ?= go
BIN_DIR ?= bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Same symbols .goreleaser.yaml stamps, so local and released builds agree.
BUILDINFO := github.com/xen0bit/netgraph/internal/buildinfo
LDFLAGS := -s -w \
	-X '$(BUILDINFO).Version=$(VERSION)' \
	-X '$(BUILDINFO).Commit=$(COMMIT)' \
	-X '$(BUILDINFO).Date=$(DATE)'

GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK   ?= govulncheck

# goarch:extra-env for the sensor; it is what goes on routers, so it carries
# every Linux arch Go supports that a router plausibly runs. Keep in sync with
# .goreleaser.yaml and the cross job in .github/workflows/ci.yml.
SENSOR_TARGETS := amd64: arm64: arm:GOARM=5 arm:GOARM=6 arm:GOARM=7 386:GO386=softfloat \
	mips:GOMIPS=softfloat mipsle:GOMIPS=softfloat \
	mips64:GOMIPS64=softfloat mips64le:GOMIPS64=softfloat riscv64: ppc64le:
# goos/goarch for the server. No mips: modernc.org/sqlite does not build there.
SERVER_TARGETS := linux/amd64 linux/arm64 linux/arm linux/riscv64 \
	darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.DEFAULT_GOAL := help

## build: build netgraph and netgraph-sensor into ./bin
.PHONY: build
build: build-server build-sensor

## build-server: build ./bin/netgraph
.PHONY: build-server
build-server:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph ./cmd/netgraph

## build-sensor: build ./bin/netgraph-sensor
.PHONY: build-sensor
build-sensor:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph-sensor ./cmd/netgraph-sensor

## web.wasm: build the browser WASM module
.PHONY: web.wasm
web.wasm:
	mkdir -p web/src/wasm web/src/js
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o web/src/wasm/web.wasm ./cmd/web
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" web/src/js/wasm_exec.js

## test: run all tests with the race detector
.PHONY: test
test:
	$(GO) test -race ./...

## fuzz: run every fuzz target briefly (FUZZTIME=20s)
FUZZTIME ?= 20s
.PHONY: fuzz
fuzz:
	@for pkg in $$($(GO) list ./...); do \
		for f in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "== $$pkg $$f"; \
			$(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

## lint: gofmt check, go vet and golangci-lint
.PHONY: lint
lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt: files above need formatting"; exit 1)
	$(GO) vet ./...
	GOOS=js GOARCH=wasm $(GO) vet ./cmd/web
	$(GOLANGCI_LINT) run

## vulncheck: run govulncheck
.PHONY: vulncheck
vulncheck:
	$(GOVULNCHECK) ./...

## cross: compile every release architecture of both binaries
.PHONY: cross
cross:
	@fail=0; \
	for t in $(SENSOR_TARGETS); do \
		arch=$${t%%:*}; extra=$${t#*:}; \
		if env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$extra $(GO) build -o /dev/null ./cmd/netgraph-sensor; \
		then echo "ok    sensor linux/$$arch $$extra"; else echo "FAIL  sensor linux/$$arch $$extra"; fail=1; fi; \
	done; \
	for t in $(SERVER_TARGETS); do \
		if env CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} $(GO) build -o /dev/null ./cmd/netgraph; \
		then echo "ok    server $$t"; else echo "FAIL  server $$t"; fail=1; fi; \
	done; \
	exit $$fail

## docker: build the sensor and server images locally
.PHONY: docker
docker:
	docker build -f deploy/Dockerfile --target sensor -t netgraph-sensor:dev .
	docker build -f deploy/Dockerfile --target server -t netgraph:dev .

## lab: run the isolated docker-compose end-to-end lab
.PHONY: lab
lab:
	$(GO) test -tags lab -count=1 -timeout 15m -v ./test/lab/...

## tidy: go mod tidy
.PHONY: tidy
tidy:
	$(GO) mod tidy

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR) dist web/dist web/src/wasm

## help: list targets
.PHONY: help
help:
	@echo "usage: make <target>"; echo
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
