# netgraph — Makefile
#
#   make            # list targets (same as `make help`)
#   make build      # build netgraph, netgraph-sensor and netgraph-agent into ./bin
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
# goos/goarch for the optional host agent: Linux (enforcement too), macOS and
# Windows (observe only). Keep in sync with .goreleaser.yaml.
AGENT_TARGETS := linux/amd64 linux/arm64 linux/arm linux/riscv64 linux/386 \
	darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.DEFAULT_GOAL := help

## build: build netgraph, netgraph-sensor and netgraph-agent into ./bin
.PHONY: build
build: build-server build-sensor build-agent

## build-server: build ./bin/netgraph
.PHONY: build-server
build-server:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph ./cmd/netgraph

## build-sensor: build ./bin/netgraph-sensor
.PHONY: build-sensor
build-sensor:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph-sensor ./cmd/netgraph-sensor

## build-ech: build the experimental ECH observer (not part of normal builds)
.PHONY: build-ech
build-ech:
	CGO_ENABLED=0 GOOS=linux $(GO) build -tags experimental -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph-ech ./cmd/netgraph-ech

## build-agent: build ./bin/netgraph-agent (host agent; GOOS=darwin or windows for those)
.PHONY: build-agent
build-agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph-agent$(if $(filter windows,$(GOOS)),.exe) ./cmd/netgraph-agent

## bpf: rebuild the agent's BPF objects from internal/agent/linux/bpf/src (clang, in Docker; BPF_NATIVE=1 for a local clang 20)
# The objects are checked in, so building the agent needs no clang. CO-RE
# (BTF) lets one object run on any kernel; there is one per byte order.
BPF_DIR   := internal/agent/linux/bpf
BPF_IMAGE ?= alpine:3.22
# Native mode needs clang, libbpf-dev and Linux headers. Objects are not
# compared byte for byte (that depends on the compiler and header versions):
# make bpf records a hash of src/conn.c, and a Go test fails when the source
# changed without a rebuild. Debian and Ubuntu keep asm/types.h under the
# multiarch triplet, which the BPF target does not search itself.
BPF_NATIVE     ?= 0
BPF_NATIVE_DIR ?= $(CURDIR)/$(BPF_DIR)
BPF_CC         ?= clang
BPF_STRIP      ?= llvm-strip
BPF_ARCH_DIR   := $(shell d=$$(gcc -dumpmachine 2>/dev/null); [ -n "$$d" ] && [ -d /usr/include/$$d ] && echo /usr/include/$$d)
.PHONY: bpf
bpf:
ifeq ($(BPF_NATIVE),1)
	cd $(BPF_NATIVE_DIR)/src && for e in el eb; do \
		$(BPF_CC) $(if $(BPF_ARCH_DIR),-I$(BPF_ARCH_DIR)) \
			-O2 -g -Wall -Werror -target bpf$$e -c conn.c -o ../conn_bpf$$e.o && \
		$(BPF_STRIP) -g ../conn_bpf$$e.o || exit 1; \
	done
else
	docker run --rm -v $(CURDIR)/$(BPF_DIR):/bpf -w /bpf/src $(BPF_IMAGE) sh -c '\
		apk add -q --no-cache clang20 llvm20 libbpf-dev linux-headers >/dev/null && \
		export PATH=/usr/lib/llvm20/bin:$$PATH && \
		for e in el eb; do \
			clang -O2 -g -Wall -Werror -target bpf$$e -c conn.c -o ../conn_bpf$$e.o && llvm-strip -g ../conn_bpf$$e.o || exit 1; \
		done && chown $(shell id -u):$(shell id -g) ../conn_bpf*.o'
endif
	cd $(CURDIR)/$(BPF_DIR)/src && { sha256sum conn.c 2>/dev/null || shasum -a 256 conn.c 2>/dev/null || openssl dgst -sha256 conn.c | sed 's/.*= //'; } > conn.c.sha256

## bpf-test: load the agent's BPF programs into this kernel and check their events (Docker, CAP_BPF)
.PHONY: bpf-test
bpf-test:
	CGO_ENABLED=0 $(GO) test -c -o $(BIN_DIR)/bpf.test ./$(BPF_DIR)
	docker run --rm --pid host --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add SYS_RESOURCE \
		-e NETGRAPH_BPF_TEST=1 -v $(CURDIR)/$(BIN_DIR)/bpf.test:/bpf.test:ro alpine /bpf.test -test.v -test.run Live

## web.build: assemble the web UI into web/dist
.PHONY: web.build
web.build:
	rm -rf web/dist && mkdir -p web/dist
	cp -r web/src/. web/dist/
	@echo "web/dist: $$(du -sh web/dist | cut -f1)"

## build-full: build netgraph with the web UI and the ASN table embedded
.PHONY: build-full
build-full: web.build asn.fetch
	CGO_ENABLED=0 $(GO) build -trimpath -tags embed_web,embed_asn -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/netgraph ./cmd/netgraph

## demo: generate a demo capture and database, then serve it on :8443
.PHONY: demo
demo: build-full build-sensor
	mkdir -p demo
	$(GO) run ./internal/testutil/genpcap demo/home.pcap
	$(BIN_DIR)/netgraph import -db demo/netgraph.db demo/home.pcap
	$(BIN_DIR)/netgraph serve -db demo/netgraph.db -no-auth -listen 127.0.0.1:8443

## oui.update: refresh the embedded IEEE MAC vendor registry
.PHONY: oui.update
oui.update:
	$(GO) run ./internal/oui/gen -o internal/oui/oui.tsv.gz

# The network (AS) table release builds embed (the embed_asn tag): iptoasn.com,
# public domain under the PDDL. It is not in git; a plain `go build` or
# `go install` has none, and the server then uses -asn-file.
ASN_URL   ?= https://iptoasn.com/data/ip2asn-combined.tsv.gz
ASN_TABLE := internal/asn/ip2asn-combined.tsv.gz
ASN_DATE  := internal/asn/ip2asn.date

## asn.fetch: download the ASN table builds embed, unless it is already here
.PHONY: asn.fetch
asn.fetch:
	@if [ -s $(ASN_TABLE) ] && [ -s $(ASN_DATE) ]; then \
		echo "$(ASN_TABLE): from $$(cat $(ASN_DATE)) (make asn.update to refresh)"; \
	else $(MAKE) --no-print-directory asn.update; fi

## asn.update: download the ASN table again
.PHONY: asn.update
asn.update:
	curl -fsSL --retry 3 -o $(ASN_TABLE).tmp $(ASN_URL)
	gzip -t $(ASN_TABLE).tmp
	mv $(ASN_TABLE).tmp $(ASN_TABLE)
	date -u +%Y-%m-%d > $(ASN_DATE)
	@echo "$(ASN_TABLE): $$(du -h $(ASN_TABLE) | cut -f1)"

## test: run all tests with the race detector, then vpn/ again without it
.PHONY: test
test:
	$(GO) test -race ./...
	@# vpn/'s AllocsPerRun guards skip under -race: this pass is what runs them.
	$(GO) test ./vpn/...

## vpn.interop: vpn/'s protocol cells against real peers, in Docker (slow; VPN_RUN=regexp)
VPN_RUN ?= .
.PHONY: vpn.interop
vpn.interop:
	$(GO) test -tags interop -count=1 -timeout 25m -run '$(VPN_RUN)' ./vpn/tests/interop/...

## test32: run the packet and decoder tests as a 32-bit process
.PHONY: test32
test32:
	CGO_ENABLED=0 GOARCH=386 $(GO) test ./internal/capture ./internal/decode ./internal/sensor ./internal/flow

## fuzz: run every fuzz target briefly (FUZZTIME=20s; FUZZPKGS=./internal/... to narrow)
FUZZTIME ?= 20s
FUZZPKGS ?= ./...
.PHONY: fuzz
fuzz:
	@for pkg in $$($(GO) list $(FUZZPKGS)); do \
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
	$(GO) vet -tags lab ./test/lab/...
	$(GO) vet -tags browser ./test/browser/...
	$(GO) vet -tags interop ./vpn/tests/interop/...
	$(GOLANGCI_LINT) run

## vulncheck: run govulncheck
.PHONY: vulncheck
vulncheck:
	$(GOVULNCHECK) ./...

## cross: compile every release architecture of the sensor and server, and the agent
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
	for t in $(AGENT_TARGETS); do \
		if env CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} GO386=softfloat $(GO) build -o /dev/null ./cmd/netgraph-agent; \
		then echo "ok    agent $$t"; else echo "FAIL  agent $$t"; fail=1; fi; \
	done; \
	exit $$fail

# An OpenWrt .ipk is a gzipped tar (opkg refuses a .deb's ar) of
# debian-binary, control.tar.gz and data.tar.gz. OpenWrt names architectures per target, not per CPU, so the
# defaults are the generic ones: override IPK_ARCH when `opkg
# print-architecture` on the router says something else.
IPK_GOARCH  ?= mipsle
IPK_GOARM   ?=
IPK_ARCH    ?= $(if $(filter amd64,$(IPK_GOARCH)),x86_64,$(if $(filter 386,$(IPK_GOARCH)),i386_pentium4,$(if $(filter arm64,$(IPK_GOARCH)),aarch64_generic,$(if $(filter arm,$(IPK_GOARCH)),arm_cortex-a7_neon-vfpv4,$(if $(filter mips,$(IPK_GOARCH)),mips_24kc,$(if $(filter mipsle,$(IPK_GOARCH)),mipsel_24kc,$(if $(filter mips64,$(IPK_GOARCH)),mips64_octeonplus,$(if $(filter mips64le,$(IPK_GOARCH)),mips64el_octeonplus,$(if $(filter riscv64,$(IPK_GOARCH)),riscv64_riscv64,$(if $(filter ppc64le,$(IPK_GOARCH)),powerpc64le_power8,$(IPK_GOARCH)))))))))))
IPK_VERSION ?= $(patsubst v%,%,$(VERSION))
IPK_BUILD   := $(BIN_DIR)/ipk
IPK_FILE    := $(IPK_BUILD)/netgraph-sensor_$(IPK_VERSION)_$(IPK_ARCH).ipk

## ipk: build an OpenWrt package for netgraph-sensor (IPK_GOARCH, IPK_ARCH)
.PHONY: ipk
ipk:
	rm -rf $(IPK_BUILD)
	mkdir -p $(IPK_BUILD)/data/usr/bin $(IPK_BUILD)/data/etc/init.d \
		$(IPK_BUILD)/data/etc/config $(IPK_BUILD)/data/etc/netgraph $(IPK_BUILD)/control
	CGO_ENABLED=0 GOOS=linux GOARCH=$(IPK_GOARCH) \
		$(if $(IPK_GOARM),GOARM=$(IPK_GOARM),) \
		$(if $(filter 386,$(IPK_GOARCH)),GO386=softfloat,) \
		$(if $(filter mips mipsle,$(IPK_GOARCH)),GOMIPS=softfloat,) \
		$(if $(filter mips64 mips64le,$(IPK_GOARCH)),GOMIPS64=softfloat,) \
		$(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(IPK_BUILD)/data/usr/bin/netgraph-sensor ./cmd/netgraph-sensor
	chmod 0755 $(IPK_BUILD)/data/usr/bin/netgraph-sensor
	install -m 0755 packaging/openwrt/netgraph-sensor.init $(IPK_BUILD)/data/etc/init.d/netgraph-sensor
	install -m 0644 packaging/openwrt/netgraph.config $(IPK_BUILD)/data/etc/config/netgraph
	printf 'Package: netgraph-sensor\nVersion: %s\nArchitecture: %s\nMaintainer: netgraph\nSection: net\nPriority: optional\nDepends: libc\nDescription: netgraph capture sensor (flow, DNS, DHCP, mDNS, ARP and TLS metadata; stateless, needs CAP_NET_RAW)\n' \
		"$(IPK_VERSION)" "$(IPK_ARCH)" > $(IPK_BUILD)/control/control
	printf '/etc/config/netgraph\n' > $(IPK_BUILD)/control/conffiles
	printf '2.0\n' > $(IPK_BUILD)/debian-binary
	tar --owner=0 --group=0 --numeric-owner -C $(IPK_BUILD)/data -czf $(IPK_BUILD)/data.tar.gz .
	tar --owner=0 --group=0 --numeric-owner -C $(IPK_BUILD)/control -czf $(IPK_BUILD)/control.tar.gz ./control ./conffiles
	tar --owner=0 --group=0 --numeric-owner -C $(IPK_BUILD) -czf $(IPK_FILE) ./debian-binary ./data.tar.gz ./control.tar.gz
	@echo "$(IPK_FILE):"
	@tar -tzf $(IPK_FILE)

## docker: build the sensor, server and agent images locally
.PHONY: docker
docker:
	docker build -f deploy/Dockerfile --target sensor -t netgraph-sensor:dev .
	docker build -f deploy/Dockerfile --target server -t netgraph:dev .
	docker build -f deploy/Dockerfile --target agent -t netgraph-agent:dev .

## browser: drive the web UI in a local headless Chrome (no Docker)
.PHONY: browser
browser: web.build
	$(GO) test -tags browser -count=1 -timeout 10m -v ./test/browser/...

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
	rm -rf $(BIN_DIR) dist web/dist demo

## help: list targets
.PHONY: help
help:
	@echo "usage: make <target>"; echo
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
