BINARY  := ssh_session_exporter
MODULE  := github.com/yuuki/ssh_session_exporter
GOOS    := linux
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)

# Tool versions. CI pins the same versions (.github/workflows); bump together.
GOLANGCI_LINT_VERSION ?= v2.15.0
GOVULNCHECK_VERSION   ?= v1.9.0
ACTIONLINT_VERSION    ?= v1.7.12
ZIZMOR_VERSION        ?= 1.32.0
FUZZTIME              ?= 30s
FUZZFLAGS             ?=
BENCH_COUNT           ?= 6
BENCHTIME             ?= 1s
# The privileged eBPF tests fail instead of skipping unless this is empty.
BPF_REQUIRE           ?= 1

# Build the Go tools with this module's toolchain (go env GOVERSION resolves
# go.mod's): golangci-lint refuses a module that targets a newer Go than the
# one it was built with, and `go run pkg@version` would otherwise build with
# the tool's own minimum Go.
GO_TOOLCHAIN := $(shell go env GOVERSION)
GO_TOOL      := GOTOOLCHAIN=$(GO_TOOLCHAIN) go run
# main, utmp's FileReader and the eBPF probe are Linux-only, so analyse the
# Linux view on any host; -exec keeps the tool itself built for the host.
GO_TOOL_LINUX := $(GO_TOOL) -exec 'env GOOS=linux'

GOLANGCI_LINT ?= $(GO_TOOL_LINUX) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   ?= $(GO_TOOL_LINUX) golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
ACTIONLINT    ?= $(GO_TOOL) github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
# uvx or pipx (preinstalled on GitHub-hosted runners) runs the pinned zizmor.
ZIZMOR ?= $(if $(shell command -v uvx 2>/dev/null),uvx zizmor@$(ZIZMOR_VERSION),pipx run zizmor==$(ZIZMOR_VERSION))

.PHONY: build test vet complexity clean install test-e2e test-e2e-rocky \
	check lint fmt lint-actions test-race test-fuzz test-bpf test-integration \
	bench vuln generate-bpf

build:
	GOOS=$(GOOS) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

vet:
	GOOS=linux go vet ./...

# Local pre-PR gate: what the required CI jobs check, without root or Docker.
check: lint lint-actions test-race build

# golangci-lint (linters and formatters per .golangci.yml) and go.mod tidiness.
lint:
	$(GOLANGCI_LINT) run
	go mod tidy -diff

fmt:
	$(GOLANGCI_LINT) fmt

# Lint (actionlint) and audit (zizmor) the GitHub Actions workflows. Without
# GH_TOKEN zizmor skips the audits that need the GitHub API.
lint-actions:
	$(ACTIONLINT)
	$(ZIZMOR) $(if $(GH_TOKEN),,--offline) .

test-race:
	go test -race ./...

# Run every fuzz target for FUZZTIME, e.g. make test-fuzz FUZZTIME=15s FUZZFLAGS=-parallel=2.
test-fuzz:
	@set -e; for pkg in $$(go list ./...); do \
		for f in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
			echo "== $$pkg $$f"; \
			go test -run='^$$' -fuzz="^$$f\$$" -fuzztime=$(FUZZTIME) $(FUZZFLAGS) $$pkg; \
		done; \
	done

# Load the embedded eBPF objects through the kernel verifier and attach them.
# Needs sudo, kernel BTF and tracefs; BPF_REQUIRE= turns failures into skips.
test-bpf:
	go test -count=1 -exec 'sudo env SSH_EXPORTER_REQUIRE_BPF=$(BPF_REQUIRE)' -run '^TestProbe' -v ./ebpf/sessionlatency/

# Tests that need Docker or root.
test-integration: test-e2e test-bpf

# Benchmarks; compare runs with benchstat.
bench:
	go test -run='^$$' -bench=. -benchmem -benchtime=$(BENCHTIME) -count=$(BENCH_COUNT) ./... | tee bench.txt

# Known vulnerabilities reachable from the code.
vuln:
	$(GOVULNCHECK) ./...

# Regenerate the eBPF objects and bindings with the bpf2go version pinned in
# ebpf/sessionlatency/generate.go. Needs clang, llvm-strip and libbpf headers.
generate-bpf:
	go generate ./ebpf/...

# Rank the most complex functions with cccc (https://github.com/moznion/cccc);
# what is analyzed is configured in cccc.toml.
complexity:
	cccc --table --top-cognitive 20 .

clean:
	rm -f $(BINARY) bench.txt

install:
	GOOS=$(GOOS) go install .

test-e2e:
	go test -tags e2e -v -count=1 -timeout 120s ./e2e/

test-e2e-rocky:
	go test -tags e2e_rocky -v -count=1 -timeout 30m ./e2e/lima/
