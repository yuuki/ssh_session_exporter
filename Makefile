BINARY  := ssh_session_exporter
MODULE  := github.com/yuuki/ssh_session_exporter
GOOS    := linux
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet complexity clean install test-e2e test-e2e-rocky

build:
	GOOS=$(GOOS) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

vet:
	GOOS=linux go vet ./...

# Rank the most complex functions with cccc (https://github.com/moznion/cccc)
# and, like CI, fail when one exceeds max-cognitive in cccc.toml.
complexity:
	cccc --table --top-cognitive 20 .

clean:
	rm -f $(BINARY)

install:
	GOOS=$(GOOS) go install .

test-e2e:
	go test -tags e2e -v -count=1 -timeout 120s ./e2e/

test-e2e-rocky:
	go test -tags e2e_rocky -v -count=1 -timeout 30m ./e2e/lima/
