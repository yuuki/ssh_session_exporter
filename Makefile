BINARY  := ssh_session_exporter
MODULE  := github.com/yuuki/ssh_session_exporter
GOOS    := linux
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet clean install test-e2e

build:
	GOOS=$(GOOS) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

vet:
	GOOS=linux go vet ./...

clean:
	rm -f $(BINARY)

install:
	GOOS=$(GOOS) go install .

test-e2e:
	go test -tags e2e -v -count=1 -timeout 120s ./e2e/
