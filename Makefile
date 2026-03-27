BINARY := ssh_session_exporter
MODULE := github.com/yuuki/ssh_sesshon_exporter
GOOS   := linux

.PHONY: build test lint clean install

build:
	GOOS=$(GOOS) go build -o $(BINARY) ./cmd/ssh_session_exporter

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)

install:
	GOOS=$(GOOS) go install ./cmd/ssh_session_exporter
