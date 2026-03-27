BINARY := ssh_session_exporter
MODULE := github.com/yuuki/ssh_sesshon_exporter
GOOS   := linux

.PHONY: build test lint clean install test-e2e

build:
	GOOS=$(GOOS) go build -o $(BINARY) .

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)

install:
	GOOS=$(GOOS) go install .

test-e2e:
	docker compose -f e2e/docker-compose.e2e.yml build
	go test -tags e2e -v -count=1 -timeout 120s ./e2e/
	docker compose -f e2e/docker-compose.e2e.yml down -v
