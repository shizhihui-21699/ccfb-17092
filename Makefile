BINARY := grpcscope
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet race selftest fmt clean install

build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/grpcscope

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

selftest: build
	./$(BINARY) selftest

fmt:
	gofmt -w cmd internal

install:
	go install -ldflags '$(LDFLAGS)' ./cmd/grpcscope

clean:
	rm -f $(BINARY)
	rm -rf results
