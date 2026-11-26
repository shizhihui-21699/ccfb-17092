.PHONY: build test race cover vet fmt clean

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -cover ./internal/...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -f rpcrecon rpcrecon-testserver
