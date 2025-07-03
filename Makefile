#!/bin/make
GOROOT:=$(shell PATH="/pkg/main/dev-lang.go.dev/bin:$$PATH" go env GOROOT)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

.PHONY: test deps

all:
	$(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build -v

deps:
	$(GOROOT)/bin/go get -v -t .

test:
	$(GOROOT)/bin/go test -v -race ./...

test-coverage:
	$(GOROOT)/bin/go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOROOT)/bin/go tool cover -html=coverage.out -o coverage.html

benchmark:
	$(GOROOT)/bin/go test -bench=. -benchmem -run=^$$ ./...

test-short:
	$(GOROOT)/bin/go test -short -v ./...

clean-test:
	rm -f coverage.out coverage.html
