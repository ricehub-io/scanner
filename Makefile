BINARY  := scanner
BUILD   := build
CMD		:= .

GOFLAGS := -trimpath
LDFLAGS := -ldflags="-s -w"

.PHONY: build run check test fmt lint security

build:
	@mkdir -p $(BUILD)
	go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD)/$(BINARY) $(CMD)

run:
	go run $(CMD)

check: fmt lint security test

test:
	go test ./... -v -race -count=1

fmt:
	goimports -l .

lint:
	golangci-lint run ./...

security:
	govulncheck ./...

install-tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest