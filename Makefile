BINARY  := scanner
BUILD   := build
CMD		:= .

GOFLAGS := -trimpath
LDFLAGS := -ldflags="-s -w"

build:
	@mkdir -p $(BUILD)
	go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD)/$(BINARY) $(CMD)

run:
	go run $(CMD)

test:
	go test ./... -v -race -count=1

install-proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest