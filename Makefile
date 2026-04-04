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