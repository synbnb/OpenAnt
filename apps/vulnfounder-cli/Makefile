BINARY_NAME=vulnfounder
LEGACY_BINARY_NAME=openant
BUILD_DIR=bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd.version=$(VERSION)"

.PHONY: build build-legacy clean test lint install

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./main.go

# Compatibility binary for existing automation. New integrations should use
# `vulnfounder`; this alias can be removed in a future major release.
build-legacy: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(BUILD_DIR)/$(LEGACY_BINARY_NAME)

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

lint:
	go vet ./...

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
