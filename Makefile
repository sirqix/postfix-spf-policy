# postfix-spf-policy Makefile

BINARY = postfix-spf-policy
# Extract version from version.go (single source of truth)
VERSION = $(shell grep 'const Version' cmd/postfix-spf-policy/version.go | sed 's/.*"\(.*\)"/\1/')
BUILD_DATE = $(shell date '+%Y-%m-%d %H:%M:%S %Z')

# Default config file path (used by binary and systemd service)
DEFAULT_CONFIG = /etc/postfix/postfix-spf-policy.conf

.PHONY: all build clean test install check-updates vendor help

all: build

# Build the binary using vendored dependencies
build:
	@echo "Building $(BINARY) v$(VERSION) (static binary, vendored deps)..."
	CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w -X 'main.buildDate=$(BUILD_DATE)' -X 'main.defaultConfig=$(DEFAULT_CONFIG)'" -o $(BINARY) ./cmd/postfix-spf-policy
	@ls -lh $(BINARY)
	@file $(BINARY)
	@echo ""
	@echo "Build successful!"

# Clean build artifacts
clean:
	rm -f $(BINARY)
	rm -f $(BINARY)-installer.run

# Run tests
test:
	go test -mod=vendor -v ./...

# Run integration tests (requires network)
test-integration:
	go test -mod=vendor -v -tags=integration ./...

# Check if upstream dependencies have newer versions available
check-updates:
	@echo "Checking for upstream dependency updates..."
	@echo ""
	@echo "Current vendored versions:"
	@cat vendor/modules.txt | grep "^#" | grep -v "##"
	@echo ""
	@echo "Latest available versions:"
	@echo ""
	@for mod in $$(cat vendor/modules.txt | grep "^#" | grep -v "##" | awk '{print $$2}'); do \
		latest=$$(go list -m -versions $$mod 2>/dev/null | awk '{print $$NF}'); \
		current=$$(grep "$$mod" vendor/modules.txt | head -1 | awk '{print $$3}'); \
		if [ "$$latest" != "$$current" ] && [ -n "$$latest" ]; then \
			echo "  $$mod: $$current -> $$latest (UPDATE AVAILABLE)"; \
		else \
			echo "  $$mod: $$current (up to date)"; \
		fi \
	done
	@echo ""

# Update a specific dependency (usage: make update-dep DEP=blitiri.com.ar/go/spf)
update-dep:
	@if [ -z "$(DEP)" ]; then \
		echo "Usage: make update-dep DEP=package/path"; \
		exit 1; \
	fi
	go get -u $(DEP)
	go mod tidy
	go mod vendor
	@echo "Updated $(DEP) and re-vendored"

# Update all dependencies to latest versions
update-all:
	@echo "Updating all dependencies to latest versions..."
	go get -u ./...
	go mod tidy
	go mod vendor
	@echo "All dependencies updated and re-vendored"

# Re-vendor current dependencies (after manual go.mod changes)
vendor:
	go mod vendor
	@echo "Dependencies vendored"

# Build the installer package
installer: build
	cp $(BINARY) installer-pkg/
	cp examples/postfix-spf-policy.conf installer-pkg/
	@# Generate systemd service file with correct config path
	@sed 's|__DEFAULT_CONFIG__|$(DEFAULT_CONFIG)|g' installer-pkg/postfix-spf-policy.service.in > installer-pkg/postfix-spf-policy.service
	makeself --notemp installer-pkg $(BINARY)-installer.run "$(BINARY) installer" ./install.sh
	rm -f installer-pkg/$(BINARY) installer-pkg/postfix-spf-policy.conf installer-pkg/postfix-spf-policy.service
	@echo ""
	@echo "Installer created: $(BINARY)-installer.run"

# Show vendored module info
info:
	@echo "$(BINARY) v$(VERSION)"
	@echo ""
	@echo "Vendored dependencies:"
	@cat vendor/modules.txt

# Help
help:
	@echo "postfix-spf-policy Makefile targets:"
	@echo ""
	@echo "  build          Build the binary (default)"
	@echo "  clean          Remove build artifacts"
	@echo "  test           Run tests"
	@echo "  check-updates  Check if upstream deps have new versions"
	@echo "  update-dep     Update specific dep (DEP=path/to/pkg)"
	@echo "  update-all     Update all deps to latest"
	@echo "  vendor         Re-vendor current dependencies"
	@echo "  installer      Build the installer package"
	@echo "  info           Show version and vendored deps"
	@echo "  help           Show this help"
