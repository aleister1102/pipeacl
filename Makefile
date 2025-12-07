BINARY_NAME=pipeacl
BIN_DIR=bin
BUILD_DIR=dist
INSTALL_PATH=$(HOME)/.local/bin
VERSION=$(shell grep '^version' Cargo.toml | head -1 | cut -d '"' -f 2)
TARGETS=x86_64-pc-windows-gnu x86_64-pc-windows-msvc

.DEFAULT_GOAL := help

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build binary for current platform"
	@echo "  clean       Remove build artifacts"
	@echo "  test        Run tests"
	@echo "  install     Build and install to $(INSTALL_PATH)"
	@echo "  uninstall   Remove from $(INSTALL_PATH)"
	@echo "  release     Release new version (usage: make release TAG=v1.0.0)"
	@echo "  bump-patch  Release next patch version"
	@echo "  bump-minor  Release next minor version"
	@echo "  bump-major  Release next major version"

build:
	mkdir -p $(BIN_DIR)
	cargo build --release
	cp target/release/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME) 2>/dev/null || cp target/release/$(BINARY_NAME).exe $(BIN_DIR)/$(BINARY_NAME).exe 2>/dev/null || true

clean:
	rm -rf $(BIN_DIR)
	rm -rf $(BUILD_DIR)
	cargo clean

test:
	cargo test

install: build
	mkdir -p $(INSTALL_PATH)
	cp $(BIN_DIR)/$(BINARY_NAME)* $(INSTALL_PATH)/
	@echo "Installed $(BINARY_NAME) to $(INSTALL_PATH)"

uninstall:
	rm -f $(INSTALL_PATH)/$(BINARY_NAME)*
	@echo "Removed $(BINARY_NAME) from $(INSTALL_PATH)"

release: ## Release new version (usage: make release TAG=v1.0.0)
	@if [ -z "$(TAG)" ]; then echo "Usage: make release TAG=v1.0.0"; exit 1; fi
	@echo "Releasing $(TAG)..."
	@cargo test 2>/dev/null || true
	@rm -rf $(BUILD_DIR) && mkdir -p $(BUILD_DIR)
	@echo "Building binaries..."
	@for target in $(TARGETS); do \
		echo "Building for $$target..."; \
		cargo build --release --target $$target 2>/dev/null || cross build --release --target $$target 2>/dev/null || { echo "  Skipping $$target"; continue; }; \
		if [ -f "target/$$target/release/$(BINARY_NAME).exe" ]; then \
			cp "target/$$target/release/$(BINARY_NAME).exe" "$(BUILD_DIR)/$(BINARY_NAME)-$$target.exe"; \
		fi; \
	done
	@cd $(BUILD_DIR) && shasum -a 256 * > checksums.txt 2>/dev/null || true
	@echo "Creating GitHub release..."
	@git tag -a $(TAG) -m "Release $(TAG)"
	@git push origin $(TAG)
	@gh release create $(TAG) $(BUILD_DIR)/* --title "$(BINARY_NAME) $(TAG)" --generate-notes
	@rm -rf $(BUILD_DIR)
	@echo "Done: $(TAG)"

bump-patch: ## Release next patch version
	@CURRENT=$$(grep '^version' Cargo.toml | head -1 | cut -d '"' -f 2); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT | cut -d. -f3); \
	NEW="$$MAJOR.$$MINOR.$$((PATCH + 1))"; \
	if [ "$$(uname)" = "Darwin" ]; then \
		sed -i '' 's/^version = ".*"/version = "'$$NEW'"/' Cargo.toml; \
	else \
		sed -i 's/^version = ".*"/version = "'$$NEW'"/' Cargo.toml; \
	fi; \
	echo "Bumped to $$NEW"; \
	$(MAKE) release TAG=v$$NEW

bump-minor: ## Release next minor version
	@CURRENT=$$(grep '^version' Cargo.toml | head -1 | cut -d '"' -f 2); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	NEW="$$MAJOR.$$((MINOR + 1)).0"; \
	if [ "$$(uname)" = "Darwin" ]; then \
		sed -i '' 's/^version = ".*"/version = "'$$NEW'"/' Cargo.toml; \
	else \
		sed -i 's/^version = ".*"/version = "'$$NEW'"/' Cargo.toml; \
	fi; \
	echo "Bumped to $$NEW"; \
	$(MAKE) release TAG=v$$NEW

bump-major: ## Release next major version
	@CURRENT=$$(grep '^version' Cargo.toml | head -1 | cut -d '"' -f 2); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	NEW="$$((MAJOR + 1)).0.0"; \
	if [ "$$(uname)" = "Darwin" ]; then \
		sed -i '' 's/^version = ".*"/version = "'$$NEW'"/' Cargo.toml; \
	else \
		sed -i 's/^version = ".*"/version = "'$$NEW'"/' Cargo.toml; \
	fi; \
	echo "Bumped to $$NEW"; \
	$(MAKE) release TAG=v$$NEW

