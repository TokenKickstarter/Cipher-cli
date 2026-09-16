# ═══════════════════════════════════════════════════════════
#  Cipher CLI — Release Build Makefile
#  Build for: macOS, Linux, Windows, Android
# ═══════════════════════════════════════════════════════════

VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
DIST := releases/v$(VERSION)
BINARY := cipher-cli

.PHONY: all clean release macos linux windows android help

help: ## Show this help
	@echo "  ⚔️  Cipher CLI v$(VERSION) — Build Targets"
	@echo ""
	@echo "  make release        Build release for current platform"
	@echo "  make macos          Build for macOS (ARM64 + x64 universal)"
	@echo "  make linux          Build for Linux x86_64"
	@echo "  make windows        Build for Windows x86_64"
	@echo "  make android        Build for Android ARM64"
	@echo "  make all            Build all platforms (requires cross)"
	@echo "  make install        Install to /usr/local/bin"
	@echo "  make checksums      Generate SHA256 checksums"
	@echo "  make clean          Remove build artifacts"

# ── Current Platform Release ──────────────────────────────

release: ## Build optimized release for current platform
	cargo build --release
	@echo ""
	@echo "  ✅ Release binary: target/release/$(BINARY)"
	@ls -lh target/release/$(BINARY)

install: release ## Install to /usr/local/bin
	sudo cp target/release/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "  ✅ Installed: /usr/local/bin/$(BINARY)"
	@cipher-cli --version

# ── macOS ─────────────────────────────────────────────────

macos: macos-arm64 macos-x64 ## Build for macOS (both architectures)
	@echo "  ✅ macOS builds complete"

macos-arm64: ## Build for macOS Apple Silicon
	rustup target add aarch64-apple-darwin 2>/dev/null || true
	cargo build --release --target aarch64-apple-darwin
	mkdir -p $(DIST)
	cp target/aarch64-apple-darwin/release/$(BINARY) $(DIST)/$(BINARY)-macos-arm64
	cd $(DIST) && tar czf $(BINARY)-macos-arm64.tar.gz $(BINARY)-macos-arm64
	@echo "  ✅ $(DIST)/$(BINARY)-macos-arm64.tar.gz"

macos-x64: ## Build for macOS Intel
	rustup target add x86_64-apple-darwin 2>/dev/null || true
	cargo build --release --target x86_64-apple-darwin
	mkdir -p $(DIST)
	cp target/x86_64-apple-darwin/release/$(BINARY) $(DIST)/$(BINARY)-macos-x64
	cd $(DIST) && tar czf $(BINARY)-macos-x64.tar.gz $(BINARY)-macos-x64
	@echo "  ✅ $(DIST)/$(BINARY)-macos-x64.tar.gz"

# ── Linux ─────────────────────────────────────────────────

linux: linux-x64 ## Build for Linux x86_64
	@echo "  ✅ Linux build complete"

linux-x64: ## Build for Linux x86_64 (requires cross or Docker)
	@which cross > /dev/null 2>&1 || (echo "  Install cross: cargo install cross" && exit 1)
	cross build --release --target x86_64-unknown-linux-gnu
	mkdir -p $(DIST)
	cp target/x86_64-unknown-linux-gnu/release/$(BINARY) $(DIST)/$(BINARY)-linux-x64
	cd $(DIST) && tar czf $(BINARY)-linux-x64.tar.gz $(BINARY)-linux-x64
	@echo "  ✅ $(DIST)/$(BINARY)-linux-x64.tar.gz"

linux-arm64: ## Build for Linux ARM64 (requires cross)
	@which cross > /dev/null 2>&1 || (echo "  Install cross: cargo install cross" && exit 1)
	cross build --release --target aarch64-unknown-linux-gnu
	mkdir -p $(DIST)
	cp target/aarch64-unknown-linux-gnu/release/$(BINARY) $(DIST)/$(BINARY)-linux-arm64
	cd $(DIST) && tar czf $(BINARY)-linux-arm64.tar.gz $(BINARY)-linux-arm64
	@echo "  ✅ $(DIST)/$(BINARY)-linux-arm64.tar.gz"

# ── Windows ───────────────────────────────────────────────

windows: windows-x64 ## Build for Windows x86_64
	@echo "  ✅ Windows build complete"

windows-x64: ## Build for Windows x86_64 (requires cross)
	@which cross > /dev/null 2>&1 || (echo "  Install cross: cargo install cross" && exit 1)
	cross build --release --target x86_64-pc-windows-gnu
	mkdir -p $(DIST)
	cp target/x86_64-pc-windows-gnu/release/$(BINARY).exe $(DIST)/$(BINARY)-windows-x64.exe
	cd $(DIST) && zip $(BINARY)-windows-x64.zip $(BINARY)-windows-x64.exe
	@echo "  ✅ $(DIST)/$(BINARY)-windows-x64.zip"

# ── Android ───────────────────────────────────────────────

android: android-arm64 ## Build for Android ARM64
	@echo "  ✅ Android build complete"

android-arm64: ## Build for Android ARM64 (requires cross + NDK)
	@which cross > /dev/null 2>&1 || (echo "  Install cross: cargo install cross" && exit 1)
	cross build --release --target aarch64-linux-android
	mkdir -p $(DIST)
	cp target/aarch64-linux-android/release/$(BINARY) $(DIST)/$(BINARY)-android-arm64
	cd $(DIST) && tar czf $(BINARY)-android-arm64.tar.gz $(BINARY)-android-arm64
	@echo "  ✅ $(DIST)/$(BINARY)-android-arm64.tar.gz"

# ── All Platforms ─────────────────────────────────────────

all: macos linux linux-arm64 windows android checksums ## Build for all platforms
	@echo ""
	@echo "  ✅ All platforms built!"
	@ls -lh $(DIST)/

# ── Checksums ─────────────────────────────────────────────

checksums: ## Generate SHA256 checksums
	cd $(DIST) && shasum -a 256 *.tar.gz *.zip 2>/dev/null > SHA256SUMS.txt || true
	@echo "  ✅ $(DIST)/SHA256SUMS.txt"
	@cat $(DIST)/SHA256SUMS.txt 2>/dev/null || true

# ── Clean ─────────────────────────────────────────────────

clean: ## Remove build artifacts
	cargo clean
	rm -rf releases/
	@echo "  ✅ Cleaned"
