# ─── Cipher Client-Core Mobile Build ───
#
# Usage:
#   make android    — Build for all Android ABIs
#   make ios        — Build universal iOS static lib
#   make all        — Build both
#   make clean      — Remove build artifacts
#
# Prerequisites:
#   Android: cargo install cargo-ndk, NDK r25+ in ANDROID_NDK_HOME
#   iOS:     cargo install cargo-lipo, Xcode + iOS SDK
#   Both:    rustup target add [targets below]

RUST_LIB_NAME = libclient_core

# ─── Android ─────────────────────────────────────────────
ANDROID_TARGETS = \
	aarch64-linux-android \
	armv7-linux-androideabi \
	x86_64-linux-android \
	i686-linux-android

ANDROID_OUT = ../cipher_app/android/app/src/main/jniLibs

.PHONY: android-setup
android-setup:
	rustup target add $(ANDROID_TARGETS)
	cargo install cargo-ndk

.PHONY: android
android:
	@echo "🤖 Building for Android..."
	cargo ndk \
		-t arm64-v8a \
		-o $(ANDROID_OUT) \
		build --release
	@echo "✅ Android libs in $(ANDROID_OUT)"

# ─── iOS ─────────────────────────────────────────────────
IOS_TARGETS = aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
IOS_OUT = ../cipher_app/ios/Runner

.PHONY: ios-setup
ios-setup:
	rustup target add $(IOS_TARGETS)
	cargo install cargo-lipo

.PHONY: ios
ios:
	@echo "🍎 Building for iOS..."
	cargo lipo --release
	@mkdir -p $(IOS_OUT)
	cp target/universal/release/$(RUST_LIB_NAME).a $(IOS_OUT)/
	@echo "✅ iOS lib in $(IOS_OUT)/$(RUST_LIB_NAME).a"

# ─── macOS (for desktop testing) ─────────────────────────
.PHONY: macos
macos:
	@echo "💻 Building for macOS..."
	cargo build --release
	@echo "✅ macOS lib in target/release/"

# ─── All ─────────────────────────────────────────────────
.PHONY: all
all: android ios

.PHONY: setup
setup: android-setup ios-setup

.PHONY: test
test:
	cargo test

.PHONY: clean
clean:
	cargo clean
	rm -rf $(ANDROID_OUT)/*/$(RUST_LIB_NAME).so
	rm -f $(IOS_OUT)/$(RUST_LIB_NAME).a
