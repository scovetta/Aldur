#!/bin/bash
# Build script for creating distribution binaries
# Usage: ./scripts/build-release.sh [target]
# If no target specified, builds for all supported platforms

set -e

VERSION=$(grep '^version' ../Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
DIST_DIR="../dist"
BINARY_NAME="aldur"

# Create dist directory
mkdir -p "$DIST_DIR"

build_target() {
    local target=$1
    local extension=""
    local archive_ext="tar.gz"

    case "$target" in
        *windows*)
            extension=".exe"
            archive_ext="zip"
            ;;
    esac

    echo "========================================="
    echo "Building for: $target"
    echo "========================================="

    cargo build --release --target "$target"

    # Create archive
    local binary_path="target/$target/release/${BINARY_NAME}${extension}"
    local archive_name="${BINARY_NAME}-${VERSION}-${target}"

    if [ -f "$binary_path" ]; then
        local staging_dir="$DIST_DIR/$archive_name"
        mkdir -p "$staging_dir"

        # Copy binary
        cp "$binary_path" "$staging_dir/"

        # Copy documentation
        cp ../README.md "$staging_dir/" 2>/dev/null || true
        cp ../LICENSE "$staging_dir/" 2>/dev/null || true

        # Create archive
        cd "$DIST_DIR"
        if [ "$archive_ext" = "zip" ]; then
            zip -r "${archive_name}.zip" "$archive_name"
        else
            tar -czf "${archive_name}.tar.gz" "$archive_name"
        fi
        rm -rf "$archive_name"
        cd - > /dev/null

        echo "✅ Created: $DIST_DIR/${archive_name}.${archive_ext}"
    else
        echo "❌ Build failed for $target: binary not found"
        return 1
    fi
}

# Supported targets for cross-compilation from Linux
LINUX_TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
)

# macOS targets (require native macOS or osxcross)
MACOS_TARGETS=(
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
)

if [ -n "$1" ]; then
    # Build specific target
    build_target "$1"
else
    # Build all Linux-crossable targets
    echo "Building distribution binaries..."
    echo "Version: $VERSION"
    echo ""

    for target in "${LINUX_TARGETS[@]}"; do
        build_target "$target" || echo "Skipping $target due to error"
        echo ""
    done

    echo "========================================="
    echo "Build Summary"
    echo "========================================="
    echo "Distribution files created in: $DIST_DIR"
    ls -la "$DIST_DIR"/*.{tar.gz,zip} 2>/dev/null || echo "No archives created"

    echo ""
    echo "Note: macOS targets require native macOS or osxcross toolchain."
    echo "These are best built via GitHub Actions on macOS runners."
fi
