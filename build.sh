#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/dist"
CADDY_VERSION="v2.11.4"
XCADDY_VERSION="v0.4.7"

# Read Go version from .tool-versions file
if [[ -f "${SCRIPT_DIR}/.tool-versions" ]]; then
    GO_VERSION=$(grep '^golang' "${SCRIPT_DIR}/.tool-versions" | awk '{print $2}')
    if [[ -z "$GO_VERSION" ]]; then
        echo "⚠️  Could not find golang version in .tool-versions, using default"
        GO_VERSION="1.21"
    fi
else
    GO_VERSION="${GO_VERSION:-1.21}"
fi

echo "🔧 Building Caddy binaries with Go ${GO_VERSION}..."

mkdir -p "$BUILD_DIR"

if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go $GO_VERSION or later."
    exit 1
fi

echo "📦 Installing xcaddy ${XCADDY_VERSION}..."
go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"
GO_BIN="$(go env GOBIN)"
if [[ -z "$GO_BIN" ]]; then
    GO_BIN="$(go env GOPATH)/bin"
fi
XCADDY="$GO_BIN/xcaddy"

# Build targets: goos goarch output_name
targets=(
    "linux amd64 caddy-linux-amd64"
    "linux arm64 caddy-linux-arm64"
    "darwin arm64 caddy-darwin-arm64"
)

for target in "${targets[@]}"; do
    read -r goos goarch output_name <<< "$target"
    output_path="$BUILD_DIR/$output_name"
    
    echo "🏗️  Building for $goos/$goarch -> $output_name"
    
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "$XCADDY" build "$CADDY_VERSION" \
        --with github.com/WeidiDeng/caddy-cloudflare-ip@f53b62aa13cb7ad79c8b47aacc3f2f03989b67e5 \
        --with github.com/fabriziosalmi/caddy-waf@v0.4.1 \
        --with github.com/darkweak/souin/plugins/caddy@v1.7.8 \
        --with github.com/darkweak/storages/simplefs/caddy@v0.0.19 \
        --with github.com/baldinof/caddy-supervisor@v0.7.0 \
        --output "$output_path"
    
    if [[ -f "$output_path" ]]; then
        file_size=$(du -h "$output_path" | cut -f1)
        echo "✅ Built $output_name ($file_size)"
    else
        echo "❌ Failed to build $output_name"
        exit 1
    fi
done

echo ""
echo "🎉 All binaries built successfully!"
echo "📁 Binaries are located in: $BUILD_DIR"
echo ""
ls -lah "$BUILD_DIR/"
