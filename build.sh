#!/bin/bash
set -e

APP_NAME="socks5-udp-checker"
ALT_NAME="socks-over-udp"

# Version info
VERSION=$(git describe --tags --always 2>/dev/null || echo "1.0.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE} -X main.builtBy=build.sh"

echo "🚀 Building ${APP_NAME} (${VERSION}, commit: ${COMMIT})..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf dist/
mkdir -p dist/

# If goreleaser is installed, use it; otherwise cross-compile natively with go build
if command -v goreleaser >/dev/null 2>&1 && [ -f ".goreleaser.yaml" ]; then
    echo "📦 Running GoReleaser build..."
    goreleaser build --snapshot --clean
else
    echo "📦 Cross-compiling for multiple platforms using Go..."

    PLATFORMS=(
        "linux/amd64"
        "linux/arm64"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
        "windows/arm64"
    )

    for PLATFORM in "${PLATFORMS[@]}"; do
        GOOS=${PLATFORM%/*}
        GOARCH=${PLATFORM#*/}
        OUTPUT_DIR="dist/${APP_NAME}_${GOOS}_${GOARCH}"
        OUTPUT_NAME="${APP_NAME}"

        if [ "${GOOS}" = "windows" ]; then
            OUTPUT_NAME="${APP_NAME}.exe"
        fi

        mkdir -p "${OUTPUT_DIR}"
        echo "  • Building ${GOOS}/${GOARCH}..."
        CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -ldflags "${LDFLAGS}" -o "${OUTPUT_DIR}/${OUTPUT_NAME}" ./cmd
    done
fi

# Build local binary for immediate use
echo "🔨 Building local executable for current system..."
go build -trimpath -ldflags "${LDFLAGS}" -o "${APP_NAME}" ./cmd

echo ""
echo "✅ Build completed! Generated binaries:"
find dist/ -type f \( -name "${APP_NAME}" -o -name "${APP_NAME}.exe" \) -exec ls -lh {} \;

echo ""
echo "📁 Binaries are located in the dist/ directory:"
echo "  • Linux (amd64):         dist/${APP_NAME}_linux_amd64/${APP_NAME}"
echo "  • Linux (arm64):         dist/${APP_NAME}_linux_arm64/${APP_NAME}"
echo "  • macOS (Intel):         dist/${APP_NAME}_darwin_amd64/${APP_NAME}"
echo "  • macOS (Apple Silicon): dist/${APP_NAME}_darwin_arm64/${APP_NAME}"
echo "  • Windows (amd64):       dist/${APP_NAME}_windows_amd64/${APP_NAME}.exe"
echo "  • Windows (arm64):       dist/${APP_NAME}_windows_arm64/${APP_NAME}.exe"
echo "  • Local binary:          ./${APP_NAME} (and ./${ALT_NAME})"
echo ""
echo "🎉 Ready to distribute!"
