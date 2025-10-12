#!/bin/bash
# Patronus SD-WAN - System Dependency Installation Script
# Version: v0.1.0-sprint30
# Purpose: Install system libraries required for full workspace build

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║    Patronus SD-WAN - Dependency Installation Script      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "❌ Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "📋 Detected OS: $OS"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ] && ! command -v sudo &> /dev/null; then
    echo "❌ This script requires sudo or root privileges"
    exit 1
fi

# Function to run commands with or without sudo
run_cmd() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

echo "🔍 Checking current environment..."
echo ""

# Check what's already installed
check_dependency() {
    local dep=$1
    if pkg-config --exists "$dep" 2>/dev/null; then
        local version=$(pkg-config --modversion "$dep")
        echo "  ✅ $dep: $version (already installed)"
        return 0
    else
        echo "  ❌ $dep: not found"
        return 1
    fi
}

# Check pkg-config itself
if command -v pkg-config &> /dev/null; then
    echo "  ✅ pkg-config: $(pkg-config --version) (already installed)"
    PKG_CONFIG_INSTALLED=true
else
    echo "  ❌ pkg-config: not found"
    PKG_CONFIG_INSTALLED=false
fi

# Check libraries
check_dependency "libnftnl" || LIBNFTNL_MISSING=true
check_dependency "libmnl" || LIBMNL_MISSING=true

echo ""

# Install based on OS
case "$OS" in
    ubuntu|debian)
        echo "📦 Installing dependencies for Ubuntu/Debian..."
        echo ""

        run_cmd apt-get update -qq

        PACKAGES=""
        [ "$PKG_CONFIG_INSTALLED" != "true" ] && PACKAGES="$PACKAGES pkg-config"
        [ "$LIBNFTNL_MISSING" = "true" ] && PACKAGES="$PACKAGES libnftnl-dev"
        [ "$LIBMNL_MISSING" = "true" ] && PACKAGES="$PACKAGES libmnl-dev"

        if [ -n "$PACKAGES" ]; then
            echo "Installing:$PACKAGES"
            run_cmd apt-get install -y $PACKAGES
        else
            echo "✅ All dependencies already installed!"
        fi

        # Optional but recommended
        echo ""
        echo "📦 Installing optional build dependencies..."
        run_cmd apt-get install -y libelf-dev zlib1g-dev 2>/dev/null || true
        ;;

    fedora|rhel|centos)
        echo "📦 Installing dependencies for RHEL/CentOS/Fedora..."
        echo ""

        PACKAGES=""
        [ "$PKG_CONFIG_INSTALLED" != "true" ] && PACKAGES="$PACKAGES pkgconfig"
        [ "$LIBNFTNL_MISSING" = "true" ] && PACKAGES="$PACKAGES libnftnl-devel"
        [ "$LIBMNL_MISSING" = "true" ] && PACKAGES="$PACKAGES libmnl-devel"

        if [ -n "$PACKAGES" ]; then
            run_cmd yum install -y $PACKAGES
        else
            echo "✅ All dependencies already installed!"
        fi

        # Optional but recommended
        echo ""
        echo "📦 Installing optional build dependencies..."
        run_cmd yum install -y elfutils-libelf-devel zlib-devel 2>/dev/null || true
        ;;

    alpine)
        echo "📦 Installing dependencies for Alpine Linux..."
        echo ""

        PACKAGES=""
        [ "$PKG_CONFIG_INSTALLED" != "true" ] && PACKAGES="$PACKAGES pkgconf"
        [ "$LIBNFTNL_MISSING" = "true" ] && PACKAGES="$PACKAGES libnftnl-dev"
        [ "$LIBMNL_MISSING" = "true" ] && PACKAGES="$PACKAGES libmnl-dev"

        if [ -n "$PACKAGES" ]; then
            run_cmd apk add $PACKAGES
        else
            echo "✅ All dependencies already installed!"
        fi

        # Optional but recommended
        echo ""
        echo "📦 Installing optional build dependencies..."
        run_cmd apk add elfutils-dev zlib-dev 2>/dev/null || true
        ;;

    *)
        echo "❌ Unsupported OS: $OS"
        echo ""
        echo "Please install the following packages manually:"
        echo "  - pkg-config (or pkgconf)"
        echo "  - libnftnl-dev (or libnftnl-devel)"
        echo "  - libmnl-dev (or libmnl-devel)"
        echo "  - libelf-dev (optional, for eBPF)"
        echo "  - zlib-dev (optional)"
        exit 1
        ;;
esac

echo ""
echo "✅ Verifying installation..."
echo ""

# Verify installation
if command -v pkg-config &> /dev/null; then
    echo "  ✅ pkg-config: $(pkg-config --version)"
else
    echo "  ❌ pkg-config: FAILED"
    exit 1
fi

if pkg-config --exists libnftnl 2>/dev/null; then
    echo "  ✅ libnftnl: $(pkg-config --modversion libnftnl)"
else
    echo "  ❌ libnftnl: FAILED"
    exit 1
fi

if pkg-config --exists libmnl 2>/dev/null; then
    echo "  ✅ libmnl: $(pkg-config --modversion libmnl)"
else
    echo "  ❌ libmnl: FAILED"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              ✅ INSTALLATION COMPLETE                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "You can now build the full workspace:"
echo ""
echo "  cargo build --workspace --all-features"
echo "  cargo test --workspace --all-features"
echo ""
echo "Or build specific packages:"
echo ""
echo "  cargo build -p patronus-dashboard"
echo "  cargo build -p patronus-ebpf"
echo ""
