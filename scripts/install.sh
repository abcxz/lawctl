#!/bin/sh
# Lawctl installer — one command to get started.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/abcxz/lawctl/main/scripts/install.sh | sh
#
# What this does:
#   1. Detects your OS and architecture
#   2. Downloads the latest lawctl binary
#   3. Puts it in /usr/local/bin (or ~/.local/bin if no sudo)
#   4. Tells you what to do next

set -e

# ── Config ──
REPO="abcxz/lawctl"
BINARY_NAME="lawctl"
HOOK_NAME="lawctl-hook"
SHIM_NAME="lawctl-shim"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info() { printf "  ${BLUE}i${NC} %s\n" "$1"; }
ok() { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
err() { printf "  ${RED}✗${NC} %s\n" "$1" >&2; }
bold() { printf "${BOLD}%s${NC}" "$1"; }

# ── Detect OS and arch ──
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin) OS="apple-darwin" ;;
        Linux)  OS="unknown-linux-gnu" ;;
        *)      err "Unsupported OS: $OS"; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64)  ARCH="x86_64" ;;
        aarch64) ARCH="aarch64" ;;
        arm64)   ARCH="aarch64" ;;
        *)       err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    PLATFORM="${ARCH}-${OS}"
}

# ── Find install location ──
find_install_dir() {
    if [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    elif [ -d "$HOME/.local/bin" ]; then
        INSTALL_DIR="$HOME/.local/bin"
    else
        mkdir -p "$HOME/.local/bin"
        INSTALL_DIR="$HOME/.local/bin"
    fi
}

# ── Get latest release tag ──
get_latest_version() {
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"//;s/".*//')

    if [ -z "$VERSION" ]; then
        err "Failed to fetch latest version from GitHub"
        exit 1
    fi
}

# ── Download and install ──
install_binary() {
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/lawctl-$VERSION-$PLATFORM.tar.gz"

    info "Downloading lawctl $VERSION for $PLATFORM..."

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/lawctl.tar.gz" 2>/dev/null; then
        # If pre-built binary not available, try building from source
        err "Pre-built binary not available for $PLATFORM"
        info "You can install from source instead:"
        echo ""
        echo "  cargo install --git https://github.com/$REPO"
        echo ""
        exit 1
    fi

    tar -xzf "$TMPDIR/lawctl.tar.gz" -C "$TMPDIR"

    # Install all binaries
    for BIN in "$BINARY_NAME" "$HOOK_NAME" "$SHIM_NAME"; do
        if [ -f "$TMPDIR/$BIN" ]; then
            mv "$TMPDIR/$BIN" "$INSTALL_DIR/$BIN"
            chmod +x "$INSTALL_DIR/$BIN"
            ok "Installed $(bold "$BIN") to $INSTALL_DIR/"
        fi
    done
}

# ── Check PATH ──
check_path() {
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            echo ""
            info "Add this to your shell profile:"
            echo ""
            echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
            echo ""
            ;;
    esac
}

# ── Main ──
main() {
    echo ""
    printf "  ${BOLD}lawctl${NC} installer\n"
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    detect_platform
    find_install_dir
    get_latest_version
    install_binary
    check_path

    echo ""
    printf "  ${GREEN}${BOLD}Done!${NC} Now go to your project and run:\n"
    echo ""
    printf "    ${BOLD}cd your-project${NC}\n"
    printf "    ${BOLD}lawctl${NC}\n"
    echo ""
}

main
