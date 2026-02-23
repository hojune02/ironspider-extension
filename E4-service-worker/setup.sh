#!/usr/bin/env bash
# setup.sh — One-time setup for IronSpider Resurrection Testbed
# Installs local CA and generates HTTPS certificate (required for Service Workers)

set -euo pipefail

echo "─────────────────────────────────────────────────────────"
echo "  IronSpider Resurrection Testbed — Setup"
echo "─────────────────────────────────────────────────────────"

# ── Check dependencies ─────────────────────────────────────────────────────
if ! command -v mkcert &>/dev/null; then
  echo "[ERROR] mkcert not found."
  echo "        Install: yay -S mkcert  (Arch)  or  brew install mkcert  (macOS)"
  exit 1
fi

if ! command -v node &>/dev/null; then
  echo "[ERROR] node not found."
  echo "        Install: yay -S nodejs  or  https://nodejs.org/"
  exit 1
fi

echo "[*] mkcert version: $(mkcert -version 2>&1)"
echo "[*] node version:   $(node --version)"

# ── Install local CA (first time only, may prompt for sudo) ───────────────
echo ""
echo "[*] Installing mkcert local CA (may prompt for sudo)..."
mkcert -install

# ── Generate certificate ───────────────────────────────────────────────────
echo ""
echo "[*] Generating TLS certificate for localhost..."
mkdir -p certs
mkcert \
  -cert-file certs/localhost.pem \
  -key-file  certs/localhost-key.pem \
  localhost 127.0.0.1 ::1

echo ""
echo "─────────────────────────────────────────────────────────"
echo "  Setup complete."
echo ""
echo "  Start the server:"
echo "    node server.js"
echo ""
echo "  Then open:"
echo "    https://localhost:8443/"
echo "─────────────────────────────────────────────────────────"
