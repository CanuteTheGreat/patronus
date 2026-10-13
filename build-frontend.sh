#!/bin/bash
# Patronus SD-WAN - Enterprise Dashboard Frontend Build Script
# Purpose: Build the frontend/ React+Vite UI and stage it into ./static,
#          which docker-compose.ha.yml bind-mounts read-only into each
#          patronus-dashboard container (volumes: ./static:/app/static:ro).
#          patronus-dashboard's own main.rs serves static/index.html and
#          static/assets/* directly -- this script is what must run on the
#          HOST before `docker-compose -f docker-compose.ha.yml up`.
#
# This frontend is the UI for the OPTIONAL multi-site SD-WAN enterprise
# dashboard (patronus-dashboard crate / docker-compose.ha.yml). It is NOT
# used by the default single-node patronus-web image (root Dockerfile),
# which correctly excludes frontend/ from its own build.
#
# Usage: ./build-frontend.sh

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$PROJECT_DIR/frontend"
STATIC_DIR="$PROJECT_DIR/static"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Patronus SD-WAN Dashboard - Frontend Build Script       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

if [ ! -d "$FRONTEND_DIR" ]; then
    echo "❌ frontend/ directory not found at $FRONTEND_DIR"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "❌ npm not found. Install Node.js (>=18) before running this script."
    exit 1
fi

echo "📋 Node: $(node --version 2>/dev/null || echo 'unknown')"
echo "📋 npm:  $(npm --version)"
echo ""

cd "$FRONTEND_DIR"

# Idempotent dependency install: prefer `npm ci` (fast, reproducible,
# requires package-lock.json to be in sync with package.json) and fall
# back to `npm install` if the lockfile is stale/missing, instead of
# failing outright.
echo "📦 Installing frontend dependencies..."
if [ -f package-lock.json ]; then
    if npm ci; then
        echo "  ✅ Installed via npm ci"
    else
        echo "  ⚠️  npm ci failed (lockfile likely out of sync) -- falling back to npm install"
        npm install
        echo "  ✅ Installed via npm install"
    fi
else
    echo "  ⚠️  No package-lock.json found -- running npm install"
    npm install
    echo "  ✅ Installed via npm install"
fi
echo ""

# Build (tsc type-check + vite build). vite.config.ts's build.outDir points
# directly at ../static so the build output lands at the repo root without
# a separate copy step.
echo "🔨 Building frontend (tsc + vite build)..."
npm run build
echo ""

if [ ! -f "$STATIC_DIR/index.html" ]; then
    echo "❌ Build did not produce $STATIC_DIR/index.html -- check vite.config.ts build.outDir"
    exit 1
fi

if [ ! -d "$STATIC_DIR/assets" ] || [ -z "$(ls -A "$STATIC_DIR/assets" 2>/dev/null)" ]; then
    echo "❌ Build did not produce any files in $STATIC_DIR/assets"
    exit 1
fi

ASSET_COUNT=$(find "$STATIC_DIR/assets" -type f | wc -l | tr -d ' ')
STATIC_SIZE=$(du -sh "$STATIC_DIR" 2>/dev/null | cut -f1)

echo "✅ Frontend built successfully"
echo "   Output:      $STATIC_DIR"
echo "   index.html:  present"
echo "   assets:      $ASSET_COUNT file(s)"
echo "   total size:  $STATIC_SIZE"
echo ""
echo "Next step: docker-compose -f docker-compose.ha.yml up"
