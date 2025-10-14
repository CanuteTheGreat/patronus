#!/bin/bash
# Build script for Patronus Dashboard frontend

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
STATIC_DIR="$SCRIPT_DIR/static"

echo "Building Patronus Dashboard frontend..."
echo "Frontend directory: $FRONTEND_DIR"
echo "Static directory: $STATIC_DIR"

# Check if frontend directory exists
if [ ! -d "$FRONTEND_DIR" ]; then
    echo "Error: Frontend directory not found at $FRONTEND_DIR"
    exit 1
fi

# Navigate to frontend directory
cd "$FRONTEND_DIR"

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Build the frontend
echo "Building React application..."
npm run build

# Verify build output
if [ ! -d "../static" ]; then
    echo "Error: Build output directory not found"
    exit 1
fi

echo "Frontend build complete!"
echo "Static files are in: $STATIC_DIR"

# List generated files
echo ""
echo "Generated files:"
ls -lh "$STATIC_DIR"

exit 0
