#!/bin/bash
# Create release artifacts for Patronus Firewall
# Usage: ./create-release.sh <version>

set -e

VERSION="${1:-0.1.0}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="$PROJECT_DIR/releases"

echo "Creating Patronus Firewall v$VERSION release artifacts..."
echo

# Create releases directory
mkdir -p "$RELEASE_DIR"

# Clean any previous builds
echo "Cleaning previous builds..."
rm -f "$RELEASE_DIR/patronus-$VERSION.tar.gz"
rm -f "$RELEASE_DIR/patronus-$VERSION.tar.gz.sha256"

# Create release tarball (excluding build artifacts and git)
echo "Creating release tarball..."
cd "$PROJECT_DIR"
tar --exclude='./target' \
    --exclude='./releases' \
    --exclude='./.git' \
    --exclude='./gentoo-overlay' \
    --exclude='*.log' \
    --exclude='*.db' \
    --exclude='*.sqlite' \
    -czf "$RELEASE_DIR/patronus-$VERSION.tar.gz" \
    --transform "s,^./,patronus-$VERSION/," \
    .

# Generate checksum
echo "Generating SHA256 checksum..."
cd "$RELEASE_DIR"
sha256sum "patronus-$VERSION.tar.gz" > "patronus-$VERSION.tar.gz.sha256"

# Show results
echo
echo "====================================="
echo "Release artifacts created successfully!"
echo "====================================="
echo "Version: $VERSION"
echo "Location: $RELEASE_DIR"
echo
echo "Files created:"
ls -lh "$RELEASE_DIR/patronus-$VERSION.tar.gz"
ls -lh "$RELEASE_DIR/patronus-$VERSION.tar.gz.sha256"
echo
echo "SHA256:"
cat "$RELEASE_DIR/patronus-$VERSION.tar.gz.sha256"
echo
echo "To publish this release:"
echo "1. Create a GitHub release for v$VERSION"
echo "2. Upload patronus-$VERSION.tar.gz"
echo "3. Update ebuild SRC_URI to point to the GitHub release"
echo "4. Run 'ebuild patronus-$VERSION.ebuild manifest' to generate checksums"
echo

exit 0
