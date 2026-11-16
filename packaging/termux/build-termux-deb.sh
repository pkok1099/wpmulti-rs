#!/usr/bin/env bash
set -euo pipefail

# Build a Termux-compatible .deb package for aarch64 using dpkg-deb.
# Usage: ./packaging/termux/build-termux-deb.sh <binary_path> <version> [output_dir]

BIN_PATH="${1:?Usage: $0 <binary_path> <version> [output_dir]}"
VERSION="${2:?Usage: $0 <binary_path> <version> [output_dir]}"
OUT_DIR="${3:-.}"

# Strip leading 'v' from tag if present (e.g. v0.1.0 -> 0.1.0)
VERSION="${VERSION#v}"
PREFIX="data/data/com.termux/files/usr"

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$STAGE_DIR/DEBIAN"
mkdir -p "$STAGE_DIR/$PREFIX/bin"
mkdir -p "$STAGE_DIR/$PREFIX/etc/wpmulti/confs"
chmod 0700 "$STAGE_DIR/$PREFIX/etc/wpmulti" "$STAGE_DIR/$PREFIX/etc/wpmulti/confs"
mkdir -p "$STAGE_DIR/$PREFIX/var/service/wpmulti/log"
mkdir -p "$STAGE_DIR/$PREFIX/share/doc/wpmulti"

install -m 0755 "$BIN_PATH" "$STAGE_DIR/$PREFIX/bin/wpmulti"
install -m 0600 packaging/termux/wpmulti.toml "$STAGE_DIR/$PREFIX/etc/wpmulti/wpmulti.toml"
install -m 0755 packaging/termux/sv-run "$STAGE_DIR/$PREFIX/var/service/wpmulti/run"
install -m 0755 packaging/termux/sv-log-run "$STAGE_DIR/$PREFIX/var/service/wpmulti/log/run"
install -m 0644 LICENSE "$STAGE_DIR/$PREFIX/share/doc/wpmulti/LICENSE"
install -m 0644 README.md "$STAGE_DIR/$PREFIX/share/doc/wpmulti/README.md"
install -m 0644 THIRD_PARTY_NOTICES.md "$STAGE_DIR/$PREFIX/share/doc/wpmulti/THIRD_PARTY_NOTICES.md"

cat > "$STAGE_DIR/DEBIAN/control" <<EOF
Package: wpmulti
Version: $VERSION
Architecture: aarch64
Maintainer: pkok1099
Section: net
Priority: optional
Homepage: https://github.com/pkok1099/wpmulti-rs
Description: High-concurrency multi-tunnel WireGuard proxy daemon for gotatun (Termux)
EOF

cat > "$STAGE_DIR/DEBIAN/conffiles" <<EOF
/$PREFIX/etc/wpmulti/wpmulti.toml
EOF

install -m 0755 packaging/termux/postinst "$STAGE_DIR/DEBIAN/postinst"

OUT_FILE="$OUT_DIR/wpmulti_${VERSION}_termux-aarch64.deb"
dpkg-deb --build --root-owner-group "$STAGE_DIR" "$OUT_FILE"
echo "Built $OUT_FILE"
