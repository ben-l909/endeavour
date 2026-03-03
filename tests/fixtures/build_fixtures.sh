#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="$ROOT_DIR/fixtures"
SRC_DIR="$FIXTURES_DIR/src"

echo "==> Building minimal_arm64"
clang \
  -arch arm64 \
  -target arm64-apple-macos12.0 \
  -O0 \
  -o "$FIXTURES_DIR/minimal_arm64/binary" \
  "$SRC_DIR/main.c"

echo "==> Building minimal_x86_64"
clang \
  -arch x86_64 \
  -target x86_64-apple-macos12.0 \
  -O0 \
  -o "$FIXTURES_DIR/minimal_x86_64/binary" \
  "$SRC_DIR/main.c"

echo "==> Building objc_classes"
clang \
  -arch arm64 \
  -target arm64-apple-macos12.0 \
  -fobjc-arc \
  -framework Foundation \
  -O0 \
  -o "$FIXTURES_DIR/objc_classes/binary" \
  "$SRC_DIR/main_objc.m" \
  "$SRC_DIR/Animal.m" \
  "$SRC_DIR/Dog.m" \
  "$SRC_DIR/Cat.m"

echo ""
echo "Built fixtures:"
echo "  $FIXTURES_DIR/minimal_arm64/binary"
echo "  $FIXTURES_DIR/minimal_x86_64/binary"
echo "  $FIXTURES_DIR/objc_classes/binary"
