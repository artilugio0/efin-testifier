#!/usr/bin/env bash

# Get the directory where the script is located.
SCRIPT_DIR="$(dirname "$(realpath "$0")")"

# Define the repository root (parent of scripts/ directory).
REPO_ROOT="$(realpath "$SCRIPT_DIR/..")"

# Define the input and output directories relative to the repository root.
SRC_DIR="$REPO_ROOT/cmd/efin-testifier"
BUILD_DIR="$REPO_ROOT/build"
BINARY_NAME="efin-testifier"

# Ensure the build directory exists.
mkdir -p "$BUILD_DIR"

# Compile the Go program with CGO_ENABLED=0.
CGO_ENABLED=0 go build -o "$BUILD_DIR/$BINARY_NAME" "$SRC_DIR"

# Check if the compilation was successful.
if [ $? -eq 0 ]; then
    echo "Compilation successful. Binary output: $BUILD_DIR/$BINARY_NAME"
else
    echo "Compilation failed."
    exit 1
fi
