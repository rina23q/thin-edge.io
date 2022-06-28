#!/bin/bash -x

set -euo pipefail

# Install required cargo crates
cargo install cargo-deb --version 1.38.1

# Load the release package list as $RELEASE_PACKAGES
pwd
ls -ltr
source ./../release_package_list.sh

# Build release debian packages
for PACKAGE in "${RELEASE_PACKAGES[@]}"
do
    cargo deb -p "$PACKAGE"
done

# Build binaries required by test
cargo build --release -p sawtooth_publisher
cargo build --release -p tedge_dummy_plugin
