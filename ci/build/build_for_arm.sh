#!/bin/bash -x

set -euo pipefail

ARCH=$1

# Install required cargo crates
cargo install cargo-deb --version 1.38.1
cargo install cross

# cross build release for target
cross build --release --target="$ARCH"

# armv7 uses `arm-linux-gnueabihf-strip`; aarch64 uses `aarch64-linux-gnu-strip`
# It appears `aarch64-linux-gnu-strip` seems to work explicitly on other arm bins but not other way around.
sudo apt update
sudo apt-get --assume-yes install binutils-arm-linux-gnueabihf binutils-aarch64-linux-gnu

# Load the release package list as $RELEASE_PACKAGES
source ./../release_package_list.sh

# Strip and build for release artifacts
for PACKAGE in "${RELEASE_PACKAGES[@]}"
do
    arm-linux-gnueabihf-strip target/"$ARCH"/release/"$PACKAGE" || aarch64-linux-gnu-strip target/"$ARCH"/release/"$PACKAGE"
    cargo deb -p "$PACKAGE" --no-strip --no-build --target="$ARCH"
done

# build binaries for testing
cross build --release -p sawtooth_publisher --target="$ARCH"
cross build --release -p tedge_dummy_plugin  --target="$ARCH"

# strip binaries for testing
arm-linux-gnueabihf-strip target/"$ARCH"/release/sawtooth_publisher || aarch64-linux-gnu-strip target/"$ARCH"/release/sawtooth_publisher
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_dummy_plugin || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_dummy_plugin
