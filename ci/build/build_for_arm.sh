#!/bin/bash -x

set -euo pipefail

ARCH=$1

cargo install cargo-deb --version 1.38.1
cargo install cargo-strip


cross build --release --target="$ARCH"

# armv7 uses `arm-linux-gnueabihf-strip`; aarch64 uses `aarch64-linux-gnu-strip`
# It appears `aarch64-linux-gnu-strip` seems to work explicitly on other arm bins but not other way around.
sudo apt update
sudo apt-get --assume-yes install binutils-arm-linux-gnueabihf binutils-aarch64-linux-gnu

# Strip for release artifacts
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_mapper || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_mapper
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_agent || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_agent
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_watchdog || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_watchdog
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_apt_plugin || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_apt_plugin
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_apama_plugin || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_apama_plugin
arm-linux-gnueabihf-strip target/"$ARCH"/release/c8y_log_plugin || aarch64-linux-gnu-strip target/"$ARCH"/release/c8y_log_plugin
arm-linux-gnueabihf-strip target/"$ARCH"/release/c8y_configuration_plugin || aarch64-linux-gnu-strip target/"$ARCH"/release/c8y_configuration_plugin

cargo deb -p tedge --no-strip --no-build --target="$ARCH"
cargo deb -p tedge_mapper --no-strip --no-build --target="$ARCH"
cargo deb -p tedge_apt_plugin --no-strip --no-build --target="$ARCH"
cargo deb -p tedge_apama_plugin --no-strip --no-build --target="$ARCH"
cargo deb -p tedge_agent --no-strip --no-build --target="$ARCH"
cargo deb -p tedge_watchdog --no-strip --no-build --target="$ARCH"
cargo deb -p c8y_log_plugin --no-strip --no-build --target="$ARCH"
cargo deb -p c8y_configuration_plugin --no-strip --no-build --target="$ARCH"

# Test artifacts
cross build --release -p sawtooth_publisher --target="$ARCH"
cross build --release -p tedge_dummy_plugin  --target="$ARCH"

arm-linux-gnueabihf-strip target/"$ARCH"/release/sawtooth_publisher || aarch64-linux-gnu-strip target/"$ARCH"/release/sawtooth_publisher
arm-linux-gnueabihf-strip target/"$ARCH"/release/tedge_dummy_plugin || aarch64-linux-gnu-strip target/"$ARCH"/release/tedge_dummy_plugin
