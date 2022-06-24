#!/bin/bash -x

set -euo pipefail

# Use market place actions to enable cache instead of those.
# If you want to have the same condition as workflow, uncomment lines below.
# rustup toolchain install 1.58.1 --allow-downgrade --component clippy rustfmt
# rustup override set 1.58.1

cargo install cargo-deb --version 1.38.1
cargo deb -p tedge
cargo deb -p tedge_mapper
cargo deb -p tedge_apt_plugin
cargo deb -p tedge_apama_plugin
cargo deb -p tedge_agent
cargo deb -p tedge_watchdog
cargo deb -p c8y_log_plugin
cargo deb -p c8y_configuration_plugin
cargo build --release -p sawtooth_publisher
cargo build --release -p tedge_dummy_plugin
