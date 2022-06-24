#!/bin/bash -x

set -euo pipefail

rustup toolchain install 1.58.1 --allow-downgrade --component clippy rustfmt
rustup override set 1.58.1
cargo clippy --version
cargo clippy
