#!/bin/bash -x

set -euo pipefail

rustup toolchain install 1.58.1 --allow-downgrade
cargo clippy --version
cargo clippy
