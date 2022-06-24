#!/bin/bash -x

set -euo pipefail

rustup toolchain install 1.58.1 --component clippy rustfmt
cargo clippy --version
cargo clippy
