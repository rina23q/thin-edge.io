#!/bin/bash -x

set -euo pipefail

# Use market place actions to enable cache instead of those.
# If you want to have the same condition as workflow, uncomment lines below.
# rustup toolchain install 1.58.1 --allow-downgrade --component clippy rustfmt
# rustup override set 1.58.1

cargo clippy --version
cargo clippy
