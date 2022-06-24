#!/bin/bash -x

set -euo pipefail

rustup override set 1.58.1
cargo clippy --version
cargo clippy
