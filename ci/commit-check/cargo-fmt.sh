#!/bin/bash -x

set -euo pipefail

cargo fmt --version
cargo fmt -- --check
