#!/bin/bash

set -euo pipefail

cargo fmt --version
cargo fmt -- --check
