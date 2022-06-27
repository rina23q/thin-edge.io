#!/bin/bash -x

set -euo pipefail

# Compile in advance to avoid that cargo compiles during the test run
# this seems to have an impact on some tests as the timing differs
cargo test --verbose --no-run --features integration-test

cargo build -p tedge_dummy_plugin

# To run the test for features here is kind of experimental
# they could fail if GitHub blocks external connections.
# It seems like they rarely do.
cargo test --verbose --features integration-test,requires-sudo -- \
--skip sending_and_receiving_a_message
