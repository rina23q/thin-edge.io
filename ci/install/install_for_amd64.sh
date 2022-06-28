#!/bin/bash -x

set -euo pipefail

DIR=$1

# Load the package list as $EXTERNAL_AMD64_PACKAGES and $RELEASE_PACKAGES
source ./ci/package_list.sh

# Install pre-required packages
sudo apt-get --assume-yes install $(echo "${EXTERNAL_AMD64_PACKAGES[*]}")

# install thin-edge packages
for PACKAGE in "${RELEASE_PACKAGES[@]}"
do
    sudo dpkg -i ./"$DIR"/"$PACKAGE"_0.*_amd64.deb
done
