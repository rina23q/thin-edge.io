#!/bin/bash -x

set -euo pipefail

DIR=$1

# install pre-required packages
sudo apt-get --assume-yes install mosquitto
sudo apt-get --assume-yes install libmosquitto1
sudo apt-get --assume-yes install collectd-core

# Load the release package list as $RELEASE_PACKAGES
source ./../release_package_list.sh

# install tedge packages
for PACKAGE in "${RELEASE_PACKAGES[@]}"
do
    sudo dpkg -i ./"$DIR"/"$PACKAGE"_0.*_amd64.deb
done
