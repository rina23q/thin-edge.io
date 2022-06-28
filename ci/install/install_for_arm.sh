#!/bin/bash -x

set -euo pipefail

DIR=$1

# install pre-required packages
sudo apt-get --assume-yes install mosquitto
sudo apt-get --assume-yes install libmosquitto1
sudo apt-get --assume-yes install mosquitto-clients
sudo apt-get --assume-yes install collectd-core
sudo apt-get --assume-yes install collectd

# Load the release package list as $RELEASE_PACKAGES
source ./../release_package_list.sh

# install tedge packages
for PACKAGE in "${RELEASE_PACKAGES[@]}"
do
    sudo dpkg -i ./"$DIR"/"$PACKAGE"_0.*_armhf.deb
done

# Configure collectd
sudo cp "/etc/tedge/contrib/collectd/collectd.conf" "/etc/collectd/collectd.conf"

# Change downloaded binaries to executable for testing
chmod +x /home/pi/examples/sawtooth_publisher
chmod +x /home/pi/tedge_dummy_plugin/tedge_dummy_plugin
