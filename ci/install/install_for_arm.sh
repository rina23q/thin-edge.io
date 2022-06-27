#!/bin/bash -x

set -euo pipefail

DIR=$1

# install pre-required packages
sudo apt-get --assume-yes install mosquitto
sudo apt-get --assume-yes install libmosquitto1
sudo apt-get --assume-yes install mosquitto-clients
sudo apt-get --assume-yes install collectd-core
sudo apt-get --assume-yes install collectd

# install tedge packages
sudo dpkg -i ./"$DIR"/tedge_0.*_armhf.deb
sudo dpkg -i ./"$DIR"/tedge_mapper_*_armhf.deb
sudo dpkg -i ./"$DIR"/tedge_agent_*_armhf.deb
sudo dpkg -i ./"$DIR"/tedge_watchdog_*_armhf.deb
sudo dpkg -i ./"$DIR"/tedge_*_plugin_*_armhf.deb
sudo dpkg -i ./"$DIR"/c8y_*_plugin_*_armhf.deb

# Configure collectd
sudo cp "/etc/tedge/contrib/collectd/collectd.conf" "/etc/collectd/collectd.conf"

# Change downloaded binaries to executable for testing
chmod +x /home/pi/examples/sawtooth_publisher
chmod +x /home/pi/tedge_dummy_plugin/tedge_dummy_plugin
