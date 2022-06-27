#!/bin/bash -x

set -euo pipefail

DIR=$1

# install pre-required packages
sudo apt-get --assume-yes install mosquitto
sudo apt-get --assume-yes install libmosquitto1
sudo apt-get --assume-yes install collectd-core

# install tedge packages
sudo dpkg -i ./"$DIR"/tedge_0.*_amd64.deb
sudo dpkg -i ./"$DIR"/tedge_mapper_*_amd64.deb
sudo dpkg -i ./"$DIR"/tedge_agent_*_amd64.deb
sudo dpkg -i ./"$DIR"/tedge_watchdog_*_amd64.deb
sudo dpkg -i ./"$DIR"/tedge_*_plugin_*_amd64.deb
sudo dpkg -i ./"$DIR"/c8y_*_plugin_*_amd64.deb

