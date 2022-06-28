#!/bin/bash -x

# Stop services
sudo systemctl stop tedge-mapper-collectd
sudo tedge disconnect c8y
sudo tedge disconnect az
sudo systemctl stop apama

# Load the release package list as $RELEASE_PACKAGES
source ./../release_package_list.sh

# Purge packages
sudo apt --assume-yes purge "${RELEASE_PACKAGES[*]}"
sudo apt --assume-yes purge mosquitto-clients mosquitto libmosquitto1 collectd-core collectd
