#!/bin/bash -x

# Stop services
sudo systemctl stop tedge-mapper-collectd
sudo tedge disconnect c8y
sudo tedge disconnect az
sudo systemctl stop apama

# Purge packages
sudo apt --assume-yes purge c8y_configuration_plugin c8y_log_plugin tedge_agent \
tedge_mapper tedge_apt_plugin tedge_apama_plugin tedge_watchdog tedge\
mosquitto-clients mosquitto libmosquitto1 collectd-core collectd
