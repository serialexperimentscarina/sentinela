#!/bin/bash
# install.sh

set -e
echo "executing rehash function, this might take a while, check sentinela.log to view when the rehash has been completed."

# check if rehash script is being run as root
if [[ $EUID -ne 0 ]]; then
   echo "this script must be run as root" 
   exit 1
fi

# stop service
echo "stopping service..."
sudo systemctl stop sentinela.service

# remove sentinela files
echo "removing current hashfile..."
sudo rm -r /var/lib/sentinela

# enable service
echo "restarting service..."
sudo systemctl start sentinela