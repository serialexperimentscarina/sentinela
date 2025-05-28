#!/bin/bash
# uninstall.sh

set -e
echo "beginnings sentinela uninstallation..."

# check if uninstall script is being run as root
if [[ $EUID -ne 0 ]]; then
   echo "this script must be run as root" 
   exit 1
fi

# stop service
echo "stopping service..."
sudo systemctl stop sentinela.service
sudo systemctl disable sentinela.service
sudo systemctl daemon-reload

# remove sentinela files
echo "removing sentinela files..."
sudo rm -r /var/lib/sentinela
sudo rm /var/log/sentinela.log
sudo rm /usr/local/bin/sentinela
sudo rm /etc/systemd/system/sentinela.service
sudo rm -r /etc/sentinela

echo "sentinela has been uninstalled!"

