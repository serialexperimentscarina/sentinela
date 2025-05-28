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

# prompt for copy of hash database
while true; do
    read -p "do you wish to create a backup copy of the current hash database? - copy will be saved under /var/backups/hashes_copy.json (y/n)" yn
    case $yn in
        [Yy]* ) sudo cp /var/lib/sentinela/hashes.json /var/backups/hashes_copy.json; break;;
        [Nn]* ) echo "skipping backup...."; break;;
        * ) echo "please answer with 'y' or 'n'";;
    esac
done

# prompt to clear logs
while true; do
    read -p "do you wish to clear current logs? (y/n)" yn
    case $yn in
        [Yy]* ) sudo rm /var/log/sentinela.log; break;;
        [Nn]* ) echo "skipping logs...."; break;;
        * ) echo "please answer with 'y' or 'n'";;
    esac
done


# remove sentinela files
echo "removing current hashfile..."
sudo rm -r /var/lib/sentinela

# enable service
echo "restarting service..."
sudo systemctl start sentinela