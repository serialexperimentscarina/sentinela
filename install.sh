#!/bin/bash
# install.sh

set -e
echo "welcome to sentinela! beginning installation..."

# check if install script is being run as root
if [[ $EUID -ne 0 ]]; then
   echo "this script must be run as root" 
   exit 1
fi

# compile binary
sudo g++ -o sentinela ./src/main.cpp -lssl -lcrypto
if [ $? -ne 0 ]; then
  echo "could not compile binary."
  exit 1
fi

# copy binary to /usr/local/bin/
sudo cp ./sentinela /usr/local/bin/sentinela

# copy .service file to /etc/systemd/system/sentinela.service
sudo cp ./sentinela.service /etc/systemd/system/sentinela.service

# enable service
sudo systemctl daemon-reload
sudo systemctl enable sentinela
sudo systemctl start sentinela

echo "installation complete!"

