# INSTALL

cd src/
sudo apt install nlohmann-json3-dev
sudo apt install libkeyutils-dev
g++ -o main main.cpp -lssl -lcrypto -lkeyutils

# TO DO:

- error checking
- code improvements and better modularization
