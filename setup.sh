#!/bin/bash

echo "

sdnpwn requires the following software...
From package manager:
   - python3
   - python3-netifaces
   - python3-scipy
   - bridge-utils
   - python3-tabulate
   - python3-pip
   - git
From pip:
   - scapy
   - websocket-client
   - python-openflow

This script will now download the above software using apt-get and pip3. If you're ok with this enter 'y' to continue.

"
read -p "Install Required Software? [y/N] " res

if [ "$res" == "y" ]; then
  sudo apt-get update
  sudo apt-get install python3 python3-pip python3-netifaces python3-scipy git bridge-utils python3-tabulate
  pip install scapy
  sudo pip install scapy
  pip install websocket-client
  pip install python-openflow

echo -e "\n

Maven is used by some modules to build Java-based SDN applications"

  read -p "Would you like to install Maven? [y/N] " res

  if [ "$res" == "y" ]; then
    apt-get install maven
  fi

else
  echo "Quiting."
fi
