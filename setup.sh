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
From pip3:
   - scapy-python
   - websocket-client
From github:
   - python-openflow-legacy (Older version of Kytos OpenFlow library)

This script will now download the above software using apt-get and pip3. If you're ok with this enter 'y' to continue.

NOTE: sdnpwn works best with Python versions 3.4 and 3.5. Some modules may not function correctly when other Python versions are used.

"
read -p "Install Required Software? [y/N] " res

if [ "$res" == "y" ]; then
  apt-get update
  apt-get install python3 python3-pip python3-netifaces python3-scipy git bridge-utils python3-tabulate
  pip3 install scapy-python3
  #pip3 install python-openflow
  pip3 install websocket-client
  
  mkdir lib
  cd lib
  git clone https://github.com/smythtech/python-openflow-legacy
  cd python-openflow-legacy
  chmod +x setup.py
  sudo python3 setup.py install
  cd ..  

echo -e "\n

Maven is used by some modules to build Java-based SDN applications"

  read -p "Would you like to install Maven? [y/N] " res

  if [ "$res" == "y" ]; then
    apt-get install maven
  fi

else
  echo "Quiting."
fi
