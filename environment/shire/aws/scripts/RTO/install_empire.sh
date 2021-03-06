#Created by Jonathan Johnson


#!/bin/bash

#Checking to see if user is running as root
if [[ $EUID -ne 0 ]]; then
   echo "You need to be root to run this script."
   exit 1
fi
cd /opt/Empire/setup
sudo apt-get uninstall python-pip -y
sudo apt-get install python-pip -y
sudo pip install -r requirements.txt
sudo pip install pefile
sudo ./install.sh << EOF

EOF
echo "Installation complete"
