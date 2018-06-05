#!/usr/bin/env bash

echo '## Install Ossec ##'
# Install on ProbeManager server
# Get args
arg=$1
destfull=$2

if [[ "$OSSEC_VERSION" == "" ]]; then
    OSSEC_VERSION="2.9.3"
fi
config="/var/ossec/etc/ossec.conf"
rules="/var/ossec/rules/"
binary="/var/ossec/bin/"

install(){
    if ! [ -d /var/ossec ]; then
        wget https://github.com/ossec/ossec-hids/archive/"$OSSEC_VERSION".tar.gz
        tar xf "$OSSEC_VERSION".tar.gz
        cp probemanager/ossec/preloaded-vars-server.conf ossec-hids-"$OSSEC_VERSION"/etc/preloaded-vars.conf
        chmod +x ossec-hids-"$OSSEC_VERSION"/etc/preloaded-vars.conf
        (cd ossec-hids-"$OSSEC_VERSION"/ && sudo ./install.sh)
        rm "$OSSEC_VERSION".tar.gz && rm -rf ossec-hids-"$OSSEC_VERSION"
        sudo cp probemanager/ossec/ossec-conf-server.xml /var/ossec/etc/ossec.conf
    fi
}

ssh_key(){
    ssh-keygen -t rsa -b 4096 -C "Ossec server" -f ~/.ssh/ossec-server_rsa -P ""
    cat ~/.ssh/ossec-server_rsa.pub >> ~/.ssh/authorized_keys
}

# OSX with source
if [[ $OSTYPE == *"darwin"* ]]; then
    os="osx"
    if brew --version | grep -qw Homebrew ; then
        if ! brew list | grep -qw wget ; then
            brew install wget
        fi
        if ! brew list | grep -qw gcc ; then
            brew install gcc
        fi
        if ! brew list | grep -qw lynx ; then
            brew install lynx
        fi
    fi
    install
    ssh_key
fi
# Debian
if [ -f /etc/debian_version ]; then
    os="debian"
    sudo apt update
    sudo apt install build-essential
    sudo apt install lynx
    install
    ssh_key
fi

if [ $arg == 'prod' ]; then
    echo "OSSEC_BINARY = '$binary'" > "$destfull"probemanager/ossec/settings.py
    echo "OSSEC_CONFIG = '$config'" >> "$destfull"probemanager/ossec/settings.py
    echo "OSSEC_RULES = '$rules'" >> "$destfull"probemanager/ossec/settings.py
    echo "OSSEC_VERSION = '$OSSEC_VERSION'" >> "$destfull"probemanager/ossec/settings.py
    echo "OSSEC_REMOTE_USER = '$(whoami)'" >> "$destfull"probemanager/ossec/settings.py
    echo "OSSEC_REMOTE_OS = '$os'" >> "$destfull"probemanager/ossec/settings.py
else
    echo "OSSEC_BINARY = '$binary'" > probemanager/ossec/settings.py
    echo "OSSEC_CONFIG = '$config'" >> probemanager/ossec/settings.py
    echo "OSSEC_RULES = '$rules'" >> probemanager/ossec/settings.py
    echo "OSSEC_VERSION = '$OSSEC_VERSION'" >> probemanager/ossec/settings.py
    echo "OSSEC_REMOTE_USER = '$(whoami)'" >> probemanager/ossec/settings.py
    echo "OSSEC_REMOTE_OS = '$os'" >> probemanager/ossec/settings.py
fi
sudo "$binary"manage_agents -V
exit 0
