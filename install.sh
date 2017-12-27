#!/usr/bin/env bash

echo '## Install Ossec ##'
# Get args
if [ -z $1 ] || [ $1 == 'dev' ]; then
    arg="dev"
    dest=""
elif [ $1 == 'prod' ]; then
    arg=$1
    if [ -z $2 ]; then
        dest='/usr/local/share'
    else
        dest=$2
    fi
else
    echo 'Bad argument'
    exit 1
fi


config=""
# OSX with source
if [[ $OSTYPE == *"darwin"* ]]; then
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
fi
# Debian
if [ -f /etc/debian_version ]; then
    sudo apt update
    sudo apt install build-essential
    sudo apt install lynx
fi
if ! [ -d /var/ossec ]; then
    wget https://github.com/ossec/ossec-hids/archive/2.9.3.tar.gz
    tar xf 2.9.3.tar.gz
    cp probemanager/ossec/preloaded-vars-server.conf ossec-hids-2.9.3/etc/preloaded-vars.conf
    chmod +x ossec-hids-2.9.3/etc/preloaded-vars.conf
    (cd ossec-hids-2.9.3/ && sudo ./install.sh)
    rm 2.9.3.tar.gz
    rm -rf ossec-hids-2.9.3
fi
config="/var/ossec/etc/ossec.conf"
if [ $arg == 'prod' ]; then
    echo "OSSEC_BINARY = '/var/ossec/bin'" > "$dest"probemanager/ossec/settings.py
    echo "OSSEC_CONFIG = '$config'" >> "$dest"probemanager/ossec/settings.py
else
    echo "OSSEC_BINARY = '/var/ossec/bin'" > probemanager/ossec/settings.py
    echo "OSSEC_CONFIG = '$config'" >> probemanager/ossec/settings.py
fi


