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
destfull="$dest"/ProbeManager/

if [ $arg == 'prod' ]; then
    "$destfull"venv/bin/python "$destfull"probemanager/manage.py runscript setup_ip --settings=probemanager.settings.$arg --script-args $destfull
else
    venv/bin/python probemanager/manage.py runscript setup_ip --settings=probemanager.settings.$arg --script-args $destfull
fi

VERSION="2.9.3"

install(){
    if ! [ -d /var/ossec ]; then
        wget https://github.com/ossec/ossec-hids/archive/"$VERSION".tar.gz
        tar xf "$VERSION".tar.gz
        cp probemanager/ossec/preloaded-vars-server.conf ossec-hids-"$VERSION"/etc/preloaded-vars.conf
        chmod +x ossec-hids-"$VERSION"/etc/preloaded-vars.conf
        (cd ossec-hids-"$VERSION"/ && sudo ./install.sh)
        rm "$VERSION".tar.gz && rm -rf ossec-hids-"$VERSION"
        sudo cp probemanager/ossec/ossec-conf-server.xml /var/ossec/etc/ossec.conf
    fi
}

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
    install
fi
# Debian
if [ -f /etc/debian_version ]; then
    sudo apt update
    sudo apt install build-essential
    sudo apt install lynx
    install
fi

if [ $arg == 'prod' ]; then
    echo "OSSEC_BINARY = '/var/ossec/bin'" > "$dest"probemanager/ossec/settings.py
    echo "OSSEC_CONFIG = '/var/ossec/etc/ossec.conf'" >> "$dest"probemanager/ossec/settings.py
    echo "OSSEC_VERSION = '$VERSION'" >> "$dest"probemanager/ossec/settings.py
else
    echo "OSSEC_BINARY = '/var/ossec/bin'" > probemanager/ossec/settings.py
    echo "OSSEC_CONFIG = '/var/ossec/etc/ossec.conf'" >> probemanager/ossec/settings.py
    echo "OSSEC_VERSION = '$VERSION'" >> probemanager/ossec/settings.py
fi


