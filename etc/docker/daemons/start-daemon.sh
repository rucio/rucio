#!/bin/sh

if [ -z "$RUCIO_ENABLE_LOGS" ]; then
    eval "$DAEMONCMD"
else
    eval "$DAEMONCMD >> /var/log/rucio/daemon.log 2>> /var/log/rucio/error.log"
fi
