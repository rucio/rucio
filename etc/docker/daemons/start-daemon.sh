#!/bin/sh

if [ -z "$RUCIO_ENABLE_LOGS" ]; then
    eval "/usr/bin/rucio-$RUCIO_DAEMON $RUCIO_DAEMON_ARGS"
else
    eval "/usr/bin/rucio-$RUCIO_DAEMON $RUCIO_DAEMON_ARGS >> /var/log/rucio/daemon.log 2>> /var/log/rucio/error.log"
fi
