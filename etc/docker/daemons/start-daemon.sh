#!/bin/sh

if [ -f /opt/rucio/etc/rucio.cfg ]; then
    echo "rucio.cfg already mounted."
else
    echo "rucio.cfg not found. will generate one."
    j2 /tmp/rucio.cfg.j2 | sed '/^\s*$/d' > /opt/rucio/etc/rucio.cfg
fi

echo "=================== /opt/rucio/etc/rucio.cfg ============================"
cat /opt/rucio/etc/rucio.cfg
echo ""

echo "starting daemon with: $RUCIO_DAEMON $RUCIO_DAEMON_ARGS"
echo ""

if [ -z "$RUCIO_ENABLE_LOGS" ]; then
    eval "/usr/bin/rucio-$RUCIO_DAEMON $RUCIO_DAEMON_ARGS"
else
    eval "/usr/bin/rucio-$RUCIO_DAEMON $RUCIO_DAEMON_ARGS >> /var/log/rucio/daemon.log 2>> /var/log/rucio/error.log"
fi
