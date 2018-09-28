#!/bin/bash -e

if [ -f /opt/rucio/etc/rucio.cfg ]; then
    echo "rucio.cfg already mounted."
else
    echo "rucio.cfg not found. will generate one."
    j2 /tmp/rucio.cfg.j2 | sed '/^\s*$/d' > /opt/rucio/etc/rucio.cfg
fi

echo "=================== /opt/rucio/etc/rucio.cfg ============================"
cat /opt/rucio/etc/rucio.cfg
echo ""

j2 /tmp/rucio.conf.j2 | sed '/^\s*$/d' > /etc/httpd/conf.d/rucio.conf

echo "=================== /etc/httpd/conf.d/rucio.conf ========================"
cat /etc/httpd/conf.d/rucio.conf
echo ""

httpd -D FOREGROUND
