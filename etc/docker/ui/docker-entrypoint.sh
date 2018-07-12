#!/bin/bash -e
j2 /tmp/rucio.conf.j2 > /etc/httpd/conf.d/rucio.conf

httpd -D FOREGROUND
