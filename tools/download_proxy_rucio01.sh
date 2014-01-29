#!/usr/bin/env sh
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

scp root@voatlasrucio-daemon-dev-01:/opt/rucio/etc/rucio01.proxy /opt/rucio/etc/rucio01.proxy
chmod 600 /opt/rucio/etc/rucio01.proxy
export X509_USER_PROXY=/opt/rucio/etc/rucio01.proxy
