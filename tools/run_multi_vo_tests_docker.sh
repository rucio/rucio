#!/bin/bash
# Copyright 2017-2019 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017-2018
# - Vincent Garonne <vgaronne@gmail.com>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

memcached -u root -d

function usage {
  echo "Usage: $0 [OPTION]..."
  echo 'Run Rucio test suite'
  echo ''
  echo '  -h    Show usage.'
  echo '  -i    Do only the initialization.'
  echo '  -r    Activate default RSEs (XRD1, XRD2, XRD3)'
  exit
}

while getopts hir opt
do
  case "$opt" in
    h) usage;;
    i) init_only="true";;
    r) activate_rse="true";;
  esac
done

cp /opt/rucio/etc/rucio_multi_vo_tst.cfg /opt/rucio/etc/rucio.cfg

echo 'Clearing memcache'
echo flush_all > /dev/tcp/127.0.0.1/11211

echo 'Graceful restart of Apache'
httpd -k graceful

echo 'Cleaning old authentication tokens'
rm -rf /tmp/.rucio_*/

echo 'Cleaning local RSE directories'
rm -rf /tmp/rucio_rse/*

echo 'Removing old SQLite databases'
rm -f /tmp/rucio.db

echo 'Resetting database tables'
tools/reset_database.py
if [ $? != 0 ]; then
    echo 'Failed to reset the database!'
    exit 1
fi

if [ -f /tmp/rucio.db ]; then
    echo 'Disable SQLite database access restriction'
    chmod 777 /tmp/rucio.db
fi

echo 'Running full alembic migration'
alembic -c /opt/rucio/etc/alembic.ini downgrade base
if [ $? != 0 ]; then
    echo 'Failed to downgrade the database!'
    exit 1
fi
alembic -c /opt/rucio/etc/alembic.ini upgrade head
if [ $? != 0 ]; then
    echo 'Failed to upgrade the database!'
    exit 1
fi

echo 'Bootstrap tests: Create jdoe account/mock scope'
tools/bootstrap_tests.py
if [ $? != 0 ]; then
    echo 'Failed to bootstrap!'
    exit 1
fi

echo 'Sync rse_repository'
tools/sync_rses.py
if [ $? != 0 ]; then
    echo 'Failed to sync!'
    exit 1
fi

echo 'Sync metadata keys'
tools/sync_meta.py
if [ $? != 0 ]; then
    echo 'Failed to sync!'
    exit 1
fi

echo 'Bootstrap tests: Create jdoe account/mock scope'
tools/bootstrap_tests.py
if [ $? != 0 ]; then
    echo 'Failed to bootstrap!'
    exit 1
fi

if test ${activate_rse}; then
    echo 'Activating default RSEs (XRD1, XRD2, XRD3)'
    tools/docker_activate_rses.sh
fi


if test ${init_only}; then
    exit
fi

echo 'Running tests on VO "tst"'
noseopts="--exclude=test_alembic --exclude=.*test_rse_protocol_.* --exclude=test_rucio_server --exclude=test_objectstore --exclude=test_auditor* --exclude=test_release* --exclude=test_throttler*"

nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts
if [ $? != 0 ]; then
    echo 'Tests on first VO failed, not attempting tests at second VO'
    exit 1
fi

echo 'Tests on first VO successful, preparing second VO'
cp /opt/rucio/etc/rucio_multi_vo_ts2.cfg /opt/rucio/etc/rucio.cfg

echo 'Clearing memcache'
echo flush_all > /dev/tcp/127.0.0.1/11211

echo 'Bootstrap tests: Create jdoe account/mock scope'
tools/bootstrap_tests.py
if [ $? != 0 ]; then
    echo 'Failed to bootstrap!'
    exit 1
fi

echo 'Sync rse_repository'
tools/sync_rses.py
if [ $? != 0 ]; then
    echo 'Failed to sync!'
    exit 1
fi

echo 'Sync metadata keys'
tools/sync_meta.py
if [ $? != 0 ]; then
    echo 'Failed to sync!'
    exit 1
fi

echo 'Bootstrap tests: Create jdoe account/mock scope'
tools/bootstrap_tests.py
if [ $? != 0 ]; then
    echo 'Failed to bootstrap!'
    exit 1
fi

if test ${activate_rse}; then
    echo 'Activating default RSEs (XRD1, XRD2, XRD3)'
    tools/docker_activate_rses.sh
fi

echo 'Running tests on VO "ts2"'
nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts
if [ $? != 0 ]; then
    echo 'Tests on second VO failed'
    exit 1
fi

echo 'Tests on second VO successful'
exit $?
