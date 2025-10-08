#!/bin/bash
# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

memcached -u root -d
memcached_ready=false
for attempt in {1..10}; do
    if timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/11211" 2>/dev/null; then
        memcached_ready=true
        break
    fi
    sleep 1
done

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
export RUCIO_HOME=/opt/rucio/etc/multi_vo/tst

echo 'Clearing memcache'
if [ "$memcached_ready" = true ]; then
    echo flush_all > /dev/tcp/127.0.0.1/11211
else
    echo 'Warning: memcached on port 11211 did not become ready; skipping flush'
fi

echo 'Graceful restart of Apache'
httpd -k graceful

echo 'Cleaning old authentication tokens'
rm -rf /tmp/.rucio_*/

echo 'Cleaning local RSE directories'
rm -rf /tmp/rucio_rse/*

echo 'Removing old SQLite databases'
rm -f /tmp/rucio.db

echo 'Resetting database tables'
ALEMBIC_CONFIG="$RUCIO_HOME/etc/alembic.ini" tools/reset_database.py
if [ $? != 0 ]; then
    echo 'Failed to reset the database!'
    exit 1
fi

if [ -f /tmp/rucio.db ]; then
    echo 'Disable SQLite database access restriction'
    chmod 777 /tmp/rucio.db
fi

echo 'Running full alembic migration'
ALEMBIC_CONFIG="$RUCIO_HOME/etc/alembic.ini" tools/alembic_migration.sh
if [ $? != 0 ]; then
    echo 'Failed to run alembic migration!'
    exit 1
fi

echo 'Bootstrapping tests'
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

if test ${activate_rse}; then
    echo 'Activating default RSEs (XRD1, XRD2, XRD3)'
    tools/docker_activate_rses.sh
fi

if test ${init_only}; then
    exit
fi

echo 'Running tests on VO "tst"'
if [ -n "$TESTS" ]; then
    tools/pytest.sh -v --tb=short $TESTS
else
    tools/pytest.sh -v --tb=short
fi
if [ $? != 0 ]; then
    echo 'Tests on first VO failed, not attempting tests at second VO'
    exit 1
fi

echo 'Tests on first VO successful, preparing second VO'
export RUCIO_HOME=/opt/rucio/etc/multi_vo/ts2

echo 'Clearing memcache'
echo flush_all > /dev/tcp/127.0.0.1/11211

echo 'Bootstrapping tests'
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

if test ${activate_rse}; then
    echo 'Activating default RSEs (XRD1, XRD2, XRD3)'
    tools/docker_activate_rses.sh
fi

echo 'Running tests on VO "ts2"'
if [ -n "$TESTS" ]; then
    tools/pytest.sh -v --tb=short $TESTS
else
    tools/pytest.sh -v --tb=short
fi
if [ $? != 0 ]; then
    echo 'Tests on second VO failed'
    exit 1
fi

echo 'Tests on second VO successful'
exit $?
