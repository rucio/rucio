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

function usage {
  echo "Usage: $0 [OPTION]..."
  echo 'Run Rucio test suite'
  echo ''
  echo '  -h    Show usage'
  echo '  -2    Run tests twice'
  echo '  -p    Indicate test selection by TESTS environment variable'
  echo '  -k    Keep database from previous test'
  echo '  -i    Do only the initialization'
  echo '  -l    Also run lint tests'
  echo '  -r    Activate default RSEs (XRD1, XRD2, XRD3, SSH1)'
  echo '  -s    Run special tests for Dirac. Includes using BelleII schema'
  echo '  -t    Verbose output from pytest'
  echo '  -a    Skip alembic downgrade/upgrade test'
  echo '  -u    Update pip dependencies only'
  echo '  -x    exit instantly on first error or failed test'
  exit
}

alembic="true"
iterations=1

while getopts h2cpkilrstaux opt
do
  case "$opt" in
    h) usage;;
    2) iterations=2;;
    p) selection="true";;
    k) keep_db="true";;
    i) init_only="true";;
    l) lint="true";;
    r) activate_rse="true";;
    s) special="true";selection="true";TESTS="test_dirac.py";;
    t) trace="true";;
    a) alembic="";;
    u) pip_only="true";;
    x) stop_on_failure="--exitfirst";;
    *) usae; exit 1;
  esac
done

if [ -z "$RUCIO_HOME" ]; then
    RUCIO_HOME=/opt/rucio
fi
echo 'Clearing memcache'
echo flush_all > /dev/tcp/127.0.0.1/11211

echo 'Update dependencies with pip'
pip install --upgrade -r requirements.txt

if test ${pip_only}; then
    exit
fi

echo 'Cleaning *.pyc files'
find lib -iname "*.pyc" -print0 | xargs -0 rm

echo 'Cleaning old authentication tokens'
rm -rf /tmp/.rucio_*/

echo 'Cleaning local RSE directories'
rm -rf /tmp/rucio_rse/*

if test ${special}; then
    if [ -f "$RUCIO_HOME"/etc/rucio.cfg ]; then
        echo 'Remove rucio.cfg'
        rm "$RUCIO_HOME"/etc/rucio.cfg
    fi
    echo 'Using the special config'
    ln -s "$RUCIO_HOME"/etc/rucio.cfg.special "$RUCIO_HOME"/etc/rucio.cfg
else
    if [ -f "$RUCIO_HOME"/etc/rucio.cfg ]; then
        echo 'Using the standard config'
    else
        echo 'rucio.cfg not found. Will try to do a symlink'
        ln -s "$RUCIO_HOME"/etc/rucio.cfg.default "$RUCIO_HOME"/etc/rucio.cfg
    fi
fi

if test ${lint}; then
    echo 'Running flake8 code style checker'
    flake8 --exclude=*.cfg bin/* lib/ tools/*.py
    if [ $? != 0 ]; then
        echo 'Checker failed, aborting.'
        exit 1
    fi

    echo 'Running pylint code style checker'
    pylint bin/* lib/ tools/*.py
    if [ $? != 0 ]; then
	      echo 'Checker failed, aborting.'
	      exit 1
    fi
fi

if test ${keep_db}; then
    echo 'Keeping database tables'
else
    echo 'Resetting database tables'

    echo 'Removing old SQLite databases'
    rm -f /tmp/rucio.db

    tools/reset_database.py

    if [ $? != 0 ]; then
        echo 'Failed to reset the database!'
        exit 1
    fi

    if [ -f /tmp/rucio.db ]; then
        echo 'Disable SQLite database access restriction'
        chmod 666 /tmp/rucio.db
    fi
fi

if test ${alembic}; then
    echo 'Running full alembic migration'
    ALEMBIC_CONFIG="$RUCIO_HOME/etc/alembic.ini" tools/alembic_migration.sh
    if [ $? != 0 ]; then
        echo 'Failed to run alembic migration!'
        exit 1
    fi
fi

echo 'Graceful restart of Apache'
httpd -k graceful

echo 'Bootstrapping tests'
tools/bootstrap_tests.py
if [ $? != 0 ]; then
    echo 'Failed to bootstrap!'
    exit 1
fi

echo 'Sync rse_repository'
if test ${special}; then
    tools/sync_rses.py etc/rse_repository.json.special
    if [ $? != 0 ]; then
        echo 'Failed to sync!'
        exit 1
    fi
else
    tools/sync_rses.py
    if [ $? != 0 ]; then
        echo 'Failed to sync!'
        exit 1
    fi
fi

echo 'Sync metadata keys'
tools/sync_meta.py
if [ $? != 0 ]; then
    echo 'Failed to sync!'
    exit 1
fi

if test ${activate_rse}; then
    echo 'Activating default RSEs (XRD1, XRD2, XRD3, SSH1)'
    tools/docker_activate_rses.sh
fi

if test ${init_only}; then
    exit
fi

PYTEST_SH_ARGS="$stop_on_failure"
if test ${trace}; then
    echo 'Running tests in verbose mode'
    PYTEST_SH_ARGS="-vvv $PYTEST_SH_ARGS"
else
    echo 'Running tests'
    PYTEST_SH_ARGS="-v --tb=short $PYTEST_SH_ARGS"
fi

for i in $iterations
do

    if test ${selection}; then
        echo "Running the following tests:"
        echo $TESTS | tr " " "\n"
    else
        TESTS=''
    fi
    echo 'Running test iteration' $i
    echo tools/pytest.sh $PYTEST_SH_ARGS $TESTS
    tools/pytest.sh $PYTEST_SH_ARGS $TESTS
done
