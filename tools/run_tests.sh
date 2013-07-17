#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

testopts="-t"
noseopts="--exclude=.*test_rse_protocol_.* "

function usage {
  echo 'Usage: $0 [OPTION]...'
  echo 'Run Rucio test suite'
  echo ''
  echo '  -h    Show usage.'
  echo '  -r    Do not skip RSE tests.'
  echo '  -c    Include only named class.'
  echo '  -t    Do not include mock tables.'
  echo '  -i    Do only the initialization.'
  echo '  -d    Delete the sqlite db file.'
  echo '  -u    Update pip dependencies.'
  echo '  -1    Only run once.'
  exit
}

seq_tool=`which seq`
if [ $? != 0 ]; then
    range=$(jot - 1 2)  #  For mac
else
    range=$(seq 1 2)
fi

while getopts hrctid1u opt
do
  case "$opt" in
    h) usage;;
    r) noseopts="";;
    c) noseopts="$OPTARG";;
    t) testopts="";;
    i) init_only="true";;
    d) delete_sqlite="true";;
    u) update_deps="true";;
    1) range=1;;
  esac
done

if test ${update_deps}; then
    echo 'Update pip dependencies'
    pip install -r tools/pip-requires
    pip install -r tools/pip-requires-client
    pip install -r tools/pip-requires-test
fi

echo 'Cleaning *.pyc files'
find lib -iname "*.pyc" | xargs rm

echo 'Cleaning old authentication tokens'
rm -rf /tmp/.rucio_*/

if test ${delete_sqlite+defined}; then
    echo 'Removing old databases'
    rm -f /tmp/rucio.db /tmp/mock-fts.db
fi

echo 'Resetting database tables'
tools/reset_database.py $testopts

if [ $? != 0 ]; then
    echo 'Failed to reset the database!'
    exit
fi

if [ -f /tmp/rucio.db ]; then
    echo 'Disable database access restriction'
    chmod 777 /tmp/rucio.db
fi

if [ -f /tmp/mock-fts.db ]; then
    echo 'Disable mock FTS database access restriction'
    chmod 777 /tmp/mock-fts.db
fi

echo 'Sync rse_repository'
tools/sync_rses.py

echo 'Sync metadata keys'
tools/sync_meta.py

echo 'Bootstrap tests: Create jdoe account/mock scope'
tools/bootstrap_tests.py

if test ${init_only}; then
    exit
fi

for i in $range
do
    echo 'Running tests with nose - Iteration' $i
    echo nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts
    nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts
done
