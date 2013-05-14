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

testopts=""

function usage {
  echo "Usage: $0 [OPTION]..."
  echo "Run Rucio's test suite(s)"
  echo ""
  echo "  -s    Skip RSE tests."
  echo "  -c    Include only named class."
  echo "  -t    Include tables required for testing."
  exit
}

while getopts hsct opt
do
  case "$opt" in
    h) usage;;
    s) noseopts="--exclude=.*test_rse_protocol_.* ";;
    c) noseopts=$OPTARG;;
    t) testopts="-t";;
  esac
done

echo "Cleaning *.pyc files"
find lib -iname '*.pyc' | xargs rm

echo "Cleaning old authentication tokens"
rm -rf /tmp/.rucio_*/

echo "Removing old database"
rm -f /tmp/rucio.db

echo "Resetting database tables" $testopts
tools/reset_database.py $testopts
if [ $? != 0 ]; then
    echo 'Failed to reset the database!'
    exit
fi

echo "Disable database access restriction"
chmod 777 /tmp/rucio.db

echo 'Sync rse_repository with Rucio core'
tools/sync_rses.py

echo 'Sync metadata keys'
tools/sync_meta.py

echo 'Bootstrap tests: Create jdoe account/mock scope'
tools/bootstrap_tests.py

for i in {1..2}
do
    echo "Running tests with nose - Iteration $i"
    nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient $noseopts
done

echo "Finished"
