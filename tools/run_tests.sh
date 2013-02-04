#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013


function usage {
  echo "Usage: $0 [OPTION]..."
  echo "Run Rucio's test suite(s)"
  echo ""
  echo "  -s, --skip-rse-tests              Skip RSE tests."
  echo "  -c, --class                       Include only named class."
  exit
}

while getopts hsc: opt
do
  case "$opt" in
    h|help) usage;;
    s|skip-rse-tests) noseopts="--exclude=.*test_rse_protocol_.*";;
    c|class) noseopts=$OPTARG;;
  esac
done

# Cleanup *pyc
echo "cleaning *.pyc files"
find lib -iname '*.pyc' | xargs rm

# Cleanup old token
rm -rf /tmp/.rucio_*/

./tools/reset_database.py
if [ $? != 0 ]; then
    echo 'Failed to reset the database'
    exit
fi

echo 'Sync rse_repository with Rucio core'
./tools/sync_rses.py

echo 'Sync metadata keys'
./tools/sync_meta.py

# Run nosetests
nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient $noseopts
nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient $noseopts
