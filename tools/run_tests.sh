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
  echo "  --skip-rse-tests              Skip RSE tests."
  exit
}

function process_option {
  case "$1" in
    -h|--help) usage;;
    --skip-rse-tests) noseopts="--exclude=.*test_rse_protocol_.*";;
  esac
}

for arg in "$@"; do
  process_option $arg
done


# Cleanup *pyc
echo "cleaning *.pyc files"
find lib -iname *.pyc | xargs rm

# Cleanup old token
rm -rf /tmp/.rucio_*/

./tools/reset_database.py
if [ $? != 0 ]; then
    echo 'Failed to reset the database'
    exit
fi


# Run nosetests
nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient $noseopts
nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient $noseopts
