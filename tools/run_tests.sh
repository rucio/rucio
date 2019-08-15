#!/bin/bash
# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2014
# - Evangelia Liotiri <evangelia.liotiri@cern.ch>, 2015
# - Tobias Wegner <tobias.wegner@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018

noseopts="--exclude=test_dq2* --exclude=.*test_rse_protocol_.* --exclude=test_alembic --exclude=test_rucio_cache --exclude=test_rucio_server"

function usage {
  echo "Usage: $0 [OPTION]..."
  echo 'Run Rucio test suite'
  echo ''
  echo ''
  echo '  -h    Show usage'
  echo '  -2    Run tests twice'
  echo '  -r    Do not skip RSE tests'
  echo '  -c    Include only named class'
  echo '  -i    Do only the initialization'
  echo '  -p    Also run pylint tests'
  echo '  -k    Keep database from previous test'
  echo '  -a    Disable alembic tests'
  echo '  -u    Update pip dependencies only'
  echo '  -x    Stop running tests after the first problem'
  exit
}

alembic="true"
iterations=1

while getopts h2rcipkaux opt
do
    case "$opt" in
	h) usage;;
	2) iterations=2;;
	r) noseopts="";;
	c) noseopts="$OPTARG";;
	i) init_only="true";;
	p) pylint="true";;
	k) keep_db="true";;
	a) alembic="";;
	u) pip_only="true";;
	x) stop_on_failure="--stop";;
    esac
done

echo 'Update dependencies with pip'
pip install -r tools/pip-requires
pip install -r tools/pip-requires-client
pip install -r tools/pip-requires-test

if test ${pip_only}; then
    exit
fi

echo 'Cleaning *.pyc files'
find lib -iname "*.pyc" | xargs rm

echo 'Cleaning old authentication tokens'
rm -rf /tmp/.rucio_*/

echo 'Cleaning storage for local test RSEs'
rm -rf /tmp/rucio_rse/*

echo 'Running flake8 code style checker'
flake8 --exclude=*.cfg bin/* lib/ tools/*.py
if [ $? != 0 ]; then
    echo 'Checker failed, aborting.'
    exit
fi

if test ${pylint}; then
    echo 'Running pylint code style checker'
    pylint bin/* lib/ tools/*.py
    if [ $? != 0 ]; then
	echo 'Checker failed, aborting.'
	exit
    fi
fi

if test ${keep_db}; then
    echo 'Keeping database tables'
else
    echo 'Resetting database tables'

    rm -f /tmp/rucio.db

    tools/reset_database.py

    if [ $? != 0 ]; then
        echo 'Failed to reset the database!'
        exit
    fi

    if [ -f /tmp/rucio.db ]; then
	echo 'Disable SQLite database access restriction'
	chmod 777 /tmp/rucio.db
    fi
fi

if test ${alembic}; then
    echo 'Running full alembic migration'
    alembic downgrade base
    if [ $? != 0 ]; then
        echo 'Failed to downgrade the database!'
        exit
    fi
    alembic upgrade head
    if [ $? != 0 ]; then
        echo 'Failed to upgrade the database!'
        exit
    fi
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

for i in $iterations
do
    echo 'Running test iteration' $i
    echo nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts $stop_on_failure
    nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts $stop_on_failure
done
