noseopts="--exclude=test_dq2* --exclude=.*test_rse_protocol_.* --exclude=test_alembic --exclude=test_rucio_cache --exclude=test_rucio_server --exclude=test_objectstore --exclude=test_auditor* --exclude=test_replica*"

function usage {
  echo "Usage: $0 [OPTION]..."
  echo 'Run Rucio test suite'
  echo ''
  echo '  -h    Show usage.'
  echo '  -r    Do not skip RSE tests.'
  echo '  -c    Include only named class.'
  echo '  -t    Do not include mock tables.'
  echo '  -i    Do only the initialization.'
  echo '  -d    Delete the sqlite db file.'
  echo '  -k    Keep database.'
  echo '  -1    Only run once.'
  echo '  -a    Run alembic tests at the end'
  echo '  -u    Update pip dependencies only'
  echo '  -x    Stop running tests after the first error or failure'
  exit
}

seq_tool=`which seq`
if [ $? != 0 ]; then
    range=$(jot - 1 2)  #  For mac
else
    range=$(seq 1 2)
fi

while getopts hrcid1kqaux opt
do
  case "$opt" in
    h) usage;;
    r) noseopts="";;
    c) noseopts="$OPTARG";;
    i) init_only="true";;
    d) delete_sqlite="true";;
    k) keep_db="true";;
    1) range=1;;
    a) alembic="true";;
    u) pip_only="true";;
    x) stop_on_failure="--stop";;
  esac
done

echo 'Update pip dependencies'
pip install -r tools/pip-requires
pip install -r tools/pip-requires-client
pip install -r tools/pip-requires-test

echo 'Cleaning *.pyc files'
find lib -iname "*.pyc" | xargs rm

echo 'Cleaning old authentication tokens'
rm -rf /tmp/.rucio_*/

if test ${delete_sqlite+defined}; then
    echo 'Removing old sqlite databases'
    rm -f /tmp/rucio.db
fi

if test ${keep_db}; then
    echo 'Keep database tables'
else
    echo 'Resetting database tables'

    tools/reset_database.py

    if [ $? != 0 ]; then
        echo 'Failed to reset the database!'
        exit
    fi
fi

if [ -f /tmp/rucio.db ]; then
    echo 'Disable sqlite database access restriction'
    chmod 777 /tmp/rucio.db
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

echo 'Running tests with nose - Iteration' $i
echo nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts $stop_on_failure
nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient $noseopts $stop_on_failure

exit $?

