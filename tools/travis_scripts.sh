#!/bin/bash

cp /opt/rucio/etc/docker/travis/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg

httpd -k start

echo '==============================='
echo "Run Oracle tests"
echo '==============================='

/opt/rucio/tools/run_tests_docker.sh -1q

if [ $? -ne 0 ]; then
    exit 1
fi

cp /opt/rucio/etc/docker/travis/rucio_mysql.cfg /opt/rucio/etc/rucio.cfg

httpd -k restart

echo '==============================='
echo "Run MySQL tests"
echo '==============================='

/opt/rucio/tools/run_tests_docker.sh -1q

if [ $? -ne 0 ]; then
    exit 1
fi

echo '==============================='
echo 'Running flake8                 '
echo '==============================='
flake8 --ignore=E501 --exclude="*.cfg bin/* lib/ tools/*.py tools/probes/common/*"

if [ $? -ne 0 ]; then
    exit 1
fi


echo '==============================='
echo 'Running pylint                 '
echo '==============================='

pylint `cat changed_files.txt` > pylint.out

grep '^E:' pylint.out

if [ $? -ne 1 ]; then
    echo 'PYLINT FAILED'
    tail -n 3 pylint.out
    exit 1
fi

echo 'PYLINT SUCCEEDED'
tail -n 3 pylint.out

exit 0
