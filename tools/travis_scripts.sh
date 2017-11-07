#!/bin/bash

cp /opt/rucio/etc/docker/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg

httpd -k start

echo '==============================='
echo "Run Oracle tests"
echo '==============================='

/opt/rucio/tools/run_tests_docker.sh -1q

if [ $? -ne 0 ]; then
    exit 1
fi

echo '==============================='
echo 'Running flake8                 '
echo '==============================='
flake8 --ignore=E501 --exclude=*.cfg bin/* lib/ tools/*.py tools/probes/common/*

if [ $? -ne 0 ]; then
    exit 1
fi


echo '==============================='
echo 'Running pylint                 '
echo '==============================='

pylint lib/rucio > pylint.out

grep '^E:' pylint.out

if [ $? -ne 0 ]; then
    echo 'PYLINT FAILED'
    tail -n 3 pylint.out
    exit 1
fi

echo 'PYLINT SUCCEEDED'
tail -n 3 pylint.out

exit 0
