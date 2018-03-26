#!/bin/bash

TEST_ENV=$1

if [[ $TEST_ENV == "flake8" ]]
  then
    echo '==============================='
    echo 'Running flake8                 '
    echo '==============================='

    flake8 --ignore=E501 --exclude="*.cfg" bin/* lib/ tools/*.py tools/probes/common/*

    if [ $? -ne 0 ]; then
        exit 1
    fi
fi


if [[ $TEST_ENV == "pylint" ]]
  then

    echo '==============================='
    echo 'Running pylint                 '
    echo '==============================='

    pylint --rcfile=/opt/rucio/pylintrc `cat changed_files.txt` > pylint.out

    if [ $(($? & 3)) -ne 0 ]; then
        echo "PYLINT FAILED"
        cat pylint.out
        exit 1
    else
        echo "PYLINT PASSED"
        tail -n 3 pylint.out
    fi

fi


if [[ $TEST_ENV == "oracle" ]]
  then
    echo '==============================='
    echo "Run Oracle tests"
    echo '==============================='

    cp /opt/rucio/etc/docker/travis/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg
    httpd -k start

    /opt/rucio/tools/run_tests_docker.sh -1q

    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

if [[ $TEST_ENV == "mysql" ]]
  then
    cp /opt/rucio/etc/docker/travis/rucio_mysql.cfg /opt/rucio/etc/rucio.cfg

    httpd -k restart

    echo '==============================='
    echo "Run MySQL tests"
    echo '==============================='

    /opt/rucio/tools/run_tests_docker.sh -1q

    if [ $? -ne 0 ]; then
        exit 1
    fi
fi


if [[ $TEST_ENV == "postgres" ]]
  then

    cp /opt/rucio/etc/docker/travis/rucio_postgres.cfg /opt/rucio/etc/rucio.cfg

    httpd -k restart

    echo '==============================='
    echo "Run Postgresql tests"
    echo '==============================='

    /opt/rucio/tools/run_tests_docker.sh -1q

    if [ $? -ne 0 ]; then
        exit 1
    fi
fi
