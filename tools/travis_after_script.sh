#!/bin/bash


if [[ $TEST_ENV == "flake8" ]]
  then
    docker stop rucio
fi


if [[ $TEST_ENV == "pylint" ]]
  then
    docker stop rucio
fi


if [[ $TEST_ENV == "oracle" ]]
  then
    docker stop rucio
    docker stop oracle
    docker stop activemq
fi


if [[ $TEST_ENV == "mysql" ]]
  then
    docker stop rucio
    docker stop mysql
    docker stop activemq
fi


if [[ $TEST_ENV == "postgres" ]]
  then
    docker stop rucio
    docker stop postgres
    docker stop activemq
fi
