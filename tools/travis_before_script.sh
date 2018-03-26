#!/bin/bash


if [[ $TEST_ENV == "flake8" ]]
  then
    docker run -d --name=rucio rucio/rucio
fi


if [[ $TEST_ENV == "pylint" ]]
  then
    docker run -d --name=rucio rucio/rucio
fi


if [[ $TEST_ENV == "oracle" ]]
  then
    docker run -d -p 8080:8080 -p 1521:1521 --name=oracle -e processes=1000 -e sessions=1105 -e transactions=1215 -e ORACLE_ALLOW_REMOTE=true sath89/oracle-xe-11g
    docker run --name=activemq -d webcenter/activemq:latest
    sleep 150
    docker run -d --link oracle:oracle --link activemq:activemq --name=rucio rucio/rucio
    docker ps -a
fi

if [[ $TEST_ENV == "mysql" ]]
  then
    docker run --name=mysql -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% -d mysql/mysql-server:5.7
    docker run --name=activemq -d webcenter/activemq:latest
    sleep 150
    docker run -d --link mysql:mysql --link activemq:activemq --name=rucio rucio/rucio
    docker ps -a
fi

if [[ $TEST_ENV == "postgres" ]]
  then
    docker run --name=postgres -e POSTGRES_PASSWORD=secret -d postgres
    docker run --name=activemq -d webcenter/activemq:latest
    sleep 150
    docker run -d --link postgres:postgres --link activemq:activemq --name=rucio rucio/rucio
    docker ps -a
fi
