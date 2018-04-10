#!/bin/bash
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2018

if [[ $RDBMS == "oracle" ]]; then
    docker run -d -p 8080:8080 -p 1521:1521 --name=oracle -e processes=1000 -e sessions=1105 -e transactions=1215 -e ORACLE_ALLOW_REMOTE=true sath89/oracle-xe-11g
    docker run --name=activemq -d webcenter/activemq:latest
    sleep 100
    docker run -d --link oracle:oracle --link activemq:activemq --name=rucio rucio/rucio
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio httpd -k start

elif [[ $RDBMS == "mysql" ]]; then
    docker run --name=mysql -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% -d mysql/mysql-server:5.7
    docker run --name=activemq -d webcenter/activemq:latest
    sleep 100
    docker run -d --link mysql:mysql --link activemq:activemq --name=rucio rucio/rucio
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_mysql.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio httpd -k start


elif [[ $RDBMS == "postgres" ]]; then
    docker run --name=postgres -e POSTGRES_PASSWORD=secret -d postgres
    docker run --name=activemq -d webcenter/activemq:latest
    sleep 100
    docker run -d --link postgres:postgres --link activemq:activemq --name=rucio rucio/rucio
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_postgres.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio httpd -k start


elif [[ $RDBMS == "sqlite" ]]; then
    docker run -d -p 443:443  --name=rucio rucio/rucio
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_sqlite.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio httpd -k start
fi

if [[ $SUITE == "client" ]]; then
     docker exec -it rucio /bin/sh -c "/opt/rucio/tools/run_tests_docker.sh -i"
fi

if [ $? -ne 0 ]; then
    exit 1
fi
