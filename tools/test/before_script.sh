#!/bin/bash
# Copyright 2018-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

set -eo pipefail

echo "* docker info"
docker info
echo
echo "* env"
env
echo

if [[ $RDBMS == "oracle" ]]; then
    # delete if directory exists
    rm -rf docker-oracle-xe-11g/
    git clone https://github.com/wnameless/docker-oracle-xe-11g.git
    docker build -t rucio/oraclexe --file docker-oracle-xe-11g/Dockerfile docker-oracle-xe-11g/
    # cleanup
    rm -rf docker-oracle-xe-11g/

    docker run -d -p 8080:8080 -p 1521:1521 --name=oracle -e processes=1000 -e sessions=1105 -e transactions=1215 -e ORACLE_ALLOW_REMOTE=true -e ORACLE_DISABLE_ASYNCH_IO=true rucio/oraclexe
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link oracle:oracle --link activemq:activemq $DOCKER_PASS_ENV --name=rucio $IMAGE
    docker cp tools/test/oracle_wait.sh oracle:/
    docker cp tools/test/oracle_setup.sh oracle:/
    date
    while ! docker exec oracle /bin/bash -c "/oracle_wait.sh" 2>&1; do
        sleep 1
    done
    date
    docker exec oracle /bin/bash -c "/oracle_setup.sh"
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_oracle.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "mysql5" ]]; then
    docker run --name=mysql5 -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% -d mysql/mysql-server:5.7
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link mysql5:mysql5 --link activemq:activemq $DOCKER_PASS_ENV --name=rucio $IMAGE
    date
    while ! docker exec mysql5 mysqladmin --user=root --password=secret ping 2>&1; do
        sleep 1
    done
    date
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql5.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql5.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "mysql8" ]]; then
    docker run --name=mysql8 -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% -d mysql/mysql-server:8.0 --default-authentication-plugin=mysql_native_password --character-set-server=latin1
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link mysql8:mysql8 --link activemq:activemq $DOCKER_PASS_ENV --name=rucio $IMAGE
    date
    while ! docker exec mysql8 mysqladmin --user=root --password=secret ping 2>&1; do
        sleep 1
    done
    date
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql8.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql8.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "postgres9" ]]; then
    docker run --name=postgres9 -e POSTGRES_PASSWORD=secret -d postgres:9 -c 'max_connections=300'
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link postgres9:postgres9 --link activemq:activemq $DOCKER_PASS_ENV --name=rucio $IMAGE
    date
    while ! docker exec postgres9 pg_isready 2>&1; do
        sleep 1
    done
    date
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres9.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres9.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "postgres12" ]]; then
    docker run --name=postgres12 -e POSTGRES_PASSWORD=secret -d postgres:12 -c 'max_connections=300'
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link postgres12:postgres12 --link activemq:activemq $DOCKER_PASS_ENV --name=rucio $IMAGE
    date
    while ! docker exec postgres12 pg_isready 2>&1; do
        sleep 1
    done
    date
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres12.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres12.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "sqlite" ]]; then
    docker run -d -p 443:443 $DOCKER_PASS_ENV --name=rucio $IMAGE
    if [[ $SUITE == "multi_vo" ]]; then
        docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_tst_sqlite.cfg /opt/rucio/etc/rucio_multi_vo_tst.cfg
        docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_ts2_sqlite.cfg /opt/rucio/etc/rucio_multi_vo_ts2.cfg
    else
        docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_sqlite.cfg /opt/rucio/etc/rucio.cfg
    fi
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_sqlite.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart
fi

docker ps -a
