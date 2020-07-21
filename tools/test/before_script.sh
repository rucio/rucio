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

POD_NETWORK_ARG=$(if [[ -n "$POD" ]]; then echo "--pod $POD"; else echo "--network container:rucio"; fi)

if [[ $RDBMS == "oracle" ]]; then
    docker run -d --name oracle $POD_NETWORK_ARG -e processes=1000 -e sessions=1105 -e transactions=1215 -e ORACLE_ALLOW_REMOTE=true -e ORACLE_DISABLE_ASYNCH_IO=true docker.io/wnameless/oracle-xe-11g-r2
    docker run -d --name activemq $POD_NETWORK_ARG docker.io/webcenter/activemq:latest
    docker exec rucio sh -c 'echo 127.0.0.1 oracle activemq >> /etc/hosts'

    docker cp tools/test/oracle_startup.sh oracle:/
    docker cp tools/test/oracle_wait.sh oracle:/
    docker cp tools/test/oracle_setup.sh oracle:/
    date
    # sometimes, Oracle needs a little kick...
    docker exec oracle /bin/bash -c "/oracle_startup.sh" || true
    for i in {1..30}; do
        sleep 2
        cont=$(bash -c 'docker exec oracle /bin/bash -c "/oracle_wait.sh" 1>&2; echo $?')
        [[ "$cont" -eq "0" ]] && break
    done
    date
    if [[ "$cont" -ne "0" ]]; then
        echo Could not connect to Oracle in time.
        exit 1
    fi
    docker exec oracle /bin/bash -c "/oracle_setup.sh"
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_oracle.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "mysql5" ]]; then
    docker run -d --name mysql5 $POD_NETWORK_ARG -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% docker.io/mysql/mysql-server:5.7
    docker run -d --name activemq $POD_NETWORK_ARG docker.io/webcenter/activemq:latest
    docker exec rucio sh -c 'echo 127.0.0.1 mysql5 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 2
        cont=$(bash -c 'ping=`docker exec mysql5 mysqladmin --user=root --password=secret ping`; echo $ping 1>&2; echo $ping | grep "mysqld is alive" 1>&2; echo $?')
        [[ "$cont" -eq "0" ]] && break
    done
    date
    if [[ "$cont" -ne "0" ]]; then
        echo Could not connect to MySQL in time.
        exit 1
    fi
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql5.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql5.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "mysql8" ]]; then
    docker run -d --name mysql8 $POD_NETWORK_ARG -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% docker.io/mysql/mysql-server:8.0 --default-authentication-plugin=mysql_native_password --character-set-server=latin1
    docker run -d --name activemq $POD_NETWORK_ARG docker.io/webcenter/activemq:latest
    docker exec rucio sh -c 'echo 127.0.0.1 mysql8 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 4
        cont=$(bash -c 'ping=`docker exec mysql8 mysqladmin --user=root --password=secret ping`; echo $ping 1>&2; echo $ping | grep "mysqld is alive" 1>&2; echo $?')
        [[ "$cont" -eq "0" ]] && break
    done
    date
    if [[ "$cont" -ne "0" ]]; then
        echo Could not connect to MySQL in time.
        exit 1
    fi
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql8.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql8.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "postgres9" ]]; then
    docker run -d --name postgres9 $POD_NETWORK_ARG -e POSTGRES_PASSWORD=secret docker.io/postgres:9 -c 'max_connections=300'
    docker run -d --name activemq $POD_NETWORK_ARG docker.io/webcenter/activemq:latest
    docker exec rucio sh -c 'echo 127.0.0.1 postgres9 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 1
        cont=$(bash -c 'docker exec postgres9 pg_isready 1>&2; echo $?')
        [[ "$cont" -eq "0" ]] && break
    done
    date
    if [[ "$cont" -ne "0" ]]; then
        echo Could not connect to Postgres in time.
        exit 1
    fi
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres9.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres9.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "postgres12" ]]; then
    docker run -d --name postgres12 $POD_NETWORK_ARG -e POSTGRES_PASSWORD=secret docker.io/postgres:12 -c 'max_connections=300'
    docker run -d --name activemq $POD_NETWORK_ARG docker.io/webcenter/activemq:latest
    docker exec rucio sh -c 'echo 127.0.0.1 postgres12 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 1
        cont=$(bash -c 'docker exec postgres12 pg_isready 1>&2; echo $?')
        [[ "$cont" -eq "0" ]] && break
    done
    date
    if [[ "$cont" -ne "0" ]]; then
        echo Could not connect to Postgres in time.
        exit 1
    fi
    if [[ $SUITE == "multi_vo" ]]; then
        docker exec rucio mkdir -p /opt/rucio/etc/multi_vo/tst/etc
        docker exec rucio mkdir -p /opt/rucio/etc/multi_vo/ts2/etc
        docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_tst_postgres12.cfg /opt/rucio/etc/multi_vo/tst/etc/rucio.cfg
        docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_ts2_postgres12.cfg /opt/rucio/etc/multi_vo/ts2/etc/rucio.cfg
    fi
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres12.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres12.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart

elif [[ $RDBMS == "sqlite" ]]; then
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/rucio_sqlite.cfg /opt/rucio/etc/rucio.cfg
    docker exec rucio cp /usr/local/src/rucio/etc/docker/test/extra/alembic_sqlite.ini /opt/rucio/etc/alembic.ini
    docker exec rucio httpd -k restart
fi

docker ps -a
