#!/bin/bash
# Copyright 2018-2019 CERN for the benefit of the ATLAS collaboration.
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

if [[ $RDBMS == "oracle" ]]; then
    docker run -d -p 8080:8080 -p 1521:1521 --name=oracle -e processes=1000 -e sessions=1105 -e transactions=1215 -e ORACLE_ALLOW_REMOTE=true -e ORACLE_DISABLE_ASYNCH_IO=true rucio/oraclexe
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link oracle:oracle --link activemq:activemq --name=rucio rucio/rucio
    docker cp tools/travis/oracle_wait.sh oracle:/
    docker cp tools/travis/oracle_setup.sh oracle:/
    date
    while ! docker exec -it oracle /bin/bash -c "/oracle_wait.sh" 2>&1; do
        sleep 1
    done
    date
    docker exec -it oracle /bin/bash -c "/oracle_setup.sh"
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/alembic_oracle.ini /opt/rucio/etc/alembic.ini
    docker exec -it rucio httpd -k restart

elif [[ $RDBMS == "mysql5" ]]; then
    docker run --name=mysql5 -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% -d mysql/mysql-server:5.7
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link mysql5:mysql5 --link activemq:activemq --name=rucio rucio/rucio
    date
    while ! docker exec mysql5 mysqladmin --user=root --password=secret ping 2>&1; do
        sleep 1
    done
    date
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_mysql5.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/alembic_mysql5.ini /opt/rucio/etc/alembic.ini
    docker exec -it rucio httpd -k restart

elif [[ $RDBMS == "mysql8" ]]; then
    docker run --name=mysql8 -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% -d mysql/mysql-server:8.0 --default-authentication-plugin=mysql_native_password --character-set-server=latin1
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link mysql8:mysql8 --link activemq:activemq --name=rucio rucio/rucio
    date
    while ! docker exec mysql8 mysqladmin --user=root --password=secret ping 2>&1; do
        sleep 1
    done
    date
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_mysql8.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/alembic_mysql8.ini /opt/rucio/etc/alembic.ini
    docker exec -it rucio httpd -k restart

elif [[ $RDBMS == "postgres9" ]]; then
    docker run --name=postgres9 -e POSTGRES_PASSWORD=secret -d postgres:9 -c 'max_connections=300'
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link postgres9:postgres9 --link activemq:activemq --name=rucio rucio/rucio
    date
    while ! docker exec postgres9 pg_isready 2>&1; do
        sleep 1
    done
    date
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_postgres9.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/alembic_postgres9.ini /opt/rucio/etc/alembic.ini
    docker exec -it rucio httpd -k restart

elif [[ $RDBMS == "postgres12" ]]; then
    docker run --name=postgres12 -e POSTGRES_PASSWORD=secret -d postgres:12 -c 'max_connections=300'
    docker run --name=activemq -d webcenter/activemq:latest
    docker run -d --link postgres12:postgres12 --link activemq:activemq --name=rucio rucio/rucio
    date
    while ! docker exec postgres12 pg_isready 2>&1; do
        sleep 1
    done
    date
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_postgres12.cfg /opt/rucio/etc/rucio.cfg
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/alembic_postgres12.ini /opt/rucio/etc/alembic.ini
    docker exec -it rucio httpd -k restart

elif [[ $RDBMS == "sqlite" ]]; then
    docker run -d -p 443:443  --name=rucio rucio/rucio
    if [[ $SUITE == "multi_vo" ]]; then
        docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_multi_vo_tst_sqlite.cfg /opt/rucio/etc/rucio_multi_vo_tst.cfg
        docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_multi_vo_ts2_sqlite.cfg /opt/rucio/etc/rucio_multi_vo_ts2.cfg
    else
        docker exec -it rucio cp /opt/rucio/etc/docker/travis/rucio_sqlite.cfg /opt/rucio/etc/rucio.cfg
    fi
    docker exec -it rucio cp /opt/rucio/etc/docker/travis/alembic_sqlite.ini /opt/rucio/etc/alembic.ini
    docker exec -it rucio httpd -k restart
fi

if [[ $SUITE == "client" ]]; then
     docker exec -it rucio /bin/sh -c "/opt/rucio/tools/run_tests_docker.sh -i"
fi

if [ $? -ne 0 ]; then
    exit 1
fi
