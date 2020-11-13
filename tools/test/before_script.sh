#!/bin/bash
# Copyright 2018-2020 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

set -eo pipefail

# Note: this file is not run when RUN_HTTPD is defined as false for the test suite.

echo "* docker $CONTAINER_RUNTIME_ARGS info"
docker $CONTAINER_RUNTIME_ARGS info
echo
echo "* env"
env
echo

RESTART_HTTPD=0
if [ "$REST_BACKEND" == "flask" ]; then
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sed -i 's/Include \/opt\/rucio\/etc\/web\/aliases.conf/WSGIScriptAlias \/  \/opt\/rucio\/lib\/rucio\/web\/rest\/flaskapi\/v1\/main\.py/' /etc/httpd/conf.d/rucio.conf
    RESTART_HTTPD=1
fi

if [ $RDBMS == "oracle" ]; then
    CON_ORACLE=$(docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS -e processes=1000 -e sessions=1105 -e transactions=1215 -e ORACLE_ALLOW_REMOTE=true -e ORACLE_DISABLE_ASYNCH_IO=true docker.io/wnameless/oracle-xe-11g-r2)
    docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS docker.io/webcenter/activemq:latest
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c 'echo 127.0.0.1 oracle activemq >> /etc/hosts'

    docker $CONTAINER_RUNTIME_ARGS cp tools/test/oracle_startup.sh ${CON_ORACLE}:/
    docker $CONTAINER_RUNTIME_ARGS cp tools/test/oracle_wait.sh ${CON_ORACLE}:/
    docker $CONTAINER_RUNTIME_ARGS cp tools/test/oracle_setup.sh ${CON_ORACLE}:/
    date
    # sometimes, Oracle needs a little kick...
    docker $CONTAINER_RUNTIME_ARGS exec $CON_ORACLE /bin/bash -c "/oracle_startup.sh" || true
    for i in {1..60}; do
        sleep 2
        cont=$(bash -c 'docker '"$CONTAINER_RUNTIME_ARGS"' exec '"$CON_ORACLE"' /bin/bash -c "/oracle_wait.sh" 1>&2; echo $?')
        [ "$cont" -eq "0" ] && break
    done
    date
    if [ "$cont" -ne "0" ]; then
        echo Could not connect to Oracle in time.
        exit 1
    fi
    docker $CONTAINER_RUNTIME_ARGS exec $CON_ORACLE /bin/bash -c "/oracle_setup.sh"
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_oracle.cfg /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_oracle.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "mysql5" ]; then
    CON_MYSQL=$(docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% docker.io/mysql/mysql-server:5.7)
    docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS docker.io/webcenter/activemq:latest
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c 'echo 127.0.0.1 mysql5 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 2
        cont=$(bash -c 'ping=`docker '"$CONTAINER_RUNTIME_ARGS"' exec '"$CON_MYSQL"' mysqladmin --user=root --password=secret ping`; echo $ping 1>&2; echo $ping | grep "mysqld is alive" 1>&2; echo $?')
        [ "$cont" -eq "0" ] && break
    done
    date
    if [ "$cont" -ne "0" ]; then
        echo Could not connect to MySQL in time.
        exit 1
    fi
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql5.cfg /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql5.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "mysql8" ]; then
    CON_MYSQL=$(docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_ROOT_HOST=% docker.io/mysql/mysql-server:8.0 --default-authentication-plugin=mysql_native_password --character-set-server=latin1)
    docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS docker.io/webcenter/activemq:latest
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c 'echo 127.0.0.1 mysql8 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 4
        cont=$(bash -c 'ping=`docker '"$CONTAINER_RUNTIME_ARGS"' exec '"$CON_MYSQL"' mysqladmin --user=root --password=secret ping`; echo $ping 1>&2; echo $ping | grep "mysqld is alive" 1>&2; echo $?')
        [ "$cont" -eq "0" ] && break
    done
    date
    if [ "$cont" -ne "0" ]; then
        echo Could not connect to MySQL in time.
        exit 1
    fi
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql8.cfg /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql8.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "postgres9" ]; then
    CON_POSTGRES=$(docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS -e POSTGRES_PASSWORD=secret docker.io/postgres:9 -c 'max_connections=300')
    docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS docker.io/webcenter/activemq:latest
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c 'echo 127.0.0.1 postgres9 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 1
        cont=$(bash -c 'docker '"$CONTAINER_RUNTIME_ARGS"' exec '"$CON_POSTGRES"' pg_isready 1>&2; echo $?')
        [ "$cont" -eq "0" ] && break
    done
    date
    if [ "$cont" -ne "0" ]; then
        echo Could not connect to Postgres in time.
        exit 1
    fi
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres9.cfg /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres9.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "postgres12" ]; then
    CON_POSTGRES=$(docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS -e POSTGRES_PASSWORD=secret docker.io/postgres:12 -c 'max_connections=300')
    docker $CONTAINER_RUNTIME_ARGS run -d $CONTAINER_RUN_ARGS docker.io/webcenter/activemq:latest
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c 'echo 127.0.0.1 postgres12 activemq >> /etc/hosts'

    date
    for i in {1..30}; do
        sleep 1
        cont=$(bash -c 'docker '"$CONTAINER_RUNTIME_ARGS"' exec '"$CON_POSTGRES"' pg_isready 1>&2; echo $?')
        [ "$cont" -eq "0" ] && break
    done
    date
    if [ "$cont" -ne "0" ]; then
        echo Could not connect to Postgres in time.
        exit 1
    fi
    if [ $SUITE == "multi_vo" ]; then
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO mkdir -p /opt/rucio/etc/multi_vo/tst/etc
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO mkdir -p /opt/rucio/etc/multi_vo/ts2/etc
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_tst_postgres12.cfg /opt/rucio/etc/multi_vo/tst/etc/rucio.cfg
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_ts2_postgres12.cfg /opt/rucio/etc/multi_vo/ts2/etc/rucio.cfg
    fi
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres12.cfg /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres12.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "sqlite" ]; then
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/rucio_sqlite.cfg /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_sqlite.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1
fi

if [ "$RESTART_HTTPD" == "1" ]; then
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO httpd -k restart
fi

docker $CONTAINER_RUNTIME_ARGS ps -a
