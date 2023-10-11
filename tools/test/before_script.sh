#!/bin/bash
# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

set -eo pipefail

# Note: this file is not run when RUN_HTTPD is defined as false for the test suite.

echo "* docker $CONTAINER_RUNTIME_ARGS info"
docker $CONTAINER_RUNTIME_ARGS info
echo
echo "* env"
env
echo

RESTART_HTTPD=0

if [ $RDBMS == "oracle" ]; then
    docker $CONTAINER_RUNTIME_ARGS cp tools/test/oracle_setup.sh ${CON_DB}:/
    docker $CONTAINER_RUNTIME_ARGS exec $CON_DB /oracle_setup.sh
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO python3 tools/merge_rucio_configs.py \
        -s /usr/local/src/rucio/etc/docker/test/extra/rucio_autotests_common.cfg  \
           /usr/local/src/rucio/etc/docker/test/extra/rucio_oracle.cfg  \
        --use-env \
        -d /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_oracle.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "mysql8" ]; then
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO python3 tools/merge_rucio_configs.py \
        -s /usr/local/src/rucio/etc/docker/test/extra/rucio_autotests_common.cfg  \
           /usr/local/src/rucio/etc/docker/test/extra/rucio_mysql8.cfg  \
        --use-env \
        -d /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_mysql8.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "postgres14" ]; then
    if [ $SUITE == "multi_vo" ]; then
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO mkdir -p /opt/rucio/etc/multi_vo/tst/etc
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO mkdir -p /opt/rucio/etc/multi_vo/ts2/etc
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO python3 tools/merge_rucio_configs.py \
            -s /usr/local/src/rucio/etc/docker/test/extra/rucio_autotests_common.cfg  \
               /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_tst_postgres14.cfg  \
            --use-env \
            -d /opt/rucio/etc/multi_vo/tst/etc/rucio.cfg
        docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO python3 tools/merge_rucio_configs.py \
            -s /usr/local/src/rucio/etc/docker/test/extra/rucio_autotests_common.cfg  \
               /usr/local/src/rucio/etc/docker/test/extra/rucio_multi_vo_ts2_postgres14.cfg  \
            --use-env \
            -d /opt/rucio/etc/multi_vo/ts2/etc/rucio.cfg
    fi
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO python3 tools/merge_rucio_configs.py \
        -s /usr/local/src/rucio/etc/docker/test/extra/rucio_autotests_common.cfg  \
           /usr/local/src/rucio/etc/docker/test/extra/rucio_postgres14.cfg \
        --use-env \
        -d /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_postgres14.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1

elif [ $RDBMS == "sqlite" ]; then
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO python3 tools/merge_rucio_configs.py \
        -s /usr/local/src/rucio/etc/docker/test/extra/rucio_autotests_common.cfg  \
           /usr/local/src/rucio/etc/docker/test/extra/rucio_sqlite.cfg \
        --use-env \
        -d /opt/rucio/etc/rucio.cfg
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO cp /usr/local/src/rucio/etc/docker/test/extra/alembic_sqlite.ini /opt/rucio/etc/alembic.ini
    RESTART_HTTPD=1
fi

echo 'Waiting for database to be ready'
if ! python3 -c "from rucio.db.sqla.session import wait_for_database; wait_for_database()"
then
    echo 'Cannot access database'
    exit 1
fi

if [ "$RESTART_HTTPD" == "1" ]; then
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO httpd -k restart
fi

docker $CONTAINER_RUNTIME_ARGS ps -a
