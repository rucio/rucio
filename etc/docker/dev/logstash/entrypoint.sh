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

set -e

# The logstash jms input plugin needs the ActiveMQ client jar (see require_jars in pipeline.conf).
# The jar must stay on 5.x even if the broker moves to 6+: the plugin imports javax.jms, renamed in ActiveMQ 6.
ACTIVEMQ_VERSION=${ACTIVEMQ_VERSION:?must be set in docker-compose.yml}

JAR_LOCATION=/usr/share/logstash/data/jars/activemq-all-${ACTIVEMQ_VERSION}.jar

if [ ! -f "$JAR_LOCATION" ]; then
    echo "Downloading activemq-all-${ACTIVEMQ_VERSION}.jar from Maven Central to ${JAR_LOCATION}"
    curl -fsSL --create-dirs -o "$JAR_LOCATION" \
        "https://repo1.maven.org/maven2/org/apache/activemq/activemq-all/${ACTIVEMQ_VERSION}/activemq-all-${ACTIVEMQ_VERSION}.jar"
    echo "Download complete"
else
    echo "Using cached ${JAR_LOCATION}"
fi

exec /usr/local/bin/docker-entrypoint "$@"
