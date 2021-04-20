# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2015-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2021

import json
import logging
import logging.handlers
import random
import sys
import socket

import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter

CONFIG_COMMON_LOGLEVEL = getattr(logging, config_get('common', 'loglevel', raise_exception=False, default='DEBUG').upper())
CONFIG_COMMON_LOGFORMAT = config_get('common', 'logformat', raise_exception=False, default='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

CONFIG_TRACE_LOGLEVEL = getattr(logging, config_get('nongrid-trace', 'loglevel', raise_exception=False, default='DEBUG').upper())
CONFIG_TRACE_LOGFORMAT = config_get('nongrid-trace', 'logformat', raise_exception=False, default='%(message)s')
CONFIG_TRACE_TRACEDIR = config_get('nongrid-trace', 'tracedir', raise_exception=False, default='/var/log/rucio')
CONFIG_TRACE_MAXBYTES = config_get_int('nongrid-trace', 'maxbytes', raise_exception=False, default=1000000000)
CONFIG_TRACE_BACKUPCOUNT = config_get_int('nongrid-trace', 'backupCount', raise_exception=False, default=10)

# reset root logger handlers. Otherwise everything from ROTATING_LOGGER will also end up in the apache logs.
logging.getLogger().handlers = []

LOGGER = logging.getLogger('nongrid_trace')
LOGGER.setLevel(CONFIG_COMMON_LOGLEVEL)

ROTATING_LOGGER = logging.getLogger('nongrid_trace_buffer')
ROTATING_LOGGER.setLevel(CONFIG_TRACE_LOGLEVEL)

try:
    HANDLER = logging.StreamHandler()
    FORMATTER = logging.Formatter(CONFIG_COMMON_LOGFORMAT)
    HANDLER.setFormatter(FORMATTER)
    LOGGER.addHandler(HANDLER)

    ROTATING_HANDLER = logging.handlers.RotatingFileHandler(filename='%s/trace' % CONFIG_TRACE_TRACEDIR, maxBytes=CONFIG_TRACE_MAXBYTES, backupCount=CONFIG_TRACE_BACKUPCOUNT)
    ROTATING_LOGFORMATTER = logging.Formatter(CONFIG_TRACE_LOGFORMAT)
    ROTATING_HANDLER.setFormatter(ROTATING_LOGFORMATTER)
    ROTATING_LOGGER.addHandler(ROTATING_HANDLER)
except:
    if 'sphinx' not in sys.modules:
        raise

BROKERS_ALIAS, BROKERS_RESOLVED = [], []
try:
    BROKERS_ALIAS = [b.strip() for b in config_get('nongrid-trace', 'brokers').split(',')]
except:
    if 'sphinx' not in sys.modules:
        raise Exception('Could not load brokers from configuration')

try:
    PORT = config_get_int('nongrid-trace', 'port')
    TOPIC = config_get('nongrid-trace', 'topic')
    USERNAME = config_get('nongrid-trace', 'username')
    PASSWORD = config_get('nongrid-trace', 'password')
    VHOST = config_get('nongrid-trace', 'broker_virtual_host', raise_exception=False)
except:
    if 'sphinx' not in sys.modules:
        raise

logging.getLogger("stomp").setLevel(logging.CRITICAL)

for broker in BROKERS_ALIAS:
    try:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        BROKERS_RESOLVED = [ai[4][0] for ai in addrinfos]
    except:
        pass

CONNS = []

for broker in BROKERS_RESOLVED:
    CONNS.append(stomp.Connection(host_and_ports=[(broker, PORT)], vhost=VHOST, reconnect_attempts_max=3))


def date_handler(obj):
    '''
    '''
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def trace(payload):
    """
    Write a trace to the buffer log file and send it to active mq.

    :param payload: Python dictionary with trace report.
    """

    record_counter('trace.trace')
    report = json.dumps(payload, default=date_handler)
    ROTATING_LOGGER.debug(report)
    t_conns = CONNS[:]

    try:
        for i in range(len(t_conns)):
            try:
                conn = random.sample(t_conns, 1)[0]
                if not conn.is_connected():
                    LOGGER.info('reconnect to ' + conn.transport._Transport__host_and_ports[0][0])
                    conn.connect(USERNAME, PASSWORD)
            except stomp.exception.NotConnectedException:
                LOGGER.warning('Could not connect to broker %s, try another one' %
                               conn.transport._Transport__host_and_ports[0][0])
                t_conns.remove(conn)
                continue
            except stomp.exception.ConnectFailedException:
                LOGGER.warning('Could not connect to broker %s, try another one' %
                               conn.transport._Transport__host_and_ports[0][0])
                t_conns.remove(conn)
                continue

        if conn.is_connected:
            conn.send(body=report, destination=TOPIC, headers={'persistent': 'true', 'appversion': 'rucio'})
        else:
            LOGGER.error("Unable to connect to broker. Could not send trace: %s" % report)
    except Exception as error:
        LOGGER.error(error)
