# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2017
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

"""
Core tracer module
"""

import json
import logging
import logging.handlers
import random
import sys
import socket

import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter

ERRLOG = logging.getLogger('errlog')
ERRLOG.setLevel(logging.ERROR)

LOGGER = logging.getLogger('trace')
LOGGER.setLevel(logging.INFO)

try:
    HANDLER = logging.handlers.RotatingFileHandler(filename='%s/trace' % config_get('trace', 'tracedir'), maxBytes=1000000000, backupCount=10)
    LOGFORMATTER = logging.Formatter('%(message)s')
    HANDLER.setFormatter(LOGFORMATTER)
    HANDLER.suffix = "%Y-%m-%d"
    LOGGER.addHandler(HANDLER)
except:
    if 'sphinx' not in sys.modules:
        raise

BROKERS_ALIAS, BROKERS_RESOLVED = [], []
try:
    BROKERS_ALIAS = [b.strip() for b in config_get('trace', 'brokers').split(',')]
except:
    if 'sphinx' not in sys.modules:
        raise Exception('Could not load brokers from configuration')

try:
    PORT = config_get_int('trace', 'port')
    TOPIC = config_get('trace', 'topic')
    USERNAME = config_get('trace', 'username')
    PASSWORD = config_get('trace', 'password')
    VHOST = config_get('trace', 'broker_virtual_host', raise_exception=False)
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
    """ format dates to ISO format """
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def trace(payload):
    """
    Write a trace to log file and send it to active mq.

    :param payload: Python dictionary with trace report.
    """

    record_counter('trace.trace')
    report = json.dumps(payload, default=date_handler)
    LOGGER.debug(report)

    t_conns = CONNS[:]

    try:
        for i in range(len(t_conns)):
            try:
                conn = random.sample(t_conns, 1)[0]
                if not conn.is_connected():
                    logging.info('reconnect to ' + conn.transport._Transport__host_and_ports[0][0])
                    conn.start()
                    conn.connect(USERNAME, PASSWORD)
            except stomp.exception.NotConnectedException:
                logging.warning('Could not connect to broker %s, try another one' %
                                conn.transport._Transport__host_and_ports[0][0])
                t_conns.remove(conn)
                continue
            except stomp.exception.ConnectFailedException:
                logging.warning('Could not connect to broker %s, try another one' %
                                conn.transport._Transport__host_and_ports[0][0])
                t_conns.remove(conn)
                continue

        if conn.is_connected:
            conn.send(body=report, destination=TOPIC, headers={'persistent': 'true', 'appversion': 'rucio'})
        else:
            logging.error("Unable to connect to broker. Could not send trace: %s" % report)
    except Exception as error:
        logging.error(error)
