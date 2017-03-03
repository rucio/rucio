# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2017

"""
Core tracer module
"""

import json
import logging
import logging.handlers
import random

import dns.resolver
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter

ERRLOG = logging.getLogger('errlog')
ERRLOG.setLevel(logging.ERROR)

LOGGER = logging.getLogger('trace')
LOGGER.setLevel(logging.INFO)

HANDLER = logging.handlers.RotatingFileHandler(filename='%s/trace' % config_get('trace', 'tracedir'), maxBytes=1000000000, backupCount=10)

LOGFORMATTER = logging.Formatter('%(message)s')
HANDLER.setFormatter(LOGFORMATTER)
HANDLER.suffix = "%Y-%m-%d"
LOGGER.addHandler(HANDLER)

BROKERSALIAS = []

try:
    BROKERSALIAS = [b.strip() for b in config_get('trace', 'brokers').split(',')]
except:
    raise Exception('Could not load brokers from configuration')
PORT = config_get_int('trace', 'port')
TOPIC = config_get('trace', 'topic')
USERNAME = config_get('trace', 'username')
PASSWORD = config_get('trace', 'password')

logging.getLogger("stomp").setLevel(logging.CRITICAL)

BROKERSRESOLVED = []
for broker in BROKERSALIAS:
    try:
        BROKERSRESOLVED.append([str(tmp_broker) for tmp_broker in dns.resolver.query(broker, 'A')])
        BROKERSRESOLVED = [item for sublist in BROKERSRESOLVED for item in sublist]
    except:
        pass

CONNS = []

for broker in BROKERSRESOLVED:
    CONNS.append(stomp.Connection(host_and_ports=[(broker, PORT)], reconnect_attempts_max=3))


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

    try:
        conn = random.sample(CONNS, 1)[0]
        if not conn.is_connected():
            logging.info('reconnect to ' + conn.transport._Transport__host_and_ports[0][0])
            conn.start()
            conn.connect(USERNAME, PASSWORD)
        conn.send(body=report, destination=TOPIC, headers={'persistent': 'true', 'appversion': 'rucio'})
    except Exception, error:
        ERRLOG.error(error)
