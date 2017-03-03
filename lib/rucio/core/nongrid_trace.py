'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
'''

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
LOGGER.setLevel(logging.DEBUG)

HANDLER = logging.handlers.RotatingFileHandler(filename='%s/trace' % config_get('nongrid-trace', 'tracedir'), maxBytes=1000000000, backupCount=10)

LOGFORMATTER = logging.Formatter('%(message)s')
HANDLER.setFormatter(LOGFORMATTER)
HANDLER.suffix = "%Y-%m-%d"
LOGGER.addHandler(HANDLER)

BROKERS_ALIAS, BROKERS_RESOLVED = [], []
try:
    BROKERS_ALIAS = [b.strip() for b in config_get('nongrid-trace', 'brokers').split(',')]
except:
    raise Exception('Could not load brokers from configuration')
PORT = config_get_int('nongrid-trace', 'port')
TOPIC = config_get('nongrid-trace', 'topic')
USERNAME = config_get('nongrid-trace', 'username')
PASSWORD = config_get('nongrid-trace', 'password')

logging.getLogger("stomp").setLevel(logging.CRITICAL)

for broker in BROKERS_ALIAS:
    try:
        BROKERS_RESOLVED.append([str(tmp_broker) for tmp_broker in dns.resolver.query(broker, 'A')])
        BROKERS_RESOLVED = [item for sublist in BROKERS_RESOLVED for item in sublist]
    except:
        pass

CONNS = []

for broker in BROKERS_RESOLVED:
    CONNS.append(stomp.Connection(host_and_ports=[(broker, PORT)], reconnect_attempts_max=3))


def date_handler(obj):
    '''
    '''
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def trace(payload):
    """
    Write a trace to log file and send it to active mq.

    :param payload: Python dictionary with trace report.
    """

    record_counter('trace.nongrid_trace')
    report = json.dumps(payload, default=date_handler)
    LOGGER.debug(report)

    try:
        conn = random.sample(CONNS, 1)[0]
        if not conn.is_connected():
            logging.info('reconnect to ' + conn.transport._Transport__host_and_ports[0][0])
            conn.start()
            conn.connect(USERNAME, PASSWORD)
        conn.send(body=report, destination=TOPIC, headers={'persistent': 'true', 'appversion': 'rucio'})
    except Exception as exception:
        ERRLOG.error(exception)
