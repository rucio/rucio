# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015

import json
import logging
import logging.handlers
import random

import dns.resolver
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter

errlog = logging.getLogger('errlog')
errlog.setLevel(logging.ERROR)

logger = logging.getLogger('trace')
logger.setLevel(logging.DEBUG)

handler = logging.handlers.RotatingFileHandler(filename='%s/trace' % config_get('nongrid-trace', 'tracedir'), maxBytes=1000000000, backupCount=10)

logFormatter = logging.Formatter('%(message)s')
handler.setFormatter(logFormatter)
handler.suffix = "%Y-%m-%d"
logger.addHandler(handler)

brokers_alias = []
brokers_resolved = []
try:
    brokers_alias = [b.strip() for b in config_get('nongrid-trace', 'brokers').split(',')]
except:
    raise Exception('Could not load brokers from configuration')
port = config_get_int('nongrid-trace', 'port')
topic = config_get('nongrid-trace', 'topic')
username = config_get('nongrid-trace', 'username')
password = config_get('nongrid-trace', 'password')

logging.getLogger("stomp").setLevel(logging.CRITICAL)

brokers_resolved = []
for broker in brokers_alias:
    try:
        brokers_resolved.append([str(tmp_broker) for tmp_broker in dns.resolver.query(broker, 'A')])
        brokers_resolved = [item for sublist in brokers_resolved for item in sublist]
    except:
        pass

conns = []

for broker in brokers_resolved:
    conns.append(stomp.Connection(host_and_ports=[(broker, port)], reconnect_attempts_max=3))


def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def trace(payload):
    """
    Write a trace to log file and send it to active mq.

    :param payload: Python dictionary with trace report.
    """

    record_counter('trace.nongrid_trace')
    report = json.dumps(payload, default=date_handler)
    logger.debug(report)

    try:
        conn = random.sample(conns, 1)[0]
        if not conn.is_connected():
            logging.info('reconnect to ' + conn.transport._Transport__host_and_ports[0][0])
            conn.start()
            conn.connect(username, password)
        conn.send(body=report, destination=topic, headers={'persistent': 'true', 'appversion': 'rucio'})
    except Exception, e:
        errlog.error(e)
