# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2017
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018

"""
Core tracer module
"""

import json
import logging
import logging.handlers
import random
import sys

import dns.resolver
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
except:
    if 'sphinx' not in sys.modules:
        raise

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
        for i in xrange(len(t_conns)):
            try:
                conn = random.sample(t_conns, 1)[0]
                if not conn.is_connected():
                    logging.info('reconnect to ' + conn.transport._Transport__host_and_ports[0][0])
                    conn.start()
                    conn.connect(USERNAME, PASSWORD)
            except stomp.exception.NotConnectedException, error:
                logging.warn('Could not connect to broker %s, try another one' %
                             conn.transport._Transport__host_and_ports[0][0])
                t_conns.remove(conn)
                continue
            except stomp.exception.ConnectFailedException as error:
                logging.warn('Could not connect to broker %s, try another one' %
                             conn.transport._Transport__host_and_ports[0][0])
                t_conns.remove(conn)
                continue

        if conn.is_connected:
            conn.send(body=report, destination=TOPIC, headers={'persistent': 'true', 'appversion': 'rucio'})
        else:
            logging.error("Unable to connect to broker. Could not send trace: %s" % report)
    except Exception, error:
        logging.error(error)
