# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021

"""
Core tracer module
"""

import json
import logging.handlers
import random
import socket

import stomp
import ipaddress
from jsonschema import validate, ValidationError, draft7_format_checker

from rucio.common.config import config_get, config_get_int
from rucio.common.exception import InvalidObject
from rucio.common.schema.generic import SCOPE, RSE, UUID, TIME_ENTRY, IPv4orIPv6, CLIENT_STATE
from rucio.core.monitor import record_counter

CONFIG_COMMON_LOGLEVEL = getattr(logging, config_get('common', 'loglevel', raise_exception=False, default='DEBUG').upper())
CONFIG_COMMON_LOGFORMAT = config_get('common', 'logformat', raise_exception=False, default='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

CONFIG_TRACE_LOGLEVEL = getattr(logging, config_get('trace', 'loglevel', raise_exception=False, default='DEBUG').upper())
CONFIG_TRACE_LOGFORMAT = config_get('trace', 'logformat', raise_exception=False, default='%(message)s')
CONFIG_TRACE_TRACEDIR = config_get('trace', 'tracedir', raise_exception=False, default='/var/log/rucio')
CONFIG_TRACE_MAXBYTES = config_get_int('trace', 'maxbytes', raise_exception=False, default=1000000000)
CONFIG_TRACE_BACKUPCOUNT = config_get_int('trace', 'backupCount', raise_exception=False, default=10)

# reset root logger handlers. Otherwise everything from ROTATING_LOGGER will also end up in the apache logs.
logging.getLogger().handlers = []

LOGGER = logging.getLogger('trace')
LOGGER.setLevel(CONFIG_COMMON_LOGLEVEL)

ROTATING_LOGGER = logging.getLogger('trace_buffer')
ROTATING_LOGGER.setLevel(CONFIG_TRACE_LOGLEVEL)

HANDLER = logging.StreamHandler()
FORMATTER = logging.Formatter(CONFIG_COMMON_LOGFORMAT)
HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLER)

ROTATING_HANDLER = logging.handlers.RotatingFileHandler(filename='%s/trace' % CONFIG_TRACE_TRACEDIR, maxBytes=CONFIG_TRACE_MAXBYTES, backupCount=CONFIG_TRACE_BACKUPCOUNT)
ROTATING_LOGFORMATTER = logging.Formatter(CONFIG_TRACE_LOGFORMAT)
ROTATING_HANDLER.setFormatter(ROTATING_LOGFORMATTER)
ROTATING_LOGGER.addHandler(ROTATING_HANDLER)

BROKERS_ALIAS, BROKERS_RESOLVED = [], []
try:
    BROKERS_ALIAS = [b.strip() for b in config_get('trace', 'brokers').split(',')]
except:
    raise Exception('Could not load brokers from configuration')

PORT = config_get_int('trace', 'port')
TOPIC = config_get('trace', 'topic')
USERNAME = config_get('trace', 'username')
PASSWORD = config_get('trace', 'password')
VHOST = config_get('trace', 'broker_virtual_host', raise_exception=False)

TOUCH_SCHEMA = {
    "description": "touch one or more DIDs",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["touch"]},
        "clientState": CLIENT_STATE,
        "account": {"type": "string"},
        "scope": SCOPE,
        "filename": {"type": "string"},
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "localSite": RSE,
        "remoteSite": RSE,
        "usrdn": {"type": "string"},
    },
    "required": ['eventType', 'clientState', 'account', 'traceTimeentry', 'traceTimeentryUnix', 'traceIp', 'traceId']
}

UPLOAD_SCHEMA = {
    "description": "upload method",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["upload"]},
        "hostname": {"type": "string"},
        "eventVersion": {"type": "string"},
        "clientState": CLIENT_STATE,
        "account": {"type": "string"},
        "uuid": UUID,
        "scope": SCOPE,
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "remoteSite": RSE,
        "filesize": {"type": "number"},
        "protocol": {"type": "string"},
        "transferStart": {"type": "number"},
        "transferEnd": {"type": "number"},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "vo": {"type": "string"},
        "stateReason": {"type": "string"},
        "filename": {"type": "string"},
        "name": {"type": "string"},
        "usrdn": {"type": "string"},
    },
    "required": ['hostname', 'account', 'eventType', 'eventVersion', 'uuid', 'scope', 'dataset',
                 'remoteSite', 'filesize', 'protocol', 'transferStart', 'traceTimeentry', 'traceTimeentryUnix',
                 'traceIp', 'traceId']
}

DOWNLOAD_SCHEMA = {
    "description": "upload method",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["download"]},
        "hostname": {"type": "string"},
        "eventVersion": {"type": "string"},
        "localSite": RSE,
        "remoteSite": RSE,
        "account": {"type": "string"},
        "uuid": UUID,
        "scope": SCOPE,
        "filename": {"type": "string"},
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "filesize": {"type": ["number", "null"]},
        "clientState": CLIENT_STATE,
        "stateReason": {"type": "string"},
        "protocol": {"type": "string"},
        "transferStart": {"type": "number"},
        "transferEnd": {"type": "number"},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "vo": {"type": "string"},
        "usrdn": {"type": "string"},
        "name": {"type": "string"},
    },
    "required": ['hostname', 'eventType', 'localSite', 'account', 'eventVersion', 'uuid', 'scope',
                 'filename', 'datasetScope', 'dataset', 'filesize', 'clientState', 'stateReason']
}

GET_SCHEMA = {
    "description": "get method, mainly sent by pilots",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["get", "get_sm", "sm_get", "get_sm_a", "sm_get_a"]},
        "clientState": CLIENT_STATE,
        "stateReason": {"type": "string"},
        "url": {"type": "string"},
        "vo": {"type": "string"},
        "scope": SCOPE,
        "eventVersion": {"type": "string"},
        "remoteSite": RSE,
        "datasetScope": {"type": "string"},
        "dataset": {"type": "string"},
        "filename": {"type": "string"},
        "name": {"type": "string"},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "usrdn": {"type": "string"},
    },
    "required": ['eventType', 'localSite', 'eventVersion', 'uuid', 'scope',
                 'filename', 'dataset']
}

SCHEMAS = {
    'touch': TOUCH_SCHEMA,
    'upload': UPLOAD_SCHEMA,
    'download': DOWNLOAD_SCHEMA,
    'get': GET_SCHEMA,
    'get_sm': GET_SCHEMA,
    'sm_get': GET_SCHEMA,
    'get_sm_a': GET_SCHEMA,
    'sm_get_a': GET_SCHEMA
}

FORMAT_CHECKER = draft7_format_checker


@FORMAT_CHECKER.checks(format="ipv4_or_ipv6")
def ip_format_checker(value: str) -> bool:
    """
    Validates IPv4 or IPv6 string values. json schemas can use `ipv4_or_ipv6` as a valid `format` argument
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        LOGGER.debug(f"{value} is not a valid IPv4 or IPv6 address and raises an errors upon validation.")
        result = False
    else:
        result = True
    finally:
        return result


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
    Write a trace to the buffer log file and send it to active mq.

    :param payload: Python dictionary with trace report.
    """

    record_counter('trace.trace')
    report = json.dumps(payload, default=date_handler)
    ROTATING_LOGGER.debug(report)
    t_conns = CONNS[:]

    try:
        validate_schema(report)
    except InvalidObject as error:
        ROTATING_LOGGER.warning("Problem validating schema: %s" % error)
        LOGGER.warning("Problem validating schema: %s" % error)

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


def validate_schema(obj):
    """
    Validate object against json schema

    :param obj: The object to validate.

    :raises: ValidationError
    """
    obj = json.loads(obj)

    try:
        if obj and 'eventType' in obj:
            validate(obj, SCHEMAS.get(obj['eventType'].lower()), format_checker=FORMAT_CHECKER)
    except ValidationError as error:
        raise InvalidObject(error)
