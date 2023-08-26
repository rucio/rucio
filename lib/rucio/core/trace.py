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

"""
Core tracer module
"""

import ipaddress
import json
import logging.handlers
import random
import socket

import stomp
from jsonschema import validate, ValidationError, Draft7Validator

from rucio.common.config import config_get, config_get_int
from rucio.common.exception import InvalidObject
from rucio.common.logging import rucio_log_formatter
from rucio.common.schema.generic import UUID, TIME_ENTRY, IPv4orIPv6
from rucio.core.monitor import MetricManager

METRICS = MetricManager(module=__name__)

CONFIG_COMMON_LOGLEVEL = getattr(logging, config_get('common', 'loglevel', raise_exception=False, default='DEBUG').upper())

CONFIG_TRACE_LOGLEVEL = getattr(logging, config_get('trace', 'loglevel', raise_exception=False, default='DEBUG').upper())
CONFIG_TRACE_LOGFORMAT = config_get('trace', 'logformat', raise_exception=False, default='%(message)s')
CONFIG_TRACE_TRACEDIR = config_get('trace', 'tracedir', raise_exception=False, default='/var/log/rucio/trace')
CONFIG_TRACE_MAXBYTES = config_get_int('trace', 'maxbytes', raise_exception=False, default=1000000000)
CONFIG_TRACE_BACKUPCOUNT = config_get_int('trace', 'backupCount', raise_exception=False, default=10)

# reset root logger handlers. Otherwise everything from ROTATING_LOGGER will also end up in the apache logs.
logging.getLogger().handlers = []

LOGGER = logging.getLogger('trace')
LOGGER.setLevel(CONFIG_COMMON_LOGLEVEL)

ROTATING_LOGGER = logging.getLogger('trace_buffer')
ROTATING_LOGGER.setLevel(CONFIG_TRACE_LOGLEVEL)

HANDLER = logging.StreamHandler()
FORMATTER = rucio_log_formatter()
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
        "clientState": {"type": "string"},
        "account": {"type": "string"},
        "scope": {"type": "string"},
        "filename": {"type": "string"},
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "localSite": {"type": "string"},
        "remoteSite": {"type": "string"},
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
        "clientState": {"type": "string"},
        "account": {"type": "string"},
        "uuid": UUID,
        "scope": {"type": "string"},
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "remoteSite": {"type": "string"},
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
    "description": "download method",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["download"]},
        "hostname": {"type": "string"},
        "eventVersion": {"type": "string"},
        "localSite": {"type": "string"},
        "remoteSite": {"type": "string"},
        "account": {"type": "string"},
        "uuid": UUID,
        "scope": {"type": "string"},
        "filename": {"type": "string"},
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "filesize": {"type": ["number", "null"]},
        "clientState": {"type": "string"},
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
        "clientState": {"type": "string"},
        "stateReason": {"type": "string"},
        "url": {"type": ["string", "null"]},
        "vo": {"type": "string"},
        "scope": {"type": "string"},
        "eventVersion": {"type": "string"},
        "remoteSite": {"type": "string"},
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

PUT_SCHEMA = {
    "description": "get method, mainly sent by pilots",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["put_sm", "put_sm_a"]},
        "clientState": {"type": "string"},
        "stateReason": {"type": "string"},
        "url": {"type": ["string", "null"]},
        "vo": {"type": "string"},
        "scope": {"type": "string"},
        "eventVersion": {"type": "string"},
        "remoteSite": {"type": "string"},
        "datasetScope": {"type": "string"},
        "dataset": {"type": "string"},
        "filename": {"type": "string"},
        "name": {"type": "string"},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "usrdn": {"type": "string"},
        "pq": {"type": "string"},
        "localSite": {"type": "string"}
    },
    "required": ['eventType', 'localSite', 'eventVersion', 'uuid',
                 'filename', 'dataset']
}

SPECIAL_SCHEMA = {
    "description": "A special schema to capture most unsupported eventTypes",
    "type": "object",
    "properties": {
        "eventType": {"enum": ["sfo2eos"]},
        "clientState": {"type": "string"},
        "account": {"type": "string"},
        "scope": {"type": "string"},
        "filename": {"type": "string"},
        "datasetScope": {"type": ["string", "null"]},
        "dataset": {"type": ["string", "null"]},
        "traceTimeentry": TIME_ENTRY,
        "traceTimeentryUnix": {"type": "number"},
        "traceIp": IPv4orIPv6,
        "traceId": UUID,
        "localSite": {"type": "string"},
        "remoteSite": {"type": "string"},
        "usrdn": {"type": "string"},
    },
    "required": ['eventType', 'clientState', 'account', 'traceTimeentry', 'traceTimeentryUnix', 'traceIp', 'traceId']
}

SCHEMAS = {
    'touch': TOUCH_SCHEMA,
    'upload': UPLOAD_SCHEMA,
    'download': DOWNLOAD_SCHEMA,
    'get': GET_SCHEMA,
    'get_sm': GET_SCHEMA,
    'sm_get': GET_SCHEMA,
    'get_sm_a': GET_SCHEMA,
    'sm_get_a': GET_SCHEMA,
    'put': PUT_SCHEMA,
    'put_sm': PUT_SCHEMA,
    'put_sm_a': PUT_SCHEMA,
    'sm_put': PUT_SCHEMA,
    'sm_put_a': PUT_SCHEMA,
    'sfo2eos': SPECIAL_SCHEMA
}

FORMAT_CHECKER = Draft7Validator.FORMAT_CHECKER


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


@METRICS.count_it
def trace(payload):
    """
    Write a trace to the buffer log file and send it to active mq.

    :param payload: Python dictionary with trace report.
    """

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

    :raises: InvalidObject
    """
    obj = json.loads(obj)

    try:
        if obj and 'eventType' in obj:
            event_type = SCHEMAS.get(obj['eventType'].lower())
            if not event_type:
                validation_error = ValidationError(message=f"Trace schema for eventType {obj['eventType']} is not currently supported.")
                validation_error.cause = "SCHEMA_NOT_FOUND"
                raise validation_error
            validate(obj, SCHEMAS.get(obj['eventType'].lower()), format_checker=FORMAT_CHECKER)
    except ValidationError as error:
        if error.cause == "SCHEMA_NOT_FOUND":
            LOGGER.error(error)
        else:
            raise InvalidObject(error)
