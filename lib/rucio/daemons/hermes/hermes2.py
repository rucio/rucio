# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Eric Vaandering <ewv@fnal.gov>, 2021
# - Martin Barisits <martin.barisits@cern.ch>, 2021
# - Rahul Chauhan <omrahulchauhan@gmail.com>, 2021

'''
   Hermes2 is a daemon that get the messages and sends them to external services (influxDB, ES, ActiveMQ).
'''

import calendar
import copy
import datetime
import json
import logging
import os
import random
import re
import smtplib
import socket
import sys
import threading
import time
from email.mime.text import MIMEText

import requests
import stomp
from prometheus_client import Counter
from six import PY2

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_int, config_get_bool
from rucio.common.exception import ConfigNotFound, DatabaseException
from rucio.common.logging import setup_logging, formatted_logger
from rucio.core import heartbeat
from rucio.core.config import get
from rucio.core.message import retrieve_messages, delete_messages, update_messages_services
from rucio.core.monitor import record_counter

logging.getLogger('requests').setLevel(logging.CRITICAL)

GRACEFUL_STOP = threading.Event()

RECONNECT_COUNTER = Counter('rucio_daemons_hermes2_reconnect', 'Counts Hermes2 reconnects to different ActiveMQ brokers', labelnames=('host',))


def default(datetype):
    if isinstance(datetype, (datetime.date, datetime.datetime)):
        return datetype.isoformat()


class HermesListener(stomp.ConnectionListener):
    '''
    Hermes Listener
    '''

    def __init__(self, broker):
        '''
        __init__
        '''
        self.__broker = broker

    def on_error(self, frame):
        '''
        Error handler
        '''
        logging.error('[broker] [%s]: %s', self.__broker, frame.body)


def setup_activemq(logger):
    """
    Deliver messages to ActiveMQ

    :param logger:             The logger object.
    """

    logger(logging.INFO, '[broker] Resolving brokers')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [broker.strip() for broker in config_get('messaging-hermes', 'brokers').split(',')]
    except:
        raise Exception('Could not load brokers from configuration')

    logger(logging.INFO, '[broker] Resolving broker dns alias: %s', brokers_alias)
    brokers_resolved = []
    for broker in brokers_alias:
        try:
            addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
            brokers_resolved.extend(ai[4][0] for ai in addrinfos)
        except socket.gaierror as ex:
            logger(logging.ERROR, '[broker] Cannot resolve domain name %s (%s)', broker, str(ex))

    logger(logging.DEBUG, '[broker] Brokers resolved to %s', brokers_resolved)

    if not brokers_resolved:
        logger(logging.FATAL, '[broker] No brokers resolved.')
        return None, None, None, None, None

    broker_timeout = 3
    if not broker_timeout:  # Allow zero in config
        broker_timeout = None

    logger(logging.INFO, '[broker] Checking authentication method')
    use_ssl = True
    try:
        use_ssl = config_get_bool('messaging-hermes', 'use_ssl')
    except:
        logger(logging.INFO, '[broker] Could not find use_ssl in configuration -- please update your rucio.cfg')

    port = config_get_int('messaging-hermes', 'port')
    vhost = config_get('messaging-hermes', 'broker_virtual_host', raise_exception=False)
    if not use_ssl:
        username = config_get('messaging-hermes', 'username')
        password = config_get('messaging-hermes', 'password')
        port = config_get_int('messaging-hermes', 'nonssl_port')

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            logger(logging.INFO, '[broker] setting up username/password authentication: %s', broker)
            con = stomp.Connection12(host_and_ports=[(broker, port)],
                                     vhost=vhost,
                                     keepalive=True,
                                     timeout=broker_timeout)
        else:
            logger(logging.INFO, '[broker] setting up ssl cert/key authentication: %s', broker)
            con = stomp.Connection12(host_and_ports=[(broker, port)],
                                     use_ssl=True,
                                     ssl_key_file=config_get('messaging-hermes', 'ssl_key_file'),
                                     ssl_cert_file=config_get('messaging-hermes', 'ssl_cert_file'),
                                     vhost=vhost,
                                     keepalive=True,
                                     timeout=broker_timeout)

        con.set_listener('rucio-hermes',
                         HermesListener(con.transport._Transport__host_and_ports[0]))

        conns.append(con)
    destination = config_get('messaging-hermes', 'destination')
    return conns, destination, username, password, use_ssl


def deliver_to_activemq(messages, conns, destination, username, password, use_ssl, logger):
    """
    Deliver messages to ActiveMQ

    :param messages:           The list of messages.
    :param conns:              A list of connections.
    :param destination:        The destination topic or queue.
    :param username:           The username if no SSL connection.
    :param password:           The username if no SSL connection.
    :param use_ssl:            Boolean to choose if SSL connection is used.
    :param logger:             The logger object.
    """
    to_delete = []
    for message in messages:
        try:
            conn = random.sample(conns, 1)[0]
            if not conn.is_connected():
                host_and_ports = conn.transport._Transport__host_and_ports[0][0]
                record_counter('daemons.hermes.reconnect.%s' % host_and_ports.split('.')[0])
                labels = {'host': host_and_ports.split('.')[0]}
                RECONNECT_COUNTER.labels(**labels).inc()
                if not use_ssl:
                    logger(logging.INFO,
                           '[broker] - connecting with USERPASS to %s',
                           host_and_ports)
                    conn.connect(username, password, wait=True)
                else:
                    logger(logging.INFO,
                           '[broker] - connecting with SSL to %s',
                           host_and_ports)
                    conn.connect(wait=True)

            conn.send(body=json.dumps({'event_type': str(message['event_type']).lower(),
                                       'payload': message['payload'],
                                       'created_at': str(message['created_at'])}),
                      destination=destination,
                      headers={'persistent': 'true',
                               'event_type': str(message['event_type']).lower()})

            to_delete.append(message['id'])
        except ValueError:
            logger(logging.ERROR,
                   '[broker] Cannot serialize payload to JSON: %s',
                   str(message['payload']))
            to_delete.append(message['id'])
            continue
        except stomp.exception.NotConnectedException as error:
            logger(logging.WARNING,
                   '[broker] Could not deliver message due to NotConnectedException: %s',
                   str(error))
            continue
        except stomp.exception.ConnectFailedException as error:
            logger(logging.WARNING,
                   '[broker] Could not deliver message due to ConnectFailedException: %s',
                   str(error))
            continue
        except Exception as error:
            logger(logging.ERROR,
                   '[broker] Could not deliver message: %s',
                   str(error))
            continue

        if str(message['event_type']).lower().startswith('transfer') or str(message['event_type']).lower().startswith('stagein'):
            logger(logging.DEBUG,
                   '[broker] - event_type: %s, scope: %s, name: %s, rse: %s, request-id: %s, transfer-id: %s, created_at: %s',
                   str(message['event_type']).lower(),
                   message['payload'].get('scope', None),
                   message['payload'].get('name', None),
                   message['payload'].get('dst-rse', None),
                   message['payload'].get('request-id', None),
                   message['payload'].get('transfer-id', None),
                   str(message['created_at']))

        elif str(message['event_type']).lower().startswith('dataset'):
            logger(logging.DEBUG, '[broker] - event_type: %s, scope: %s, name: %s, rse: %s, rule-id: %s, created_at: %s)',
                   str(message['event_type']).lower(),
                   message['payload']['scope'],
                   message['payload']['name'],
                   message['payload']['rse'],
                   message['payload']['rule_id'],
                   str(message['created_at']))

        elif str(message['event_type']).lower().startswith('deletion'):
            if 'url' not in message['payload']:
                message['payload']['url'] = 'unknown'
            logger(logging.DEBUG,
                   '[broker] - event_type: %s, scope: %s, name: %s, rse: %s, url: %s, created_at: %s)',
                   str(message['event_type']).lower(),
                   message['payload']['scope'],
                   message['payload']['name'],
                   message['payload']['rse'],
                   message['payload']['url'],
                   str(message['created_at']))
        else:
            logger(logging.DEBUG,
                   '[broker] Other message: %s',
                   message)
    return to_delete


def deliver_emails(messages, logger):
    """
    Sends emails

    :param messages:           The list of messages.
    :param logger:             The logger object.
    """

    email_from = config_get('messaging-hermes', 'email_from')
    to_delete = []
    for message in messages:
        if message['event_type'] == 'email':

            if PY2:
                msg = MIMEText(message['payload']['body'].encode('utf-8'))
            else:
                msg = MIMEText(message['payload']['body'])

            msg['From'] = email_from
            msg['To'] = ', '.join(message['payload']['to'])
            if PY2:
                msg['Subject'] = message['payload']['subject'].encode('utf-8')
            else:
                msg['Subject'] = message['payload']['subject']

            try:
                smtp = smtplib.SMTP()
                smtp.connect()
                smtp.sendmail(msg['From'], message['payload']['to'], msg.as_string())
                smtp.quit()
                to_delete.append(message['id'])
            except Exception as error:
                logger(logging.ERROR, 'Cannot send email : %s', str(error))
        else:
            to_delete.append(message['id'])
            continue
    return to_delete


def submit_to_elastic(messages, endpoint, logger):
    """
    Aggregate a list of message to ElasticSearch

    :param messages:           The list of messages.
    :param endpoint:           The ES endpoint were to send the messages.
    :param logger:             The logger object.
    """
    text = ''
    for message in messages:
        services = message['services']
        if services and 'elastic' not in services.split(','):
            continue
        text += '{ "index":{ } }\n%s\n' % json.dumps(message, default=default)
    res = requests.post(endpoint, data=text, headers={'Content-Type': 'application/json'})
    return res.status_code


def aggregate_to_influx(messages, bin_size, endpoint, logger):
    """
    Aggregate a list of message using a certain bin_size
    and submit them to a InfluxDB endpoint

    :param messages:           The list of messages.
    :param bin_size:           The size of the bins for the aggreagation (e.g. 10m, 1h, etc.).
    :param endpoint:           The InfluxDB endpoint were to send the messages.
    :param logger:             The logger object.
    """
    bins = {}
    dtime = datetime.datetime.now()
    microsecond = dtime.microsecond

    for message in messages:
        services = message['services']
        if services and 'influx' not in services.split(','):
            continue
        event_type = message['event_type']
        payload = message['payload']
        if event_type in ['transfer-failed', 'transfer-done']:
            if not payload['transferred_at']:
                logger(logging.WARNING, 'No transferred_at for message. Reason : %s', payload['reason'])
                continue
            transferred_at = time.strptime(payload['transferred_at'], '%Y-%m-%d %H:%M:%S')
            if bin_size == '1m':
                transferred_at = int(calendar.timegm(transferred_at)) * 1000000000
                transferred_at += microsecond
            if transferred_at not in bins:
                bins[transferred_at] = {}
            src_rse, dest_rse, activity = payload['src-rse'], payload['dst-rse'], payload['activity']
            activity = re.sub(' ', r'\ ', activity)
            key = 'transfer,activity=%s,src_rse=%s,dst_rse=%s' % (activity, src_rse, dest_rse)
            if key not in bins[transferred_at]:
                bins[transferred_at][key] = [0, 0, 0, 0]
            if event_type == 'transfer-done':
                bins[transferred_at][key][0] += 1
                bins[transferred_at][key][1] += payload['bytes']
            if event_type == 'transfer-failed':
                bins[transferred_at][key][2] += 1
                bins[transferred_at][key][3] += payload['bytes']
        elif event_type in ['deletion-failed', 'deletion-done']:
            created_at = message['created_at']
            if bin_size == '1m':
                created_at = created_at.replace(second=0, microsecond=0, tzinfo=datetime.timezone.utc).timestamp()
            created_at = int(created_at) * 1000000000
            created_at += microsecond
            if created_at not in bins:
                bins[created_at] = {}
            rse = payload['rse']
            key = 'deletion,rse=%s' % (rse)
            if key not in bins[created_at]:
                bins[created_at][key] = [0, 0, 0, 0]
            if event_type == 'deletion-done':
                bins[created_at][key][0] += 1
                bins[created_at][key][1] += payload['bytes']
            if event_type == 'deletion-failed':
                bins[created_at][key][2] += 1
                bins[created_at][key][3] += payload['bytes']
    points = ''
    for timestamp in bins:
        for entry in bins[timestamp]:
            metrics = bins[timestamp][entry]
            event_type = entry.split(',')[0]
            point = '%s nb_%s_done=%s,bytes_%s_done=%s,nb_%s_failed=%s,bytes_%s_failed=%s %s' % (entry,
                                                                                                 event_type,
                                                                                                 metrics[0],
                                                                                                 event_type,
                                                                                                 metrics[1],
                                                                                                 event_type,
                                                                                                 metrics[2],
                                                                                                 event_type,
                                                                                                 metrics[3],
                                                                                                 timestamp)
            points += point
            points += '\n'
    if points:
        res = requests.post(endpoint, data=points)
        logger(logging.DEBUG, '%s', str(res.text))
        return res.status_code
    return 204


def hermes2(once=False, thread=0, bulk=1000, sleep_time=10):
    """
    Creates a Hermes2 Worker that can submit messages to different services (InfluXDB, ElasticSearch, ActiveMQ)
    The list of services need to be define in the config service in the hermes section.
    The list of endpoints need to be defined in rucio.cfg in the hermes section.

    :param once:       Run only once.
    :param thread:     Thread number at startup.
    :param bulk:       The number of requests to process.
    :param sleep_time: Time between two cycles.
    """

    executable = 'hermes2'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)

    # Make an initial heartbeat so that all daemons have the correct worker number on the next try
    GRACEFUL_STOP.wait(10)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
    prepend_str = 'hermes2[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prepend_str + '%s')

    try:
        services_list = get('hermes', 'services_list')
        services_list = services_list.split(',')
    except ConfigNotFound:
        logger(logging.DEBUG, 'No services found, exiting')
        sys.exit(1)
    if 'influx' in services_list:
        try:
            influx_endpoint = config_get('hermes', 'influxdb_endpoint', False, None)
            if not influx_endpoint:
                logger(logging.ERROR, 'InfluxDB defined in the services list, but no endpoint can be find. Exiting')
                sys.exit(1)
        except Exception as err:
            logger(logging.ERROR, str(err))
    if 'elastic' in services_list:
        try:
            elastic_endpoint = config_get('hermes', 'elastic_endpoint', False, None)
            if not elastic_endpoint:
                logger(logging.ERROR, 'Elastic defined in the services list, but no endpoint can be find. Exiting')
                sys.exit(1)
        except Exception as err:
            logger(logging.ERROR, str(err))
    if 'activemq' in services_list:
        try:
            # activemq_endpoint = config_get('hermes', 'activemq_endpoint', False, None)
            conns, destination, username, password, use_ssl = setup_activemq(logger)
            if not conns:
                logger(logging.ERROR, 'ActiveMQ defined in the services list, cannot be setup')
                sys.exit(1)
        except Exception as err:
            logger(logging.ERROR, str(err))

    while not GRACEFUL_STOP.is_set():
        message_status = copy.deepcopy(services_list)
        message_statuses = {}
        stime = time.time()
        try:
            start_time = time.time()
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'hermes2[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            logger = formatted_logger(logging.log, prepend_str + '%s')
            messages = retrieve_messages(bulk=bulk,
                                         thread=heart_beat['assign_thread'],
                                         total_threads=heart_beat['nr_threads'])

            if messages:
                for message in messages:
                    message_statuses[message['id']] = copy.deepcopy(services_list)
                logger(logging.DEBUG, 'Retrieved %i messages retrieved in %s seconds', len(messages), time.time() - start_time)

                if 'influx' in message_status:
                    t_time = time.time()
                    logger(logging.DEBUG, 'Will submit to influxDB')
                    try:
                        state = aggregate_to_influx(messages=messages, bin_size='1m', endpoint=influx_endpoint, logger=logger)
                    except Exception as error:
                        logger(logging.ERROR, 'Error sending to InfluxDB : %s', str(error))
                        state = 500
                    if state in [204, 200]:
                        logger(logging.INFO, 'Messages successfully submitted to influxDB in %s seconds', time.time() - t_time)
                        for message in messages:
                            message_statuses[message['id']].remove('influx')
                    else:
                        logger(logging.INFO, 'Failure to submit to influxDB')

                if 'elastic' in message_status:
                    t_time = time.time()
                    try:
                        state = submit_to_elastic(messages=messages, endpoint=elastic_endpoint, logger=logger)
                    except Exception as error:
                        logger(logging.ERROR, 'Error sending to Elastic : %s', str(error))
                        state = 500
                    if state in [200, 204]:
                        logger(logging.INFO, 'Messages successfully submitted to elastic in %s seconds', time.time() - t_time)
                        for message in messages:
                            message_statuses[message['id']].remove('elastic')
                    else:
                        logger(logging.INFO, 'Failure to submit to elastic')

                if 'emails' in message_status:
                    t_time = time.time()
                    try:
                        to_delete = deliver_emails(messages=messages, logger=logger)
                        logger(logging.INFO, 'Messages successfully submitted by emails in %s seconds', time.time() - t_time)
                        for message_id in to_delete:
                            message_statuses[message_id].remove('emails')
                    except Exception as error:
                        logger(logging.ERROR, 'Error sending email : %s', str(error))

                if 'activemq' in message_status:
                    t_time = time.time()
                    try:
                        to_delete = deliver_to_activemq(messages=messages, conns=conns, destination=destination, username=username, password=password, use_ssl=use_ssl, logger=logger)
                        logger(logging.INFO, 'Messages successfully submitted to ActiveMQ in %s seconds', time.time() - t_time)
                        for message_id in to_delete:
                            message_statuses[message_id].remove('activemq')
                    except Exception as error:
                        logger(logging.ERROR, 'Error sending to ActiveMQ : %s', str(error))

                to_delete = []
                to_update = {}
                for message in messages:
                    status = message_statuses[message['id']]
                    if not status:
                        to_delete.append({'id': message['id'],
                                          'created_at': message['created_at'],
                                          'updated_at': message['created_at'],
                                          'payload': str(message['payload']),
                                          'event_type': message['event_type']})
                    else:
                        status = ",".join(status)
                        if status not in to_update:
                            to_update[status] = []
                        to_update[status].append({'id': message['id'],
                                                  'created_at': message['created_at'],
                                                  'updated_at': message['created_at'],
                                                  'payload': str(message['payload']),
                                                  'event_type': message['event_type']})
                logger(logging.INFO, 'Deleting %s messages', len(to_delete))
                delete_messages(messages=to_delete)
                for status in to_update:
                    logger(logging.INFO, 'Failure to submit %s messages to %s. Will update the message status', str(len(to_update[status])), status)
                    update_messages_services(messages=to_update[status], services=status)

            if once:
                break
            tottime = time.time() - stime
            if tottime < sleep_time:
                logger(logging.INFO, 'Will sleep for %s seconds', sleep_time - tottime)
                time.sleep(sleep_time - tottime)

        except Exception:
            logger(logging.ERROR, "Failed to submit messages", exc_info=True)


def stop(signum=None, frame=None):
    '''
    Graceful exit.
    '''
    logging.info('Caught CTRL-C - waiting for cycle to end before shutting down')
    GRACEFUL_STOP.set()


def run(once=False, threads=1, bulk=1000, sleep_time=10, broker_timeout=3):
    '''
    Starts up the hermes2 threads.
    '''
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('starting hermes2 threads')
    thread_list = [threading.Thread(target=hermes2, kwargs={'thread': cnt,
                                                            'once': once,
                                                            'bulk': bulk,
                                                            'sleep_time': sleep_time}) for cnt in range(0, threads)]

    for thrd in thread_list:
        thrd.start()

    logging.debug(thread_list)
    # Interruptible joins require a timeout.
    while thread_list:
        thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.is_alive()]
