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

'''
   Hermes is a daemon to deliver messages: to a messagebroker via STOMP, or emails via SMTP.
'''

import functools
import json
import logging
import random
import smtplib
import socket
import threading
import traceback

from email.mime.text import MIMEText
from typing import List, Dict, Any

import stomp

import rucio.db.sqla.util

from rucio.common import exception
from rucio.common.config import config_get, config_get_int, config_get_bool
from rucio.common.logging import setup_logging
from rucio.core.message import retrieve_messages, delete_messages
from rucio.core.monitor import MultiCounter
from rucio.daemons.common import HeartbeatHandler, run_daemon

logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('stomp').setLevel(logging.CRITICAL)

RECONNECT_COUNTER = MultiCounter(prom='rucio_daemons_hermes_reconnect', statsd='daemons.hermes.reconnect.{host}',
                                 documentation='Counts Hermes reconnects to different ActiveMQ brokers', labelnames=('host',))

graceful_stop = threading.Event()


def deliver_emails(once: bool = False,
                   send_email: bool = True,
                   thread: int = 0,
                   bulk: int = 1000,
                   sleep_time: int = 60) -> None:
    '''
    Main loop to deliver emails via SMTP.
    '''
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable='hermes [email]',
        logger_prefix='hermes_email',
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once_emails,
            send_email=send_email,
            thread=thread,
            bulk=bulk,
        )
    )


def run_once_emails(heartbeat_handler: HeartbeatHandler,
                    send_email: bool,
                    thread: int,
                    bulk: int,
                    **_kwargs: Dict[str, Any]) -> None:
    worker_number, total_workers, logger = heartbeat_handler.live()

    email_from = config_get('messaging-hermes', 'email_from')

    logger(logging.DEBUG, 'bulk %i', bulk)

    messages = retrieve_messages(bulk=bulk,
                                 thread=worker_number,
                                 total_threads=total_workers,
                                 event_type='email')

    if messages != []:
        to_delete = []
        for message in messages:
            logger(logging.DEBUG, 'submitting: %s', str(message))

            msg = MIMEText(message['payload']['body'])
            msg['From'] = email_from
            msg['To'] = ', '.join(message['payload']['to'])
            msg['Subject'] = message['payload']['subject']

            if send_email:
                smtp = smtplib.SMTP()
                smtp.connect()
                smtp.sendmail(msg['From'], message['payload']['to'], msg.as_string())
                smtp.quit()

            to_delete.append({'id': message['id'],
                              'created_at': message['created_at'],
                              'updated_at': message['created_at'],
                              'payload': str(message['payload']),
                              'event_type': 'email'})

            logger(logging.DEBUG, 'submitting done: %s',
                   str(message['id']))

        delete_messages(to_delete)
        logger(logging.INFO, 'submitted %i messages', len(to_delete))

    must_sleep = False
    if len(messages) < bulk:
        logger(logging.INFO, "Only %d messages, which is less than the bulk %d, will sleep"
               % (len(messages), bulk))
        must_sleep = True

    return must_sleep


class HermesListener(stomp.ConnectionListener):
    '''
    Hermes Listener
    '''
    def __init__(self, broker: str) -> None:
        '''
        __init__
        '''
        self.__broker = broker

    def on_error(self, frame: str) -> None:
        '''
        Error handler
        '''
        logging.error('[broker] [%s]: %s', self.__broker, frame.body)


def deliver_messages(once: bool = False,
                     brokers_resolved: List[str] = None,
                     thread: int = 0,
                     bulk: int = 1000,
                     broker_timeout: int = 3,
                     broker_retry: int = 3,
                     sleep_time: int = 60) -> None:
    '''
    Main loop to deliver messages to a broker.
    '''
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable='hermes [broker]',
        logger_prefix='hermes_broker',
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once_messages,
            brokers_resolved=brokers_resolved,
            thread=thread,
            bulk=bulk,
            sleep_time=sleep_time,
            broker_timeout=broker_timeout,
            broker_retry=broker_retry,
        )
    )


def run_once_messages(heartbeat_handler: HeartbeatHandler,
                      brokers_resolved: List[str],
                      thread: int,
                      bulk: int,
                      broker_timeout: int,
                      broker_retry: int,
                      **_kwargs: Dict[str, Any]) -> None:
    worker_number, total_workers, logger = heartbeat_handler.live()

    if not brokers_resolved:
        logging.fatal('No brokers resolved.')
        return

    if not broker_timeout:  # Allow zero in config
        broker_timeout = None

    logging.info('[broker] checking authentication method')
    use_ssl = True
    try:
        use_ssl = config_get_bool('messaging-hermes', 'use_ssl')
    except:
        logging.info('[broker] could not find use_ssl in configuration -- please update your rucio.cfg')

    port = config_get_int('messaging-hermes', 'port')
    vhost = config_get('messaging-hermes', 'broker_virtual_host', raise_exception=False)
    if not use_ssl:
        username = config_get('messaging-hermes', 'username')
        password = config_get('messaging-hermes', 'password')
        port = config_get_int('messaging-hermes', 'nonssl_port')

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            logging.info('[broker] setting up username/password authentication: %s' % broker)
            con = stomp.Connection12(host_and_ports=[(broker, port)],
                                     vhost=vhost,
                                     keepalive=True,
                                     timeout=broker_timeout)
        else:
            logging.info('[broker] setting up ssl cert/key authentication: %s' % broker)
            con = stomp.Connection12(host_and_ports=[(broker, port)],
                                     use_ssl=True,
                                     ssl_key_file=config_get('messaging-hermes', 'ssl_key_file'),
                                     ssl_cert_file=config_get('messaging-hermes', 'ssl_cert_file'),
                                     vhost=vhost,
                                     keepalive=True,
                                     )

        con.set_listener('rucio-hermes',
                         HermesListener(con.transport._Transport__host_and_ports[0]))

        conns.append(con)
    destination = config_get('messaging-hermes', 'destination')

    logger(logging.DEBUG, 'using: %s', [conn.transport._Transport__host_and_ports[0][0] for conn in conns])

    messages = retrieve_messages(bulk=bulk,
                                 thread=worker_number,
                                 total_threads=total_workers,
                                 old_mode=True)

    if messages:
        logger(logging.DEBUG, 'retrieved %i messages',
               len(messages))
        to_delete = []
        for message in messages:
            try:
                conn = random.sample(conns, 1)[0]
                if not conn.is_connected():
                    host_and_ports = conn.transport._Transport__host_and_ports[0][0]
                    RECONNECT_COUNTER.labels(host=host_and_ports.split('.')[0]).inc()
                    if not use_ssl:
                        logger(logging.INFO, 'connecting with USERPASS to %s',
                               host_and_ports)
                        conn.connect(username, password, wait=True)
                    else:
                        logger(logging.INFO, 'connecting with SSL to %s',
                               host_and_ports)
                        conn.connect(wait=True)

                conn.send(body=json.dumps({'event_type': str(message['event_type']).lower(),
                                           'payload': message['payload'],
                                           'created_at': str(message['created_at'])}),
                          destination=destination,
                          headers={'persistent': 'true',
                                   'event_type': str(message['event_type']).lower()})

                to_delete.append({'id': message['id'],
                                  'created_at': message['created_at'],
                                  'updated_at': message['created_at'],
                                  'payload': json.dumps(message['payload']),
                                  'event_type': message['event_type']})
            except ValueError:
                logger(logging.WARNING, 'Cannot serialize payload to JSON: %s',
                       str(message['payload']))
                to_delete.append({'id': message['id'],
                                  'created_at': message['created_at'],
                                  'updated_at': message['created_at'],
                                  'payload': str(message['payload']),
                                  'event_type': message['event_type']})
                continue
            except stomp.exception.NotConnectedException as error:
                logger(logging.WARNING, 'Could not deliver message due to NotConnectedException: %s',
                       str(error))
                continue
            except stomp.exception.ConnectFailedException as error:
                logger(logging.WARNING, 'Could not deliver message due to ConnectFailedException: %s',
                       str(error))
                continue
            except Exception as error:
                logger(logging.WARNING, 'Could not deliver message: %s', str(error))
                logger(logging.CRITICAL, traceback.format_exc())
                continue

            if str(message['event_type']).lower().startswith('transfer') or str(message['event_type']).lower().startswith('stagein'):
                logger(logging.DEBUG, 'event_type: %s, scope: %s, name: %s, rse: %s, request-id: %s, transfer-id: %s, created_at: %s',
                       str(message['event_type']).lower(),
                       message['payload'].get('scope', None),
                       message['payload'].get('name', None),
                       message['payload'].get('dst-rse', None),
                       message['payload'].get('request-id', None),
                       message['payload'].get('transfer-id', None),
                       str(message['created_at']))

            elif str(message['event_type']).lower().startswith('dataset'):
                logger(logging.DEBUG, 'event_type: %s, scope: %s, name: %s, rse: %s, rule-id: %s, created_at: %s)',
                       str(message['event_type']).lower(),
                       message['payload']['scope'],
                       message['payload']['name'],
                       message['payload']['rse'],
                       message['payload']['rule_id'],
                       str(message['created_at']))

            elif str(message['event_type']).lower().startswith('deletion'):
                if 'url' not in message['payload']:
                    message['payload']['url'] = 'unknown'
                logger(logging.DEBUG, 'event_type: %s, scope: %s, name: %s, rse: %s, url: %s, created_at: %s)',
                       str(message['event_type']).lower(),
                       message['payload']['scope'],
                       message['payload']['name'],
                       message['payload']['rse'],
                       message['payload']['url'],
                       str(message['created_at']))
            else:
                logger(logging.DEBUG, 'other message: %s',
                       message)

        delete_messages(to_delete)
        logger(logging.INFO, 'submitted %i messages',
               len(to_delete))

    must_sleep = False
    if len(messages) < bulk:
        logger(logging.INFO, "Only %d messages, which is less than the bulk %d, will sleep"
               % (len(messages), bulk))
        must_sleep = True

    return must_sleep


def stop(signum: int = None, frame: str = None) -> None:
    '''
    Graceful exit.
    '''
    logging.info('Caught CTRL-C - waiting for cycle to end before shutting down')
    graceful_stop.set()


def run(once: bool = False,
        send_email: bool = True,
        threads: int = 1,
        bulk: int = 1000,
        broker_timeout: int = 3,
        broker_retry: int = 3,
        sleep_time: int = 60) -> None:
    '''
    Starts up the hermes threads.
    '''
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('resolving brokers')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-hermes', 'brokers').split(',')]
    except:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s', brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        try:
            addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
            brokers_resolved.extend(ai[4][0] for ai in addrinfos)
        except socket.gaierror as ex:
            logging.error('Cannot resolve domain name %s (%s)', broker, str(ex))

    logging.debug('brokers resolved to %s', brokers_resolved)

    if once:
        logging.info('executing one hermes iteration only')
        deliver_messages(once=once,
                         brokers_resolved=brokers_resolved,
                         bulk=bulk,
                         broker_timeout=broker_timeout, broker_retry=broker_retry, sleep_time=sleep_time)
        deliver_emails(once=once,
                       send_email=send_email, bulk=bulk, sleep_time=sleep_time)

    else:
        logging.info('starting hermes threads')
        thread_list = [threading.Thread(target=deliver_messages, kwargs={'brokers_resolved': brokers_resolved,
                                                                         'thread': i,
                                                                         'bulk': bulk,
                                                                         'broker_timeout': broker_timeout,
                                                                         'broker_retry': broker_retry,
                                                                         'sleep_time': sleep_time}) for i in range(0, threads)]

        for thrd in range(0, 1):
            thread_list.append(threading.Thread(target=deliver_emails, kwargs={'thread': thrd,
                                                                               'bulk': bulk,
                                                                               'sleep_time': sleep_time}))

        for thrd in thread_list:
            thrd.start()

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [t.join(timeout=3.14) for t in thread_list if t and t.is_alive()]
