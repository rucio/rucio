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
# - Wen Guan <wen.guan@cern.ch>, 2015-2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Sahan Dilshan <32576163+sahandilshan@users.noreply.github.com>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

"""
Conveyor is a daemon to manage file transfers.
"""

from __future__ import division

import datetime
import json
import logging
import socket
import threading
import time
import traceback

import stomp

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.constants import FTS_COMPLETE_STATE
from rucio.common.logging import setup_logging
from rucio.common.policy import get_policy
from rucio.core import request
from rucio.core.monitor import record_counter
from rucio.core.transfer import set_transfer_update_time, is_recoverable_fts_overwrite_error
from rucio.daemons.conveyor.common import HeartbeatHandler
from rucio.db.sqla.constants import RequestState

logging.getLogger("stomp").setLevel(logging.CRITICAL)

graceful_stop = threading.Event()


class Receiver(object):

    def __init__(self, broker, id_, total_threads, full_mode=False, all_vos=False):
        self.__all_vos = all_vos
        self.__broker = broker
        self.__id = id_
        self.__total_threads = total_threads
        self.__full_mode = full_mode

    def on_error(self, frame):
        record_counter('daemons.conveyor.receiver.error')
        logging.error('[%s] %s' % (self.__broker, frame.body))

    def on_message(self, frame):
        record_counter('daemons.conveyor.receiver.message_all')

        msg = json.loads(frame.body)

        if not self.__all_vos:
            if 'vo' not in msg or msg['vo'] != get_policy():
                return

        if 'job_metadata' in msg.keys() \
           and isinstance(msg['job_metadata'], dict) \
           and 'issuer' in msg['job_metadata'].keys() \
           and str(msg['job_metadata']['issuer']) == str('rucio'):

            if 'job_state' in msg.keys() and (
                    str(msg['job_state']) != str('ACTIVE')
                    or str(msg['job_state']) == str('ACTIVE') and 'job_m_replica' in msg.keys() and (str(msg['job_m_replica']).lower() == str('true'))):

                response = {'new_state': None,
                            'transfer_id': msg.get('tr_id').split("__")[-1],
                            'job_state': msg.get('t_final_transfer_state', None),
                            'src_url': msg.get('src_url', None),
                            'dst_url': msg.get('dst_url', None),
                            'started_at': datetime.datetime.utcfromtimestamp(float(msg.get('tr_timestamp_start', 0)) / 1000),
                            'transferred_at': datetime.datetime.utcfromtimestamp(float(msg.get('tr_timestamp_complete', 0)) / 1000),
                            'duration': (float(msg.get('tr_timestamp_complete', 0)) - float(msg.get('tr_timestamp_start', 0))) / 1000,
                            'reason': msg.get('t__error_message', None),
                            'scope': msg['file_metadata'].get('scope', None),
                            'name': msg['file_metadata'].get('name', None),
                            'src_type': msg['file_metadata'].get('src_type', None),
                            'dst_type': msg['file_metadata'].get('dst_type', None),
                            'src_rse': msg['file_metadata'].get('src_rse', None),
                            'dst_rse': msg['file_metadata'].get('dst_rse', None),
                            'dst_file': msg['file_metadata'].get('dst_file', {}),
                            'request_id': msg['file_metadata'].get('request_id', None),
                            'activity': msg['file_metadata'].get('activity', None),
                            'src_rse_id': msg['file_metadata'].get('src_rse_id', None),
                            'dest_rse_id': msg['file_metadata'].get('dest_rse_id', None),
                            'previous_attempt_id': msg['file_metadata'].get('previous_attempt_id', None),
                            'adler32': msg['file_metadata'].get('adler32', None),
                            'md5': msg['file_metadata'].get('md5', None),
                            'filesize': msg['file_metadata'].get('filesize', None),
                            'external_host': msg.get('endpnt', None),
                            'multi_sources': msg.get('job_metadata', {}).get('multi_sources', None),
                            'details': {'files': msg['file_metadata']}}

                record_counter('daemons.conveyor.receiver.message_rucio')
                if str(msg['t_final_transfer_state']) == FTS_COMPLETE_STATE.OK:  # pylint:disable=no-member
                    response['new_state'] = RequestState.DONE
                elif str(msg['t_final_transfer_state']) == FTS_COMPLETE_STATE.ERROR and is_recoverable_fts_overwrite_error(response):  # pylint:disable=no-member
                    response['new_state'] = RequestState.DONE
                elif str(msg['t_final_transfer_state']) == FTS_COMPLETE_STATE.ERROR:  # pylint:disable=no-member
                    response['new_state'] = RequestState.FAILED

                try:
                    if response['new_state']:
                        logging.info('RECEIVED DID %s:%s FROM %s TO %s REQUEST %s TRANSFER_ID %s STATE %s' % (response['scope'],
                                                                                                              response['name'],
                                                                                                              response['src_rse'],
                                                                                                              response['dst_rse'],
                                                                                                              response['request_id'],
                                                                                                              response['transfer_id'],
                                                                                                              response['new_state']))

                        if self.__full_mode:
                            ret = request.update_request_state(response)
                            record_counter('daemons.conveyor.receiver.update_request_state.{updated}', labels={'updated': ret})
                        else:
                            try:
                                logging.debug("Update request %s update time" % response['request_id'])
                                set_transfer_update_time(response['external_host'], response['transfer_id'], datetime.datetime.utcnow() - datetime.timedelta(hours=24))
                                record_counter('daemons.conveyor.receiver.set_transfer_update_time')
                            except Exception as error:
                                logging.debug("Failed to update transfer's update time: %s" % str(error))
                except Exception:
                    logging.critical(traceback.format_exc())


def receiver(id_, total_threads=1, full_mode=False, all_vos=False):
    """
    Main loop to consume messages from the FTS3 producer.
    """

    logging.info('receiver starting in full mode: %s' % full_mode)

    logger_prefix = executable = 'conveyor-receiver'

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-fts3', 'brokers').split(',')]
    except Exception:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        brokers_resolved.extend(ai[4][0] for ai in addrinfos)

    logging.info('brokers resolved to %s', brokers_resolved)

    logging.info('checking authentication method')
    use_ssl = True
    try:
        use_ssl = config_get_bool('messaging-fts3', 'use_ssl')
    except:
        logging.info('could not find use_ssl in configuration -- please update your rucio.cfg')

    port = config_get_int('messaging-fts3', 'port')
    vhost = config_get('messaging-fts3', 'broker_virtual_host', raise_exception=False)
    if not use_ssl:
        username = config_get('messaging-fts3', 'username')
        password = config_get('messaging-fts3', 'password')
        port = config_get_int('messaging-fts3', 'nonssl_port')

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            logging.info('setting up username/password authentication: %s' % broker)
            con = stomp.Connection12(host_and_ports=[(broker, port)],
                                     use_ssl=False,
                                     vhost=vhost,
                                     reconnect_attempts_max=999)
        else:
            logging.info('setting up ssl cert/key authentication: %s' % broker)
            con = stomp.Connection12(host_and_ports=[(broker, port)],
                                     use_ssl=True,
                                     ssl_key_file=config_get('messaging-fts3', 'ssl_key_file'),
                                     ssl_cert_file=config_get('messaging-fts3', 'ssl_cert_file'),
                                     vhost=vhost,
                                     reconnect_attempts_max=999)
        conns.append(con)

    logging.info('receiver started')

    with HeartbeatHandler(executable=executable, logger_prefix=logger_prefix) as heartbeat_handler:

        while not graceful_stop.is_set():

            _, logger = heartbeat_handler.live()

            for conn in conns:

                if not conn.is_connected():
                    logger(logging.INFO, 'connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                    record_counter('daemons.messaging.fts3.reconnect.{host}', labels={'host': conn.transport._Transport__host_and_ports[0][0].split('.')[0]})

                    conn.set_listener('rucio-messaging-fts3', Receiver(broker=conn.transport._Transport__host_and_ports[0],
                                                                       id_=id_, total_threads=total_threads,
                                                                       full_mode=full_mode, all_vos=all_vos))
                    if not use_ssl:
                        conn.connect(username, password, wait=True)
                    else:
                        conn.connect(wait=True)
                    conn.subscribe(destination=config_get('messaging-fts3', 'destination'),
                                   id='rucio-messaging-fts3',
                                   ack='auto')
            time.sleep(1)

        for conn in conns:
            try:
                conn.disconnect()
            except Exception:
                pass


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, total_threads=1, full_mode=False):
    """
    Starts up the receiver thread
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('starting receiver thread')
    threads = [threading.Thread(target=receiver, kwargs={'id_': i,
                                                         'full_mode': full_mode,
                                                         'total_threads': total_threads}) for i in range(0, total_threads)]

    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
