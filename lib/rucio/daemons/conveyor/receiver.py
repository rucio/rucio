# Copyright 2015-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2015-2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2018
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
#
# PY3K COMPATIBLE

"""
Conveyor is a daemon to manage file transfers.
"""

from __future__ import division

import datetime
import json
import logging
import os
import socket
import sys
import threading
import time
import traceback

import stomp

from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.policy import get_policy
from rucio.core import heartbeat, request
from rucio.core.monitor import record_counter
from rucio.core.transfer import set_transfer_update_time
from rucio.db.sqla.constants import RequestState, FTSCompleteState


logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


class Receiver(object):

    def __init__(self, broker, id, total_threads, full_mode=False):
        self.__broker = broker
        self.__id = id
        self.__total_threads = total_threads
        self.__full_mode = full_mode

    def on_error(self, headers, message):
        record_counter('daemons.conveyor.receiver.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        record_counter('daemons.conveyor.receiver.message_all')

        try:
            msg = json.loads(message)
        except Exception:
            msg = json.loads(message[:-1])  # Note: I am not sure if this is needed anymore, this was due to an unparsable EOT character

        if 'vo' not in msg or msg['vo'] != get_policy():
            return

        if 'job_metadata' in msg.keys() \
           and isinstance(msg['job_metadata'], dict) \
           and 'issuer' in msg['job_metadata'].keys() \
           and str(msg['job_metadata']['issuer']) == str('rucio'):

            if 'job_m_replica' in msg.keys() and 'job_state' in msg.keys() \
               and (str(msg['job_m_replica']).lower() == str('false') or (str(msg['job_m_replica']).lower() == str('true') and str(msg['job_state']) != str('ACTIVE'))):

                if 'request_id' in msg['job_metadata']:
                    # submitted by old submitter
                    response = {'new_state': None,
                                'transfer_id': msg.get('tr_id').split("__")[-1],
                                'job_state': msg.get('t_final_transfer_state', None),
                                'src_url': msg.get('src_url', None),
                                'dst_url': msg.get('dst_url', None),
                                'transferred_at': datetime.datetime.utcfromtimestamp(float(msg.get('tr_timestamp_complete', 0)) / 1000),
                                'duration': (float(msg.get('tr_timestamp_complete', 0)) - float(msg.get('tr_timestamp_start', 0))) / 1000,
                                'reason': msg.get('t__error_message', None),
                                'scope': msg['job_metadata'].get('scope', None),
                                'name': msg['job_metadata'].get('name', None),
                                'src_rse': msg['job_metadata'].get('src_rse', None),
                                'dst_rse': msg['job_metadata'].get('dst_rse', None),
                                'request_id': msg['job_metadata'].get('request_id', None),
                                'activity': msg['job_metadata'].get('activity', None),
                                'src_rse_id': msg['job_metadata'].get('src_rse_id', None),
                                'dest_rse_id': msg['job_metadata'].get('dest_rse_id', None),
                                'previous_attempt_id': msg['job_metadata'].get('previous_attempt_id', None),
                                'adler32': msg['job_metadata'].get('adler32', None),
                                'md5': msg['job_metadata'].get('md5', None),
                                'filesize': msg['job_metadata'].get('filesize', None),
                                'external_host': msg.get('endpnt', None),
                                'job_m_replica': msg.get('job_m_replica', None),
                                'details': {'files': msg['job_metadata']}}
                else:
                    # for new submitter, file_metadata replace the job_metadata
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
                                'request_id': msg['file_metadata'].get('request_id', None),
                                'activity': msg['file_metadata'].get('activity', None),
                                'src_rse_id': msg['file_metadata'].get('src_rse_id', None),
                                'dest_rse_id': msg['file_metadata'].get('dest_rse_id', None),
                                'previous_attempt_id': msg['file_metadata'].get('previous_attempt_id', None),
                                'adler32': msg['file_metadata'].get('adler32', None),
                                'md5': msg['file_metadata'].get('md5', None),
                                'filesize': msg['file_metadata'].get('filesize', None),
                                'external_host': msg.get('endpnt', None),
                                'job_m_replica': msg.get('job_m_replica', None),
                                'details': {'files': msg['file_metadata']}}

                record_counter('daemons.conveyor.receiver.message_rucio')
                if str(msg['t_final_transfer_state']) == str(FTSCompleteState.OK):
                    response['new_state'] = RequestState.DONE
                elif str(msg['t_final_transfer_state']) == str(FTSCompleteState.ERROR):
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
                            record_counter('daemons.conveyor.receiver.update_request_state.%s' % ret)
                        else:
                            try:
                                logging.debug("Update request %s update time" % response['request_id'])
                                set_transfer_update_time(response['external_host'], response['transfer_id'], datetime.datetime.utcnow() - datetime.timedelta(hours=24))
                                record_counter('daemons.conveyor.receiver.set_transfer_update_time')
                            except Exception as error:
                                logging.debug("Failed to update transfer's update time: %s" % str(error))
                except Exception:
                    logging.critical(traceback.format_exc())


def receiver(id, total_threads=1, full_mode=False):
    """
    Main loop to consume messages from the FTS3 producer.
    """

    logging.info('receiver starting in full mode: %s' % full_mode)

    executable = 'conveyor-receiver'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()

    heartbeat.sanity_check(executable=executable, hostname=hostname)
    # Make an initial heartbeat so that all finishers have the correct worker number on the next try
    heartbeat.live(executable, hostname, pid, hb_thread)

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

    while not graceful_stop.is_set():

        heartbeat.live(executable, hostname, pid, hb_thread)

        for conn in conns:

            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.messaging.fts3.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])

                conn.set_listener('rucio-messaging-fts3', Receiver(broker=conn.transport._Transport__host_and_ports[0], id=id, total_threads=total_threads, full_mode=full_mode))
                conn.start()
                if not use_ssl:
                    conn.connect(username, password, wait=True)
                else:
                    conn.connect(wait=True)
                conn.subscribe(destination=config_get('messaging-fts3', 'destination'),
                               id='rucio-messaging-fts3',
                               ack='auto')

        time.sleep(1)

    logging.info('receiver graceful stop requested')

    for conn in conns:
        try:
            conn.disconnect()
        except Exception:
            pass

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('receiver graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, total_threads=1, full_mode=False):
    """
    Starts up the receiver thread
    """

    logging.info('starting receiver thread')
    threads = [threading.Thread(target=receiver, kwargs={'id': i,
                                                         'full_mode': full_mode,
                                                         'total_threads': total_threads}) for i in range(0, total_threads)]

    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.isAlive()]
