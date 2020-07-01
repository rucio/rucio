#!/usr/bin/env python
# Copyright 2014-2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
#
# PY3K COMPATIBLE

'''
   Hernes2 is a daemon that get the messages and sends them to external services (influxDB, ES, ActiveMQ).
'''

import datetime
import json
import logging
import os
import re
import sys
import socket
import threading
import time
import traceback

from copy import deepcopy

import requests

from rucio.common.config import config_get
from rucio.core import heartbeat
from rucio.core.config import get
from rucio.core.message import retrieve_messages, delete_messages, update_messages_services
from rucio.common.exception import ConfigNotFound


logging.getLogger('requests').setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def default(datetype):
    if isinstance(datetype, (datetime.date, datetime.datetime)):
        return datetype.isoformat()


def submit_to_elastic(messages, endpoint, prepend_str):
    """
    Aggregate a list of message to ElascticSearch

    :param messages:     The list of messages.
    :param endpoint:     The ES endpoint were to send the messages.
    :param prepend_str:  The string to prepend to the logging.
    """
    text = ''
    for message in messages:
        services = message['services']
        if services and 'elastic' not in services.split(','):
            continue
        text += '{ "index":{ } }\n%s\n' % json.dumps(message, default=default)
    res = requests.post(endpoint, data=text, headers={'Content-Type': 'application/json'})
    return res.status_code


def aggregate_to_influx(messages, bin_size, endpoint, prepend_str):
    """
    Aggregate a list of message using a certain bin_size
    and submit them to a InfluxDB endpoint

    :param messages:     The list of messages.
    :param bin_size:     The size of the bins for the aggreagation (e.g. 10m, 1h, etc.).
    :param endpoint:     The InfluxDB endpoint were to send the messages.
    :param prepend_str:  The string to prepend to the logging.
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
            transferred_at = time.strptime(payload['transferred_at'], '%Y-%m-%d %H:%M:%S')
            if bin_size == '1m':
                transferred_at = int(datetime.datetime(*transferred_at[:5]).strftime('%s')) * 1000000000
                transferred_at += microsecond
            if transferred_at not in bins:
                bins[transferred_at] = {}
            src_rse, dest_rse, activity = payload['src-rse'], payload['dst-rse'], payload['activity']
            activity = re.sub(' ', '\ ', activity)  # noqa: W605
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
                created_at = created_at.replace(second=0, microsecond=0)
            created_at = int(created_at.strftime('%s')) * 1000000000
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
        logging.debug('%s %s', prepend_str, str(res.text))
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

    try:
        services_list = get('hermes', 'services_list')
        services_list = services_list.split(',')
    except ConfigNotFound as err:
        logging.debug('No services found, exiting')
        sys.exit(1)
    if 'influx' in services_list:
        try:
            influx_endpoint = config_get('hermes', 'influxdb_endpoint', False, None)
            if not influx_endpoint:
                logging.error('InfluxDB defined in the services list, but no endpoint can be find. Exiting')
                sys.exit(1)
        except Exception as err:
            logging.error(err)
    if 'elastic' in services_list:
        try:
            elastic_endpoint = config_get('hermes', 'elastic_endpoint', False, None)
            if not elastic_endpoint:
                logging.error('Elastic defined in the services list, but no endpoint can be find. Exiting')
                sys.exit(1)
        except Exception as err:
            logging.error(err)
    if 'activemq' in services_list:
        try:
            activemq_endpoint = config_get('hermes', 'activemq_endpoint', False, None)
            if not activemq_endpoint:
                logging.error('ActiveMQ defined in the services list, but no endpoint can be find. Exiting')
                sys.exit(1)
        except Exception as err:
            logging.error(err)

    executable = 'hermes2'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])

    # Make an initial heartbeat so that all daemons have the correct worker number on the next try
    GRACEFUL_STOP.wait(10)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)

    while not GRACEFUL_STOP.is_set():
        message_status = deepcopy(services_list)
        stime = time.time()
        try:
            start_time = time.time()
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            messages = retrieve_messages(bulk=bulk,
                                         thread=heart_beat['assign_thread'],
                                         total_threads=heart_beat['nr_threads'])

            if messages:
                logging.debug('%s Retrieved %i messages retrieved in %s seconds', prepend_str, len(messages), time.time() - start_time)
                if 'influx' in message_status:
                    logging.debug('%s Will submit to influxDB', prepend_str)
                    state = aggregate_to_influx(messages, bin_size='1m', endpoint=influx_endpoint, prepend_str=prepend_str)
                    if state in [204, 200]:
                        logging.info('%s Messages successfully submitted to influxDB', prepend_str)
                        message_status.remove('influx')
                    else:
                        logging.info('%s Failure to submit to influxDB', prepend_str)
                if 'elastic' in message_status:
                    state = submit_to_elastic(messages, endpoint=elastic_endpoint, prepend_str=prepend_str)
                    if state in [200, 204]:
                        logging.info('%s Messages successfully submitted to elastic', prepend_str)
                        message_status.remove('elastic')
                    else:
                        logging.info('%s Failure to submit to elastic', prepend_str)

                to_delete_or_update = []
                for message in messages:
                    to_delete_or_update.append({'id': message['id'],
                                                'created_at': message['created_at'],
                                                'updated_at': message['created_at'],
                                                'payload': str(message['payload']),
                                                'event_type': 'email'})
                if message_status == []:
                    delete_messages(messages=to_delete_or_update)
                else:
                    logging.info('%s Failure to submit to one service. Will update the message status', prepend_str)
                    update_messages_services(messages=to_delete_or_update, services=",".join(message_status))

            if once:
                break
            tottime = time.time() - stime
            if tottime < sleep_time:
                logging.info('%s Will sleep for %s seconds', prepend_str, sleep_time - tottime)
                time.sleep(sleep_time - tottime)

        except:
            logging.critical(traceback.format_exc())


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
        thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.isAlive()]
