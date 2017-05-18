# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
#  - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2017
#  - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
#  - Wen Guan, <wen.guan@cern.ch>, 2014
#  - Vincent Garonne, <vincent.garonne@cern.ch>, 2015
#  - Martin Barisits, <martin.barisits@cern.ch>, 2017
'''
   Hermes is a daemon to deliver messages: to a messagebroker via STOMP, or emails via SMTP.
'''

import json
import logging
import os
import random
import smtplib
import socket
import ssl
import sys
import threading
import time
import traceback

from email.mime.text import MIMEText
from sqlalchemy.orm.exc import NoResultFound

import dns.resolver
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.message import retrieve_messages, delete_messages
from rucio.core.monitor import record_counter


logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('stomp').setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def deliver_emails(once=False, send_email=True, thread=0, bulk=1000, delay=10):
    '''
    Main loop to deliver emails via SMTP.
    '''

    logging.info('[email] starting - threads (%i) bulk (%i)' % (thread, bulk))

    executable = 'hermes [email]'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    sanity_check(executable=executable, hostname=hostname)

    # Make an initial heartbeat so that all daemons have the correct worker number on the next try
    live(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)
    graceful_stop.wait(1)

    email_from = config_get('messaging-hermes', 'email_from')

    while not graceful_stop.is_set():

        hb = live(executable, hostname, pid, hb_thread)
        logging.debug('[email] %i:%i - bulk %i' % (hb['assign_thread'],
                                                   hb['nr_threads'],
                                                   bulk))

        t_start = time.time()

        tmp = retrieve_messages(bulk=bulk,
                                thread=hb['assign_thread'],
                                total_threads=hb['nr_threads'],
                                event_type='email')

        if tmp != []:
            to_delete = []
            for t in tmp:
                logging.debug('[email] %i:%i - submitting: %s' % (hb['assign_thread'],
                                                                  hb['nr_threads'],
                                                                  str(t)))

                msg = MIMEText(t['payload']['body'].encode('utf-8'))

                msg['From'] = email_from
                msg['To'] = ', '.join(t['payload']['to'])
                msg['Subject'] = t['payload']['subject'].encode('utf-8')

                if send_email:
                    s = smtplib.SMTP()
                    s.connect()
                    s.sendmail(msg['From'], t['payload']['to'], msg.as_string())
                    s.quit()

                to_delete.append(t['id'])
                logging.debug('[email] %i:%i - submitting done: %s' % (hb['assign_thread'],
                                                                       hb['nr_threads'],
                                                                       str(t['id'])))

            delete_messages(to_delete)
            logging.info('[email] %i:%i - submitted %i messages' % (hb['assign_thread'],
                                                                    hb['nr_threads'],
                                                                    len(to_delete)))

        if once:
            break

        t_delay = delay - (time.time() - t_start)
        t_delay = t_delay if t_delay > 0 else 0
        if t_delay:
            logging.debug('[email] %i:%i - sleeping %s seconds' % (hb['assign_thread'], hb['nr_threads'], t_delay))
        time.sleep(t_delay)

    logging.debug('[email] %i:%i - graceful stop requested' % (hb['assign_thread'], hb['nr_threads']))

    die(executable, hostname, pid, hb_thread)

    logging.debug('[email] %i:%i - graceful stop done' % (hb['assign_thread'], hb['nr_threads']))


def deliver_messages(once=False, brokers_resolved=None, thread=0, bulk=1000, delay=10, broker_timeout=3, broker_retry=3):
    '''
    Main loop to deliver messages to a broker.
    '''

    logging.info('[broker] starting - threads (%i) bulk (%i)' % (thread, bulk))

    if not brokers_resolved:
        logging.fatal('No brokers resolved.')
        return

    conns = []
    for broker in brokers_resolved:
        conns.append({'conn': stomp.Connection(host_and_ports=[(broker, config_get_int('messaging-hermes', 'port'))],
                                               use_ssl=True,
                                               ssl_key_file=config_get('messaging-hermes', 'ssl_key_file'),
                                               ssl_cert_file=config_get('messaging-hermes', 'ssl_cert_file'),
                                               ssl_version=ssl.PROTOCOL_TLSv1,
                                               keepalive=True,
                                               timeout=broker_timeout),
                      'use': False,
                      'retry': 0})  # reconnect safeguard counter
    destination = config_get('messaging-hermes', 'destination')

    executable = 'hermes [broker]'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    # Make an initial heartbeat so that all daemons have the correct worker number on the next try
    sanity_check(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)

    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            t_start = time.time()

            hb = live(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)

            for conn in conns:

                if not conn['conn'].is_connected():
                    logging.info('[broker] %i:%i - connecting to %s' % (hb['assign_thread'],
                                                                        hb['nr_threads'],
                                                                        conn['conn'].transport._Transport__host_and_ports[0][0]))
                    record_counter('daemons.hermes.reconnect.%s' % conn['conn'].transport._Transport__host_and_ports[0][0].split('.')[0])

                    try:
                        if conn['retry'] >= broker_retry:
                            logging.warning('[broker] %i:%i - connection retrials exceeded, skipping this round: %s' % (hb['assign_thread'],
                                                                                                                        hb['nr_threads'],
                                                                                                                        conn['conn'].transport._Transport__host_and_ports[0][0]))
                            conn['retry'] = 0
                            conn['use'] = False
                            continue
                        else:
                            conn['conn'].start()
                            conn['conn'].connect()
                            conn['use'] = True
                    except stomp.exception.ConnectFailedException as e:
                        logging.warning('[broker] %i:%i - connection timeout, retrying: %s' % (hb['assign_thread'],
                                                                                               hb['nr_threads'],
                                                                                               conn['conn'].transport._Transport__host_and_ports[0][0]))
                        conn['retry'] += 1
                        conn['use'] = False

            usable_conns = [conn for conn in conns if conn['use']]
            logging.debug('[broker] %i:%i - using: %s' % (hb['assign_thread'],
                                                          hb['nr_threads'],
                                                          [uc['conn'].transport._Transport__host_and_ports[0][0] for uc in usable_conns]))

            tmp = retrieve_messages(bulk=bulk,
                                    thread=hb['assign_thread'],
                                    total_threads=hb['nr_threads'])

            if tmp != []:
                logging.debug('[broker] %i:%i - retrieved %i messages' % (hb['assign_thread'],
                                                                          hb['nr_threads'],
                                                                          len(tmp)))
                to_delete = []
                for t in tmp:

                    try:
                        random.sample(usable_conns, 1)[0]['conn'].send(body=json.dumps({'event_type': str(t['event_type']).lower(),
                                                                                        'payload': t['payload'],
                                                                                        'created_at': str(t['created_at'])}),
                                                                       destination=destination,
                                                                       headers={'persistent': 'true'})
                        to_delete.append(t['id'])
                    except ValueError:
                        logging.warn('Cannot serialize payload to JSON: %s' % str(t['payload']))
                        to_delete.append(t['id'])
                        continue
                    except Exception, e:
                        logging.warn('Could not deliver message: %s' % str(e))
                        continue

                    if str(t['event_type']).lower().startswith('transfer') or str(t['event_type']).lower().startswith('stagein'):
                        logging.debug('[broker] %i:%i - event_type: %s, scope: %s, name: %s, rse: %s, request-id: %s, transfer-id: %s, created_at: %s' % (hb['assign_thread'],
                                                                                                                                                          hb['nr_threads'],
                                                                                                                                                          str(t['event_type']).lower(),
                                                                                                                                                          t['payload'].get('scope', None),
                                                                                                                                                          t['payload'].get('name', None),
                                                                                                                                                          t['payload'].get('dst-rse', None),
                                                                                                                                                          t['payload'].get('request-id', None),
                                                                                                                                                          t['payload'].get('transfer-id', None),
                                                                                                                                                          str(t['created_at'])))
                    elif str(t['event_type']).lower().startswith('dataset'):
                        logging.debug('[broker] %i:%i - event_type: %s, scope: %s, name: %s, rse: %s, rule-id: %s, created_at: %s)' % (hb['assign_thread'],
                                                                                                                                       hb['nr_threads'],
                                                                                                                                       str(t['event_type']).lower(),
                                                                                                                                       t['payload']['scope'],
                                                                                                                                       t['payload']['name'],
                                                                                                                                       t['payload']['rse'],
                                                                                                                                       t['payload']['rule_id'],
                                                                                                                                       str(t['created_at'])))
                    elif str(t['event_type']).lower().startswith('deletion'):
                        if 'url' not in t['payload']:
                            t['payload']['url'] = 'unknown'
                        logging.debug('[broker] %i:%i - event_type: %s, scope: %s, name: %s, rse: %s, url: %s, created_at: %s)' % (hb['assign_thread'],
                                                                                                                                   hb['nr_threads'],
                                                                                                                                   str(t['event_type']).lower(),
                                                                                                                                   t['payload']['scope'],
                                                                                                                                   t['payload']['name'],
                                                                                                                                   t['payload']['rse'],
                                                                                                                                   t['payload']['url'],
                                                                                                                                   str(t['created_at'])))

                    else:
                        logging.debug('[broker] %i:%i - other message: %s' % (hb['assign_thread'],
                                                                              hb['nr_threads'],
                                                                              t))

                delete_messages(to_delete)
                logging.info('[broker] %i:%i - submitted %i messages' % (hb['assign_thread'],
                                                                         hb['nr_threads'],
                                                                         len(to_delete)))

                if once:
                    break

        except NoResultFound:
            # silence this error: https://its.cern.ch/jira/browse/RUCIO-1699
            pass
        except:
            logging.critical(traceback.format_exc())

        t_delay = delay - (time.time() - t_start)
        t_delay = t_delay if t_delay > 0 else 0
        if t_delay:
            logging.debug('[broker] %i:%i - sleeping %s seconds' % (hb['assign_thread'], hb['nr_threads'], t_delay))
        time.sleep(t_delay)

    logging.debug('[broker] %i:%i - graceful stop requested' % (hb['assign_thread'], hb['nr_threads']))

    for conn in conns:
        try:
            conn.disconnect()
        except:
            pass

    die(executable, hostname, pid, hb_thread)

    logging.debug('[broker] %i:%i - graceful stop done' % (hb['assign_thread'], hb['nr_threads']))

    return


def stop(signum=None, frame=None):
    '''
    Graceful exit.
    '''

    graceful_stop.set()


def run(once=False, send_email=True, threads=1, bulk=1000, delay=10, broker_timeout=3, broker_retry=3):
    '''
    Starts up the hermes threads.
    '''

    logging.info('resolving brokers')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-hermes', 'brokers').split(',')]
    except:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        try:
            brokers_resolved.append([str(tmp_broker) for tmp_broker in dns.resolver.query(broker, 'A')])
        except dns.resolver.NXDOMAIN:
            logging.error('Cannot resolve domain name %s', broker)

    brokers_resolved = [item for sublist in brokers_resolved for item in sublist]

    logging.debug('brokers resolved to %s', brokers_resolved)

    if once:
        logging.info('executing one hermes iteration only')
        deliver_messages(once=once, brokers_resolved=brokers_resolved, bulk=bulk, delay=delay, broker_timeout=broker_timeout, broker_retry=broker_retry)
        deliver_emails(once=once, send_email=send_email, bulk=bulk, delay=delay)

    else:
        logging.info('starting hermes threads')
        thread_list = [threading.Thread(target=deliver_messages, kwargs={'brokers_resolved': brokers_resolved,
                                                                         'thread': i,
                                                                         'bulk': bulk,
                                                                         'delay': delay,
                                                                         'broker_timeout': broker_timeout,
                                                                         'broker_retry': broker_retry}) for i in xrange(0, threads)]

        for i in xrange(0, threads):
            thread_list.append(threading.Thread(target=deliver_emails, kwargs={'thread': i,
                                                                               'bulk': bulk,
                                                                               'delay': delay}))

        [t.start() for t in thread_list]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(thread_list) > 0:
            thread_list = [t.join(timeout=3.14) for t in thread_list if t and t.isAlive()]
