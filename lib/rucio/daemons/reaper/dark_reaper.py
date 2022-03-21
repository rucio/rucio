# -*- coding: utf-8 -*-
# Copyright 2016-2022 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2021
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020-2022
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2020-2021
# - Eric Vaandering <ewv@fnal.gov>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Joel Dierkes <joel.dierkes@cern.ch>, 2021

'''
Dark Reaper is a daemon to manage quarantined file deletion.
'''

import hashlib
import logging
import os
import random
import socket
import sys
import threading
import time
import traceback

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get_bool
from rucio.common.exception import (SourceNotFound, DatabaseException, ServiceUnavailable,
                                    RSEAccessDenied, ResourceTemporaryUnavailable,
                                    RSENotFound, VONotFound)
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.utils import daemon_sleep
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.message import add_message
from rucio.core.quarantined_replica import (list_quarantined_replicas,
                                            delete_quarantined_replicas,
                                            list_rses_with_quarantined_replicas)
import rucio.core.rse as rse_core
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.rse import rsemanager as rsemgr

logging.getLogger("requests").setLevel(logging.CRITICAL)

GRACEFUL_STOP = threading.Event()


def reaper(rses, chunk_size=100, once=False, scheme=None, sleep_time=300):
    """
    Main loop to select and delete files.

    :param rses: List of RSEs the reaper should work against.
    :param chunk_size: the size of chunk for deletion.
    :param once: If True, only runs one iteration of the main loop.
    :param scheme: Force the reaper to use a particular protocol, e.g., mock.
    :param sleep_time: Thread sleep time after each chunk of work.
    """

    pid = os.getpid()
    thread = threading.current_thread()
    hostname = socket.gethostname()
    executable = ' '.join(sys.argv)
    hash_executable = hashlib.sha256((sys.argv[0] + ''.join(rses)).encode()).hexdigest()
    sanity_check(executable=None, hostname=hostname)

    # heartbeat
    heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread,
                     hash_executable=hash_executable)
    prepend_str = 'dark-reaper [%i/%i] : ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
    logger = formatted_logger(logging.log, prepend_str + '%s')
    logger(logging.INFO, 'Starting Dark Reaper on RSEs: %s', ', '.join(rses))

    if not once:
        logger(logging.INFO, 'Waiting for heartbeat synchonization')
        GRACEFUL_STOP.wait(10)  # To prevent running on the same partition if all the reapers restart at the same time

    while not GRACEFUL_STOP.is_set():
        try:
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread,
                             hash_executable=hash_executable)
            prepend_str = 'dark-reaper [%i/%i] : ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
            logger = formatted_logger(logging.log, prepend_str + '%s')
            logger(logging.INFO, 'Live gives {0[heartbeat]}'.format(locals()))
            nothing_to_do = True
            start_time = time.time()

            rses_to_process = list(set(rses) & set(list_rses_with_quarantined_replicas()))
            random.shuffle(rses_to_process)
            for rse_id in rses_to_process:
                # The following query returns the list of real replicas (deleted_replicas) and list of dark replicas (dark_replicas)
                # Real replicas can be directly removed from the quarantine table
                deleted_replicas, dark_replicas = list_quarantined_replicas(rse_id=rse_id,
                                                                            limit=chunk_size,
                                                                            worker_number=heartbeat['assign_thread'],
                                                                            total_workers=heartbeat['nr_threads'])

                rse_info = rsemgr.get_rse_info(rse_id=rse_id)
                rse = rse_info['rse']
                prot = rsemgr.create_protocol(rse_info, 'delete', scheme=scheme)

                heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread,
                                 hash_executable=hash_executable)
                prepend_str = 'dark-reaper [%i/%i] : ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
                logger = formatted_logger(logging.log, prepend_str + '%s')
                try:
                    prot.connect()
                    for replica in dark_replicas:
                        nothing_to_do = False
                        scope = ''
                        if replica['scope']:
                            scope = replica['scope'].external
                        try:
                            pfn = str(list(rsemgr.lfns2pfns(rse_settings=rse_info,
                                                            lfns=[{'scope': scope,
                                                                   'name': replica['name'],
                                                                   'path': replica['path']}],
                                                            operation='delete',
                                                            scheme=scheme).values())[0])
                            logger(logging.INFO, 'Deletion ATTEMPT of %s:%s as %s on %s', scope, replica['name'], pfn, rse)
                            start = time.time()
                            prot.delete(pfn)
                            duration = time.time() - start
                            logger(logging.INFO, 'Deletion SUCCESS of %s:%s as %s on %s in %s seconds', scope, replica['name'], pfn, rse, duration)
                            payload = {'scope': scope,
                                       'name': replica['name'],
                                       'rse': rse,
                                       'rse_id': rse_id,
                                       'file-size': replica.get('bytes') or 0,
                                       'bytes': replica.get('bytes') or 0,
                                       'url': pfn,
                                       'duration': duration,
                                       'protocol': prot.attributes['scheme']}
                            if replica['scope'].vo != 'def':
                                payload['vo'] = replica['scope'].vo
                            add_message('deletion-done', payload)
                            deleted_replicas.append(replica)
                        except SourceNotFound:
                            err_msg = ('Deletion NOTFOUND of %s:%s as %s on %s'
                                       % (scope, replica['name'], pfn, rse))
                            logger(logging.WARNING, err_msg)
                            deleted_replicas.append(replica)
                        except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                            err_msg = ('Deletion NOACCESS of %s:%s as %s on %s: %s'
                                       % (scope, replica['name'], pfn, rse, str(error)))
                            logger(logging.WARNING, err_msg)
                            payload = {'scope': scope,
                                       'name': replica['name'],
                                       'rse': rse,
                                       'rse_id': rse_id,
                                       'file-size': replica['bytes'] or 0,
                                       'bytes': replica['bytes'] or 0,
                                       'url': pfn,
                                       'reason': str(error),
                                       'protocol': prot.attributes['scheme']}
                            if replica['scope'].vo != 'def':
                                payload['vo'] = replica['scope'].vo
                            add_message('deletion-failed', payload)

                        except Exception:
                            logging.critical(traceback.format_exc())
                finally:
                    prot.close()

                delete_quarantined_replicas(rse_id=rse_id, replicas=deleted_replicas)

                if once:
                    break

            if once:
                break

            if nothing_to_do:
                logger(logging.INFO, 'Nothing to do')
                daemon_sleep(start_time=start_time, sleep_time=sleep_time, graceful_stop=GRACEFUL_STOP)

        except DatabaseException as error:
            logging.warning('Reaper:  %s', str(error))
        except Exception:
            logging.critical(traceback.format_exc())

    die(executable=executable, hostname=hostname, pid=pid, thread=thread, hash_executable=hash_executable)
    logging.info('Graceful stop requested')
    logging.info('Graceful stop done')
    return


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(total_workers=1, chunk_size=100, once=False, rses=[], scheme=None,
        exclude_rses=None, include_rses=None, vos=None, delay_seconds=0, sleep_time=300):
    """
    Starts up the reaper threads.

    :param total_workers: The total number of workers.
    :param chunk_size: the size of chunk for deletion.
    :param once: If True, only runs one iteration of the main loop.
    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs (Single-VO only).
    :param scheme: Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param exclude_rses: RSE expression to exclude RSEs from the Reaper.
    :param include_rses: RSE expression to include RSEs.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If None, we either use all VOs if run from "def", or the current VO otherwise.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('main: starting processes')

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logging.warning('Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '',
                                                       ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logging.info('Dark Reaper: This instance will work on VO%s: %s'
                     % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    all_rses = []
    for vo in vos:
        all_rses.extend([rse['id'] for rse in rse_core.list_rses(filters={'vo': vo})])

    if rses:
        invalid = set(rses) - set([rse['rse'] for rse in all_rses])
        if invalid:
            msg = 'RSE{} {} cannot be found'.format('s' if len(invalid) > 1 else '',
                                                    ', '.join([repr(rse) for rse in invalid]))
            raise RSENotFound(msg)
        rses = [rse for rse in all_rses if rse['rse'] in rses]
    else:
        rses = all_rses

    if exclude_rses:
        excluded_rses = [rse['id'] for rse in parse_expression(exclude_rses)]
        rses = [rse for rse in rses if rse not in excluded_rses]

    if include_rses:
        included_rses = [rse['id'] for rse in parse_expression(include_rses)]
        rses = [rse for rse in rses if rse in included_rses]

    if not rses:
        logging.error('Dark Reaper: No RSEs found. Exiting.')
        return

    threads = []
    for worker in range(total_workers):
        kwargs = {'rses': rses,
                  'once': once,
                  'chunk_size': chunk_size,
                  'scheme': scheme,
                  'sleep_time': sleep_time}
        threads.append(threading.Thread(target=reaper, kwargs=kwargs,
                                        name='Worker: %s, Total_Workers: %s' % (worker, total_workers)))
    [t.start() for t in threads]
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
