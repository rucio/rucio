# -*- coding: utf-8 -*-
# Copyright 2016-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2021
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2020-2021
# - Eric Vaandering <ewv@fnal.gov>, 2021

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
from rucio.common.logging import setup_logging
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.message import add_message
from rucio.core.quarantined_replica import (list_quarantined_replicas,
                                            delete_quarantined_replicas,
                                            list_rses)
import rucio.core.rse as rse_core
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.rse import rsemanager as rsemgr

logging.getLogger("requests").setLevel(logging.CRITICAL)

GRACEFUL_STOP = threading.Event()


def reaper(rses, worker_number=0, total_workers=1, chunk_size=100, once=False, scheme=None):
    """
    Main loop to select and delete files.

    :param rses: List of RSEs the reaper should work against.
    :param worker_number: The worker number.
    :param total_workers:  The total number of workers.
    :param chunk_size: the size of chunk for deletion.
    :param once: If True, only runs one iteration of the main loop.
    :param scheme: Force the reaper to use a particular protocol, e.g., mock.
    """
    logging.info('Starting Dark Reaper %s-%s: Will work on RSEs: %s', worker_number, total_workers, ', '.join(rses))

    pid = os.getpid()
    thread = threading.current_thread()
    hostname = socket.gethostname()
    executable = ' '.join(sys.argv)
    hash_executable = hashlib.sha256((sys.argv[0] + ''.join(rses)).encode()).hexdigest()
    sanity_check(executable=None, hostname=hostname)

    while not GRACEFUL_STOP.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread,
                             hash_executable=hash_executable)
            logging.info('Dark Reaper({0[worker_number]}/{0[total_workers]}): Live gives {0[heartbeat]}'
                         .format(locals()))
            nothing_to_do = True

            rses_to_process = list(set(rses) & set(list_rses()))
            random.shuffle(rses_to_process)
            for rse_id in rses_to_process:
                replicas = list_quarantined_replicas(rse_id=rse_id,
                                                     limit=chunk_size, worker_number=worker_number,
                                                     total_workers=total_workers)

                rse_info = rsemgr.get_rse_info(rse_id=rse_id)
                rse = rse_info['rse']
                prot = rsemgr.create_protocol(rse_info, 'delete', scheme=scheme)
                deleted_replicas = []
                try:
                    prot.connect()
                    for replica in replicas:
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
                            logging.info('Dark Reaper %s-%s: Deletion ATTEMPT of %s:%s as %s on %s',
                                         worker_number, total_workers, scope, replica['name'], pfn, rse)
                            start = time.time()
                            prot.delete(pfn)
                            duration = time.time() - start
                            logging.info('Dark Reaper %s-%s: Deletion SUCCESS of %s:%s as %s on %s in %s seconds',
                                         worker_number, total_workers, scope, replica['name'], pfn, rse, duration)
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
                            err_msg = ('Dark Reaper %s-%s: Deletion NOTFOUND of %s:%s as %s on %s'
                                       % (worker_number, total_workers, scope, replica['name'], pfn, rse))
                            logging.warning(err_msg)
                            deleted_replicas.append(replica)
                        except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                            err_msg = ('Dark Reaper %s-%s: Deletion NOACCESS of %s:%s as %s on %s: %s'
                                       % (worker_number, total_workers, scope, replica['name'], pfn, rse, str(error)))
                            logging.warning(err_msg)
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
                logging.info('Dark Reaper %s-%s: Nothing to do. I will sleep for 60s', worker_number, total_workers)
                time.sleep(60)

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
        exclude_rses=None, include_rses=None, vos=None, delay_seconds=0):
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
        kwargs = {'worker_number': worker,
                  'total_workers': total_workers,
                  'rses': rses,
                  'once': once,
                  'chunk_size': chunk_size,
                  'scheme': scheme}
        threads.append(threading.Thread(target=reaper, kwargs=kwargs,
                                        name='Worker: %s, Total_Workers: %s' % (worker, total_workers)))
    [t.start() for t in threads]
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
