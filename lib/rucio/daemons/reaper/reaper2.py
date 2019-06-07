# Copyright 2016-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2019
# - Wen Guan <wguan.icedew@gmail.com>, 2016
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019
#
# PY3K COMPATIBLE

'''
Reaper is a daemon to manage file deletion.
'''

from __future__ import print_function, division

import logging
import os
import socket
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.common.exception import (DatabaseException, RSENotFound)
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rse import list_rses, get_rse_limits, get_rse_usage, list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression


logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def __check_rse_usage(rse, rse_id, prepend_str):
    """
    Internal method to check RSE usage and limits.

    :param rse_id: the rse name.
    :param rse_id: the rse id.

    :returns : max_being_deleted_files, needed_free_space, used, free.
    """
    max_being_deleted_files, needed_free_space, used, free, obsolete = None, None, None, None, None

    # Get RSE limits
    limits = get_rse_limits(rse=rse, rse_id=rse_id)
    if not limits and 'MinFreeSpace' not in limits and 'MaxBeingDeletedFiles' not in limits:
        return max_being_deleted_files, needed_free_space, used, free

    min_free_space = limits.get('MinFreeSpace')
    max_being_deleted_files = limits.get('MaxBeingDeletedFiles')

    # Check from which sources to get used and total spaces
    # Default is storage
    attributes = list_rse_attributes(rse)
    source_for_total_space = attributes.get('sourceForTotalSpace', 'storage')
    source_for_used_space = attributes.get('sourceForUsedSpace', 'storage')

    logging.debug('%s RSE: %s, source_for_total_space: %s, source_for_used_space: %s',
                  prepend_str, rse, source_for_total_space, source_for_used_space)

    # Get total, used and obsolete space
    rse_usage = get_rse_usage(rse=rse, rse_id=rse_id)
    usage = [entry for entry in rse_usage if entry['source'] == 'obsolete']
    for var in usage:
        obsolete = var['used']
        break
    usage = [entry for entry in rse_usage if entry['source'] == source_for_total_space]

    if not usage:
        if not obsolete:
            return max_being_deleted_files, needed_free_space, used, free
        return max_being_deleted_files, obsolete, used, free

    for var in usage:
        total, used = var['total'], var['used']
        break

    if source_for_total_space != source_for_used_space:
        usage = [entry for entry in rse_usage if entry['source'] == source_for_used_space]
        if not usage:
            return max_being_deleted_files, needed_free_space, None, free
        for var in usage:
            used = var['used']
            break

    free = total - used
    if min_free_space:
        needed_free_space = min_free_space - free

    # If needed_free_space negative, nothing to delete except if some Epoch tombstoned replicas
    if needed_free_space <= 0:
        needed_free_space = 0 or obsolete

    return max_being_deleted_files, needed_free_space, used, free


def reaper(rses, chunk_size=100,
           once=False, greedy=False, scheme=None, delay_seconds=0):
    """
    Main loop to select and delete files.

    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param chunk_size: the size of chunk for deletion.
    :param once: If True, only runs one iteration of the main loop.
    :param greedy: If True, delete right away replicas with tombstone.
    :param scheme: Force the reaper to use a particular protocol, e.g., mock.
    """

    hostname = socket.getfqdn()
    executable = sys.argv[0]
    pid = os.getpid()
    hb_thread = threading.current_thread()
    sanity_check(executable=executable, hostname=hostname)
    heart_beat = live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Reaper starting')

    time.sleep(10)  # To prevent running on the same partition if all the reapers restart at the same time
    heart_beat = live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Reaper started')

    while not GRACEFUL_STOP.is_set():

        try:
            dict_rses = {}
            heart_beat = live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
            for rse in rses:
                # Check if RSE is blacklisted
                if rse['availability'] % 2 == 0:
                    logging.debug('%s RSE %s is blacklisted for delete', prepend_str, rse['rse'])
                    continue
                max_being_deleted_files, needed_free_space, used, free = __check_rse_usage(rse['rse'], rse['id'], prepend_str)
                # Check if greedy mode
                if greedy:
                    dict_rses[(rse['rse'], rse['id'])] = [max_being_deleted_files, 100000000000000]
                else:
                    if needed_free_space:
                        dict_rses[(rse['rse'], rse['id'])] = [max_being_deleted_files, needed_free_space]
                    else:
                        logging.debug('%s Nothing to delete on %s', prepend_str, rse['rse'])

            logging.debug(prepend_str + str(dict_rses))
            # Call list_unlocked_replicas here
            # Actual deletion will take place there

            if once:
                break

            time.sleep(1)

        except DatabaseException as error:
            logging.warning('%s Reaper:  %s', prepend_str, str(error))
        except Exception:
            logging.critical(traceback.format_exc())

    die(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)
    logging.info('%s Graceful stop requested', prepend_str)
    logging.info('%s Graceful stop done', prepend_str)
    return


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(total_threads=1, chunk_size=100, once=False, greedy=False, rses=None, scheme=None, exclude_rses=None, include_rses=None, delay_seconds=0):
    """
    Starts up the reaper threads.

    :param total_threads: The total number of workers.
    :param chunk_size: the size of chunk for deletion.
    :param threads_per_worker: Total number of threads created by each worker.
    :param once: If True, only runs one iteration of the main loop.
    :param greedy: If True, delete right away replicas with tombstone.
    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param scheme: Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param exclude_rses: RSE expression to exclude RSEs from the Reaper.
    :param include_rses: RSE expression to include RSEs.
    """
    logging.info('main: starting processes')

    all_rses = list_rses()
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
        excluded_rses = parse_expression(exclude_rses)
        rses = [rse for rse in rses if rse not in excluded_rses]

    if include_rses:
        included_rses = parse_expression(include_rses)
        rses = [rse for rse in rses if rse in included_rses]

    if not rses:
        logging.error('Reaper: No RSEs found. Exiting.')
        return

    logging.info('Reaper: This instance will work on RSEs: ' + ', '.join([rse['rse'] for rse in rses]))

    logging.info('starting submitter threads')
    threads = [threading.Thread(target=reaper, kwargs={'once': once,
                                                       'rses': rses,
                                                       'chunk_size': chunk_size,
                                                       'greedy': greedy,
                                                       'delay_seconds': delay_seconds,
                                                       'scheme': scheme}) for _ in range(0, total_threads)]

    for thread in threads:
        thread.start()

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.isAlive()]
