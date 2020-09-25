# -*- coding: utf-8 -*-
# Copyright 2016-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2019
# - Wen Guan <wen.guan@cern.ch>, 2016
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

'''
Reaper is a daemon to manage file deletion.
'''

from __future__ import print_function, division

import datetime
import hashlib
import logging
import math
import os
import random
import socket
import sys
import threading
import time
import traceback

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import (SourceNotFound, ServiceUnavailable, RSEAccessDenied,
                                    ReplicaUnAvailable, ResourceTemporaryUnavailable,
                                    DatabaseException, UnsupportedOperation,
                                    ReplicaNotFound, RSENotFound, VONotFound)
from rucio.common.utils import chunks
from rucio.core import monitor
from rucio.core import rse as rse_core
from rucio.core.credential import get_signed_url
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.message import add_message
from rucio.core.replica import (list_unlocked_replicas, update_replicas_states,
                                delete_replicas)
from rucio.core.rse import get_rse_attribute, sort_rses, get_rse_name
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.constants import ReplicaState
from rucio.rse import rsemanager as rsemgr

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def __check_rse_usage(rse_id):
    """
    Internal method to check RSE usage and limits.

    :param rse_id: the rse id.

    :returns : max_being_deleted_files, needed_free_space, used, free.
    """
    max_being_deleted_files, needed_free_space, used, free = None, None, None, None

    rse = get_rse_name(rse_id=rse_id)
    # Get RSE limits
    limits = rse_core.get_rse_limits(rse_id=rse_id)
    if not limits and 'MinFreeSpace' not in limits and 'MaxBeingDeletedFiles' not in limits:
        return max_being_deleted_files, needed_free_space, used, free

    min_free_space = limits.get('MinFreeSpace')
    max_being_deleted_files = limits.get('MaxBeingDeletedFiles')

    # Check from which sources to get used and total spaces
    # Default is storage
    source_for_total_space, source_for_used_space = 'storage', 'storage'
    values = get_rse_attribute(rse_id=rse_id, key='source_for_total_space')
    if values:
        source_for_total_space = values[0]
    values = get_rse_attribute(rse_id=rse_id, key='source_for_used_space')
    if values:
        source_for_used_space = values[0]

    logging.debug('RSE: %(rse)s, source_for_total_space: %(source_for_total_space)s, '
                  'source_for_used_space: %(source_for_used_space)s' % locals())

    # Get total and used space
    usage = rse_core.get_rse_usage(rse_id=rse_id, source=source_for_total_space)
    if not usage:
        return max_being_deleted_files, needed_free_space, used, free
    for var in usage:
        total, used = var['total'], var['used']
        break

    if source_for_total_space != source_for_used_space:
        usage = rse_core.get_rse_usage(rse_id=rse_id, source=source_for_used_space)
        if not usage:
            return max_being_deleted_files, needed_free_space, None, free
        for var in usage:
            used = var['used']
            break

    free = total - used
    if min_free_space:
        needed_free_space = min_free_space - free

    return max_being_deleted_files, needed_free_space, used, free


def reaper(rses, worker_number=0, child_number=0, total_children=1, chunk_size=100,
           once=False, greedy=False, scheme=None, delay_seconds=0):
    """
    Main loop to select and delete files.

    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param worker_number: The worker number.
    :param child_number: The child number.
    :param total_children: The total number of children created per worker.
    :param chunk_size: the size of chunk for deletion.
    :param once: If True, only runs one iteration of the main loop.
    :param greedy: If True, delete right away replicas with tombstone.
    :param scheme: Force the reaper to use a particular protocol, e.g., mock.
    """
    logging.info('Starting Reaper: Worker %(worker_number)s, '
                 'child %(child_number)s will work on RSEs: ' % locals() + ', '.join([rse['rse'] for rse in rses]))

    pid = os.getpid()
    thread = threading.current_thread()
    hostname = socket.gethostname()
    executable = ' '.join(sys.argv)
    # Generate a hash just for the subset of RSEs
    rse_names = [rse['rse'] for rse in rses]
    hash_executable = hashlib.sha256((sys.argv[0] + ''.join(rse_names)).encode()).hexdigest()
    sanity_check(executable=None, hostname=hostname)

    nothing_to_do = {}
    while not GRACEFUL_STOP.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread, hash_executable=hash_executable)
            checkpoint_time = datetime.datetime.now()
            # logging.info('Reaper({0[worker_number]}/{0[child_number]}): Live gives {0[heartbeat]}'.format(locals()))

            max_deleting_rate = 0
            for rse in sort_rses(rses):
                try:
                    if checkpoint_time + datetime.timedelta(minutes=1) < datetime.datetime.now():
                        heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread, hash_executable=hash_executable)
                        # logging.info('Reaper({0[worker_number]}/{0[child_number]}): Live gives {0[heartbeat]}'.format(locals()))
                        checkpoint_time = datetime.datetime.now()

                    if rse['id'] in nothing_to_do and nothing_to_do[rse['id']] > datetime.datetime.now():
                        continue
                    logging.info('Reaper %s-%s: Running on RSE %s %s', worker_number, child_number,
                                 rse['rse'], nothing_to_do.get(rse['id']))

                    rse_info = rsemgr.get_rse_info(rse_id=rse['id'])
                    rse_protocol = rse_core.get_rse_protocols(rse_id=rse['id'])

                    if not rse_protocol['availability_delete']:
                        logging.info('Reaper %s-%s: RSE %s is not available for deletion', worker_number, child_number, rse_info['rse'])
                        nothing_to_do[rse['id']] = datetime.datetime.now() + datetime.timedelta(minutes=30)
                        continue

                    # Temporary hack to force gfal for deletion
                    for protocol in rse_info['protocols']:
                        if protocol['impl'] == 'rucio.rse.protocols.srm.Default' or protocol['impl'] == 'rucio.rse.protocols.gsiftp.Default':
                            protocol['impl'] = 'rucio.rse.protocols.gfal.Default'

                    needed_free_space, max_being_deleted_files = None, 100
                    needed_free_space_per_child = None
                    if not greedy:
                        max_being_deleted_files, needed_free_space, used, free = __check_rse_usage(rse_id=rse['id'])
                        logging.info('Reaper %(worker_number)s-%(child_number)s: Space usage for RSE %(rse)s - max_being_deleted_files: %(max_being_deleted_files)s, needed_free_space: %(needed_free_space)s, used: %(used)s, free: %(free)s' % locals())
                        if needed_free_space <= 0:
                            needed_free_space, needed_free_space_per_child = 0, 0
                            logging.info('Reaper %s-%s: free space is above minimum limit for %s', worker_number, child_number, rse['rse'])
                        else:
                            if total_children and total_children > 0:
                                needed_free_space_per_child = needed_free_space / float(total_children)

                    start = time.time()
                    with monitor.record_timer_block('reaper.list_unlocked_replicas'):
                        replicas = list_unlocked_replicas(rse_id=rse['id'],
                                                          bytes=needed_free_space_per_child,
                                                          limit=max_being_deleted_files,
                                                          worker_number=child_number,
                                                          total_workers=total_children,
                                                          delay_seconds=delay_seconds)
                    logging.debug('Reaper %s-%s: list_unlocked_replicas on %s for %s bytes in %s seconds: %s replicas', worker_number, child_number, rse['rse'], needed_free_space_per_child, time.time() - start, len(replicas))

                    if not replicas:
                        nothing_to_do[rse['id']] = datetime.datetime.now() + datetime.timedelta(minutes=30)
                        logging.info('Reaper %s-%s: No replicas to delete %s. The next check will occur at %s',
                                     worker_number, child_number, rse['rse'],
                                     nothing_to_do[rse['id']])
                        continue

                    prot = rsemgr.create_protocol(rse_info, 'delete', scheme=scheme)
                    for files in chunks(replicas, chunk_size):
                        logging.debug('Reaper %s-%s: Running on : %s', worker_number, child_number, str(files))
                        try:
                            update_replicas_states(replicas=[dict(list(replica.items()) + [('state', ReplicaState.BEING_DELETED), ('rse_id', rse['id'])]) for replica in files], nowait=True)
                            for replica in files:
                                try:
                                    replica['pfn'] = str(list(rsemgr.lfns2pfns(rse_settings=rse_info,
                                                                               lfns=[{'scope': replica['scope'].external, 'name': replica['name'], 'path': replica['path']}],
                                                                               operation='delete', scheme=scheme).values())[0])
                                except (ReplicaUnAvailable, ReplicaNotFound) as error:
                                    err_msg = 'Failed to get pfn UNAVAILABLE replica %s:%s on %s with error %s' % (replica['scope'], replica['name'], rse['rse'], str(error))
                                    logging.warning('Reaper %s-%s: %s', worker_number, child_number, err_msg)
                                    replica['pfn'] = None

                            monitor.record_counter(counters='reaper.deletion.being_deleted', delta=len(files))

                            try:
                                deleted_files = []
                                prot.connect()
                                for replica in files:
                                    try:
                                        deletion_dict = {'scope': replica['scope'].external,
                                                         'name': replica['name'],
                                                         'rse': rse_info['rse'],
                                                         'rse_id': rse_info['id'],
                                                         'file-size': replica['bytes'],
                                                         'bytes': replica['bytes'],
                                                         'url': replica['pfn'],
                                                         'protocol': prot.attributes['scheme']}
                                        if replica['scope'].vo != 'def':
                                            deletion_dict['vo'] = replica['scope'].vo
                                        logging.info('Reaper %s-%s: Deletion ATTEMPT of %s:%s as %s on %s', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'])
                                        start = time.time()
                                        if rse['staging_area'] or rse['rse'].endswith("STAGING"):
                                            logging.warning('Reaper %s-%s: Deletion STAGING of %s:%s as %s on %s, will only delete the catalog and not do physical deletion',
                                                            worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'])
                                        else:
                                            if replica['pfn']:
                                                pfn = replica['pfn']
                                                # sign the URL if necessary
                                                if prot.attributes['scheme'] == 'https' and rse_info['sign_url'] is not None:
                                                    pfn = get_signed_url(rse['id'], rse_info['sign_url'], 'delete', pfn)
                                                prot.delete(pfn)
                                            else:
                                                logging.warning('Reaper %s-%s: Deletion UNAVAILABLE of %s:%s as %s on %s', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'])
                                        monitor.record_timer('daemons.reaper.delete.%s.%s' % (prot.attributes['scheme'], rse['rse']), (time.time() - start) * 1000)
                                        duration = time.time() - start

                                        deleted_files.append({'scope': replica['scope'], 'name': replica['name']})

                                        deletion_dict['duration'] = duration
                                        add_message('deletion-done', deletion_dict)
                                        logging.info('Reaper %s-%s: Deletion SUCCESS of %s:%s as %s on %s in %s seconds', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'], duration)
                                    except SourceNotFound:
                                        err_msg = 'Deletion NOTFOUND of %s:%s as %s on %s' % (replica['scope'], replica['name'], replica['pfn'], rse['rse'])
                                        logging.warning(err_msg)
                                        deleted_files.append({'scope': replica['scope'], 'name': replica['name']})
                                        if replica['state'] == ReplicaState.AVAILABLE:
                                            deletion_dict['reason'] = str(err_msg)
                                            add_message('deletion-failed', deletion_dict)
                                    except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                                        logging.warning('Reaper %s-%s: Deletion NOACCESS of %s:%s as %s on %s: %s', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'], str(error))
                                        deletion_dict['reason'] = str(error)
                                        add_message('deletion-failed', deletion_dict)
                                    except Exception as error:
                                        logging.critical('Reaper %s-%s: Deletion CRITICAL of %s:%s as %s on %s: %s', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'], str(traceback.format_exc()))
                                        deletion_dict['reason'] = str(error)
                                        add_message('deletion-failed', deletion_dict)
                                    except:
                                        logging.critical('Reaper %s-%s: Deletion CRITICAL of %s:%s as %s on %s: %s', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'], str(traceback.format_exc()))
                            except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                                for replica in files:
                                    logging.warning('Reaper %s-%s: Deletion NOACCESS of %s:%s as %s on %s: %s', worker_number, child_number, replica['scope'], replica['name'], replica['pfn'], rse['rse'], str(error))
                                    payload = {'scope': replica['scope'].external,
                                               'name': replica['name'],
                                               'rse': rse_info['rse'],
                                               'rse_id': rse_info['id'],
                                               'file-size': replica['bytes'],
                                               'bytes': replica['bytes'],
                                               'url': replica['pfn'],
                                               'reason': str(error),
                                               'protocol': prot.attributes['scheme']}
                                    if replica['scope'].vo != 'def':
                                        deletion_dict['vo'] = replica['scope'].vo
                                    add_message('deletion-failed', payload)
                                    break
                            finally:
                                prot.close()
                            start = time.time()
                            with monitor.record_timer_block('reaper.delete_replicas'):
                                delete_replicas(rse_id=rse['id'], files=deleted_files)
                            logging.debug('Reaper %s-%s: delete_replicas successes %s %s %s', worker_number, child_number, rse['rse'], len(deleted_files), time.time() - start)
                            monitor.record_counter(counters='reaper.deletion.done', delta=len(deleted_files))

                        except DatabaseException as error:
                            logging.warning('Reaper %s-%s: DatabaseException %s', worker_number, child_number, str(error))
                        except UnsupportedOperation as error:
                            logging.warning('Reaper %s-%s: UnsupportedOperation %s', worker_number, child_number, str(error))
                        except:
                            logging.critical(traceback.format_exc())

                except RSENotFound as error:
                    logging.warning('Reaper %s-%s: RSE not found %s', worker_number, child_number, str(error))

                except:
                    logging.critical(traceback.format_exc())

            if once:
                break

            time.sleep(1)

        except DatabaseException as error:
            logging.warning('Reaper:  %s', str(error))
        except:
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


def run(total_workers=1, chunk_size=100, threads_per_worker=None, once=False, greedy=False, rses=[], scheme=None, exclude_rses=None, include_rses=None, vos=None, delay_seconds=0):
    """
    Starts up the reaper threads.

    :param total_workers: The total number of workers.
    :param chunk_size: the size of chunk for deletion.
    :param threads_per_worker: Total number of threads created by each worker.
    :param once: If True, only runs one iteration of the main loop.
    :param greedy: If True, delete right away replicas with tombstone.
    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param scheme: Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param exclude_rses: RSE expression to exclude RSEs from the Reaper.
    :param include_rses: RSE expression to include RSEs.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If None, we either use all VOs if run from "def", or the current VO otherwise.
    """
    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('Reaper1 daemon will be deprecated and replaced by reaper2 with Rucio release 1.25 (~March 2021)!')
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
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logging.info('Reaper: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    all_rses = []
    for vo in vos:
        all_rses.extend(rse_core.list_rses(filters={'vo': vo}))

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

    threads = []
    nb_rses_per_worker = int(math.ceil(len(rses) / float(total_workers))) or 1
    rses = random.sample(rses, len(rses))
    for worker in range(total_workers):
        for child in range(threads_per_worker or 1):
            rses_list = rses[worker * nb_rses_per_worker: worker * nb_rses_per_worker + nb_rses_per_worker]
            if not rses_list:
                logging.warning('Reaper: Empty RSEs list for worker %(worker)s' % locals())
                continue
            kwargs = {'worker_number': worker,
                      'child_number': child,
                      'total_children': threads_per_worker or 1,
                      'once': once,
                      'chunk_size': chunk_size,
                      'greedy': greedy,
                      'rses': rses_list,
                      'delay_seconds': delay_seconds,
                      'scheme': scheme}
            threads.append(threading.Thread(target=reaper, kwargs=kwargs, name='Worker: %s, child: %s' % (worker, child)))
    [t.start() for t in threads]
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
