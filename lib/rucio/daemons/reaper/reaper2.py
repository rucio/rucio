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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2020
# - Wen Guan <wguan.icedew@gmail.com>, 2016
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019-2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

'''
Reaper is a daemon to manage file deletion.
'''

from __future__ import print_function, division

import logging
import os
import random
import socket
import sys
import threading
import time
import traceback
from collections import OrderedDict
from datetime import datetime, timedelta
from math import ceil
from operator import itemgetter

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE
from prometheus_client import Counter
from sqlalchemy.exc import DatabaseError, IntegrityError

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import (DatabaseException, RSENotFound, ConfigNotFound,
                                    ReplicaUnAvailable, ReplicaNotFound, ServiceUnavailable,
                                    RSEAccessDenied, ResourceTemporaryUnavailable, SourceNotFound,
                                    VONotFound)
from rucio.common.utils import chunks
from rucio.core import monitor
from rucio.core.config import get
from rucio.core.credential import get_signed_url
from rucio.core.heartbeat import live, die, sanity_check, list_payload_counts
from rucio.core.message import add_message
from rucio.core.replica import list_and_mark_unlocked_replicas, delete_replicas
from rucio.core.rse import list_rses, get_rse_limits, get_rse_usage, list_rse_attributes, get_rse_protocols
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_evaluation_backlog
from rucio.core.vo import list_vos
from rucio.rse import rsemanager as rsemgr

logging.getLogger("reaper").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()

REGION = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=600,
                                 arguments={'url': config_get('cache', 'url', False, '127.0.0.1:11211'),
                                            'distributed_lock': True})

DELETION_COUNTER = Counter('rucio_daemons_reaper_deletion_done', 'Number of deleted replicas')


def get_rses_to_process(rses, include_rses, exclude_rses, vos):
    """
    Return the list of RSEs to process based on rses, include_rses and exclude_rses

    :param rses:               List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param exclude_rses:       RSE expression to exclude RSEs from the Reaper.
    :param include_rses:       RSE expression to include RSEs.
    :param vos:                VOs on which to look for RSEs. Only used in multi-VO mode.
                               If None, we either use all VOs if run from "def",

    :returns: A list of RSEs to process
    """
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

    cache_key = 'rses_to_process'
    if multi_vo:
        cache_key += '@%s' % '-'.join(vo for vo in vos)
    result = REGION.get(cache_key)
    if result is not NO_VALUE:
        return result

    all_rses = []
    for vo in vos:
        all_rses.extend(list_rses(filters={'vo': vo}))

    if rses:
        invalid = set(rses) - set([rse['rse'] for rse in all_rses])
        if invalid:
            msg = 'RSE{} {} cannot be found'.format('s' if len(invalid) > 1 else '',
                                                    ', '.join([repr(rse) for rse in invalid]))
            raise RSENotFound(msg)
        rses = [rse for rse in all_rses if rse['rse'] in rses]
    else:
        rses = all_rses

    if include_rses:
        included_rses = parse_expression(include_rses)
        rses = [rse for rse in rses if rse in included_rses]

    if exclude_rses:
        excluded_rses = parse_expression(exclude_rses)
        rses = [rse for rse in rses if rse not in excluded_rses]

    REGION.set(cache_key, rses)
    logging.info('Reaper: This instance will work on RSEs: %s', ', '.join([rse['rse'] for rse in rses]))
    return rses


def delete_from_storage(replicas, prot, rse_info, staging_areas, prepend_str):
    deleted_files = []
    rse_name = rse_info['rse']
    rse_id = rse_info['id']
    try:
        prot.connect()
        for replica in replicas:
            # Physical deletion
            try:
                deletion_dict = {'scope': replica['scope'].external,
                                 'name': replica['name'],
                                 'rse': rse_name,
                                 'file-size': replica['bytes'],
                                 'bytes': replica['bytes'],
                                 'url': replica['pfn'],
                                 'protocol': prot.attributes['scheme']}
                if replica['scope'].vo != 'def':
                    deletion_dict['vo'] = replica['scope'].vo
                logging.info('%s Deletion ATTEMPT of %s:%s as %s on %s', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name)
                start = time.time()
                # For STAGING RSEs, no physical deletion
                if rse_id in staging_areas:
                    logging.warning('%s Deletion STAGING of %s:%s as %s on %s, will only delete the catalog and not do physical deletion', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name)
                    deleted_files.append({'scope': replica['scope'], 'name': replica['name']})
                    continue

                if replica['pfn']:
                    pfn = replica['pfn']
                    # sign the URL if necessary
                    if prot.attributes['scheme'] == 'https' and rse_info['sign_url'] is not None:
                        pfn = get_signed_url(rse_id, rse_info['sign_url'], 'delete', pfn)
                    prot.delete(pfn)
                else:
                    logging.warning('%s Deletion UNAVAILABLE of %s:%s as %s on %s', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name)

                monitor.record_timer('daemons.reaper.delete.%s.%s' % (prot.attributes['scheme'], rse_name), (time.time() - start) * 1000)
                duration = time.time() - start

                deleted_files.append({'scope': replica['scope'], 'name': replica['name']})

                deletion_dict['duration'] = duration
                add_message('deletion-done', deletion_dict)
                logging.info('%s Deletion SUCCESS of %s:%s as %s on %s in %s seconds', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name, duration)

            except SourceNotFound:
                err_msg = 'Deletion NOTFOUND of %s:%s as %s on %s' % (replica['scope'], replica['name'], replica['pfn'], rse_name)
                logging.warning('%s %s', prepend_str, err_msg)
                deleted_files.append({'scope': replica['scope'], 'name': replica['name']})

            except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                logging.warning('%s Deletion NOACCESS of %s:%s as %s on %s: %s', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name, str(error))
                deletion_dict['reason'] = str(error)
                add_message('deletion-failed', deletion_dict)

            except Exception as error:
                logging.critical('%s Deletion CRITICAL of %s:%s as %s on %s: %s', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name, str(traceback.format_exc()))
                deletion_dict['reason'] = str(error)
                add_message('deletion-failed', deletion_dict)

    except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
        for replica in replicas:
            logging.warning('%s Deletion NOACCESS of %s:%s as %s on %s: %s', prepend_str, replica['scope'], replica['name'], replica['pfn'], rse_name, str(error))
            payload = {'scope': replica['scope'].external,
                       'name': replica['name'],
                       'rse': rse_name,
                       'file-size': replica['bytes'],
                       'bytes': replica['bytes'],
                       'url': replica['pfn'],
                       'reason': str(error),
                       'protocol': prot.attributes['scheme']}
            if replica['scope'].vo != 'def':
                payload['vo'] = replica['scope'].vo
            add_message('deletion-failed', payload)

    finally:
        prot.close()
    return deleted_files


def get_rses_to_hostname_mapping():
    """
    Return a dictionaries mapping the RSEs to the hostname of the SE

    :returns: Dictionary with RSE_id as key and (hostname, rse_info) as value
    """

    result = REGION.get('rse_hostname_mapping')
    if result is NO_VALUE:
        result = {}
        all_rses = list_rses()
        for rse in all_rses:
            rse_protocol = get_rse_protocols(rse_id=rse['id'])
            for prot in rse_protocol['protocols']:
                if prot['domains']['wan']['delete'] == 1:
                    result[rse['id']] = (prot['hostname'], rse_protocol)
            if rse['id'] not in result:
                logging.warning('No default delete protocol for %s', rse['rse'])

        REGION.set('rse_hostname_mapping', result)
        return result

    return result


def get_max_deletion_threads_by_hostname(hostname):
    """
    Internal method to check RSE usage and limits.

    :param hostname: the hostname of the SE

    :returns : The maximum deletion thread for the SE.
    """
    result = REGION.get('max_deletion_threads_%s' % hostname)
    if result is NO_VALUE:
        try:
            max_deletion_thread = get('reaper', 'max_deletion_threads_%s' % hostname)
        except ConfigNotFound:
            try:
                max_deletion_thread = get('reaper', 'nb_workers_by_hostname')
            except ConfigNotFound:
                max_deletion_thread = 5
        REGION.set('max_deletion_threads_%s' % hostname, max_deletion_thread)
        result = max_deletion_thread
    return result


def __check_rse_usage(rse, rse_id, prepend_str):
    """
    Internal method to check RSE usage and limits.

    :param rse_id: the rse name.
    :param rse_id: the rse id.

    :returns : max_being_deleted_files, needed_free_space, used, free, only_delete_obsolete.
    """

    result = REGION.get('rse_usage_%s' % rse_id)
    if result is NO_VALUE:
        max_being_deleted_files, needed_free_space, used, free, obsolete = None, None, None, None, None

        # First of all check if greedy mode is enabled for this RSE
        attributes = list_rse_attributes(rse_id=rse_id)
        greedy = attributes.get('greedyDeletion', False)
        if greedy:
            result = (max_being_deleted_files, 1000000000000, used, free, False)
            REGION.set('rse_usage_%s' % rse_id, result)
            return result

        # Get RSE limits
        limits = get_rse_limits(rse_id=rse_id)
        if not limits and 'MinFreeSpace' not in limits and 'MaxBeingDeletedFiles' not in limits:
            result = (max_being_deleted_files, needed_free_space, used, free, False)
            REGION.set('rse_usage_%s' % rse_id, result)
            return result

        min_free_space = limits.get('MinFreeSpace')
        max_being_deleted_files = limits.get('MaxBeingDeletedFiles')

        # Check from which sources to get used and total spaces
        # Default is storage
        source_for_total_space = attributes.get('source_for_total_space', 'storage')
        source_for_used_space = attributes.get('source_for_used_space', 'storage')

        logging.debug('%s RSE: %s, source_for_total_space: %s, source_for_used_space: %s',
                      prepend_str, rse, source_for_total_space, source_for_used_space)

        # Get total, used and obsolete space
        rse_usage = get_rse_usage(rse_id=rse_id)
        usage = [entry for entry in rse_usage if entry['source'] == 'obsolete']
        for var in usage:
            obsolete = var['used']
            break
        usage = [entry for entry in rse_usage if entry['source'] == source_for_total_space]

        # If no information is available about disk space, do nothing except if there are replicas with Epoch tombstone
        if not usage:
            if not obsolete:
                result = (max_being_deleted_files, needed_free_space, used, free, False)
                REGION.set('rse_usage_%s' % rse_id, result)
                return result
            result = (max_being_deleted_files, obsolete, used, free, True)
            REGION.set('rse_usage_%s' % rse_id, result)
            return result

        # Extract the total and used space
        for var in usage:
            total, used = var['total'], var['used']
            break

        if source_for_total_space != source_for_used_space:
            usage = [entry for entry in rse_usage if entry['source'] == source_for_used_space]
            if not usage:
                result = (max_being_deleted_files, needed_free_space, None, free, False)
                REGION.set('rse_usage_%s' % rse_id, result)
                return result
            for var in usage:
                used = var['used']
                break

        free = total - used
        if min_free_space:
            needed_free_space = min_free_space - free

        # If needed_free_space negative, nothing to delete except if some Epoch tombstoned replicas
        if needed_free_space <= 0:
            needed_free_space = 0 or obsolete
            result = (max_being_deleted_files, needed_free_space, used, free, True)
        else:
            result = (max_being_deleted_files, needed_free_space, used, free, False)
        REGION.set('rse_usage_%s' % rse_id, result)
        return result

    return result


def reaper(rses, include_rses, exclude_rses, vos=None, chunk_size=100, once=False, greedy=False,
           scheme=None, delay_seconds=0, sleep_time=60):
    """
    Main loop to select and delete files.

    :param rses:           List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param include_rses:   RSE expression to include RSEs.
    :param exclude_rses:   RSE expression to exclude RSEs from the Reaper.
    :param vos:            VOs on which to look for RSEs. Only used in multi-VO mode.
                           If None, we either use all VOs if run from "def", or the current VO otherwise.
    :param chunk_size:     The size of chunk for deletion.
    :param once:           If True, only runs one iteration of the main loop.
    :param greedy:         If True, delete right away replicas with tombstone.
    :param scheme:         Force the reaper to use a particular protocol, e.g., mock.
    :param delay_seconds:  The delay to query replicas in BEING_DELETED state.
    :param sleep_time:     Time between two cycles.
    """
    hostname = socket.getfqdn()
    executable = 'reaper2'
    pid = os.getpid()
    hb_thread = threading.current_thread()
    sanity_check(executable=executable, hostname=hostname)
    heart_beat = live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logging.info('%s Reaper starting', prepend_str)

    if not once:
        GRACEFUL_STOP.wait(10)  # To prevent running on the same partition if all the reapers restart at the same time
    heart_beat = live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logging.info('%s Reaper started', prepend_str)

    while not GRACEFUL_STOP.is_set():

        # Check if there is a Judge Evaluator backlog
        try:
            max_evaluator_backlog_count = get('reaper', 'max_evaluator_backlog_count')
        except ConfigNotFound:
            max_evaluator_backlog_count = None
        try:
            max_evaluator_backlog_duration = get('reaper', 'max_evaluator_backlog_duration')
        except ConfigNotFound:
            max_evaluator_backlog_duration = None
        if max_evaluator_backlog_count or max_evaluator_backlog_duration:
            backlog = get_evaluation_backlog()
            if max_evaluator_backlog_count and \
               backlog[0] and \
               max_evaluator_backlog_duration and \
               backlog[1] and \
               backlog[0] > max_evaluator_backlog_count and \
               backlog[1] < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration):
                logging.error('%s Reaper: Judge evaluator backlog count and duration hit, stopping operation', prepend_str)
                GRACEFUL_STOP.wait(30)
                continue
            elif max_evaluator_backlog_count and backlog[0] and backlog[0] > max_evaluator_backlog_count:
                logging.error('%s Reaper: Judge evaluator backlog count hit, stopping operation', prepend_str)
                GRACEFUL_STOP.wait(30)
                continue
            elif max_evaluator_backlog_duration and backlog[1] and backlog[1] < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration):
                logging.error('%s Reaper: Judge evaluator backlog duration hit, stopping operation', prepend_str)
                GRACEFUL_STOP.wait(30)
                continue

        rses_to_process = get_rses_to_process(rses, include_rses, exclude_rses, vos)
        if not rses_to_process:
            logging.error('%s Reaper: No RSEs found. Will sleep for 30 seconds', prepend_str)
            GRACEFUL_STOP.wait(30)
            continue
        start_time = time.time()
        try:
            staging_areas = []
            dict_rses = {}
            heart_beat = live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            tot_needed_free_space = 0
            for rse in rses_to_process:
                # Check if the RSE is a staging area
                if rse['staging_area']:
                    staging_areas.append(rse['rse'])
                # Check if RSE is blacklisted
                if rse['availability'] % 2 == 0:
                    logging.debug('%s RSE %s is blacklisted for delete', prepend_str, rse['rse'])
                    continue
                max_being_deleted_files, needed_free_space, used, free, only_delete_obsolete = __check_rse_usage(rse['rse'], rse['id'], prepend_str)
                # Check if greedy mode
                if greedy:
                    dict_rses[(rse['rse'], rse['id'])] = [1000000000000, max_being_deleted_files, only_delete_obsolete]
                    tot_needed_free_space += 1000000000000
                else:
                    if needed_free_space:
                        dict_rses[(rse['rse'], rse['id'])] = [needed_free_space, max_being_deleted_files, only_delete_obsolete]
                        tot_needed_free_space += needed_free_space
                    else:
                        logging.debug('%s Nothing to delete on %s', prepend_str, rse['rse'])

            # Ordering the RSEs based on the needed free space
            sorted_dict_rses = OrderedDict(sorted(dict_rses.items(), key=itemgetter(1), reverse=True))
            logging.debug('%s List of RSEs to process ordered by needed space desc : %s', prepend_str, str(sorted_dict_rses))

            # Get the mapping between the RSE and the hostname used for deletion. The dictionary has RSE as key and (hostanme, rse_info) as value
            rses_hostname_mapping = get_rses_to_hostname_mapping()
            # logging.debug('%s Mapping RSEs to hostnames used for deletion : %s', prepend_str, str(rses_hostname_mapping))

            list_rses_mult = []

            # Loop over the RSEs. rse_key = (rse, rse_id) and fill list_rses_mult that contains all RSEs to process with different multiplicity
            for rse_key in dict_rses:
                rse_name, rse_id = rse_key
                # The length of the deletion queue scales inversily with the number of workers
                # The ceil increase the weight of the RSE with small amount of files to delete
                max_workers = ceil(dict_rses[rse_key][0] / tot_needed_free_space * 1000 / heart_beat['nr_threads'])
                list_rses_mult.extend([(rse_name, rse_id, dict_rses[rse_key][0], dict_rses[rse_key][1]) for _ in range(int(max_workers))])
            random.shuffle(list_rses_mult)

            for rse_name, rse_id, needed_free_space, max_being_deleted_files in list_rses_mult:
                result = REGION.get('pause_deletion_%s' % rse_id, expiration_time=120)
                if result is not NO_VALUE:
                    logging.info('%s Not enough replicas to delete on %s during the previous cycle. Deletion paused for a while', prepend_str, rse_name)
                    continue
                logging.debug('%s Working on %s. Percentage of the total space needed %.2f', prepend_str, rse_name, needed_free_space / tot_needed_free_space * 100)
                rse_hostname, rse_info = rses_hostname_mapping[rse_id]
                rse_hostname_key = '%s,%s' % (rse_id, rse_hostname)
                payload_cnt = list_payload_counts(executable, older_than=600, hash_executable=None, session=None)
                # logging.debug('%s Payload count : %s', prepend_str, str(payload_cnt))
                tot_threads_for_hostname = 0
                tot_threads_for_rse = 0
                for key in payload_cnt:
                    if key and key.find(',') > -1:
                        if key.split(',')[1] == rse_hostname:
                            tot_threads_for_hostname += payload_cnt[key]
                        if key.split(',')[0] == str(rse_id):
                            tot_threads_for_rse += payload_cnt[key]

                max_deletion_thread = get_max_deletion_threads_by_hostname(rse_hostname)
                if rse_hostname_key in payload_cnt and tot_threads_for_hostname >= max_deletion_thread:
                    logging.debug('%s Too many deletion threads for %s on RSE %s. Back off', prepend_str, rse_hostname, rse_name)
                    # Might need to reschedule a try on this RSE later in the same cycle
                    continue

                logging.info('%s Nb workers on %s smaller than the limit (current %i vs max %i). Starting new worker on RSE %s', prepend_str, rse_hostname, tot_threads_for_hostname, max_deletion_thread, rse_name)
                live(executable, hostname, pid, hb_thread, older_than=600, hash_executable=None, payload=rse_hostname_key, session=None)
                logging.debug('%s Total deletion workers for %s : %i', prepend_str, rse_hostname, tot_threads_for_hostname + 1)
                # List and mark BEING_DELETED the files to delete
                del_start_time = time.time()
                only_delete_obsolete = dict_rses[(rse_name, rse_id)][2]
                try:
                    with monitor.record_timer_block('reaper.list_unlocked_replicas'):
                        if only_delete_obsolete:
                            logging.debug('%s Will run list_and_mark_unlocked_replicas on %s. No space needed, will only delete EPOCH tombstoned replicas', prepend_str, rse_name)
                        replicas = list_and_mark_unlocked_replicas(limit=chunk_size,
                                                                   bytes=needed_free_space,
                                                                   rse_id=rse_id,
                                                                   delay_seconds=delay_seconds,
                                                                   only_delete_obsolete=only_delete_obsolete,
                                                                   session=None)
                    logging.debug('%s list_and_mark_unlocked_replicas on %s for %s bytes in %s seconds: %s replicas', prepend_str, rse_name, needed_free_space, time.time() - del_start_time, len(replicas))
                    if len(replicas) < chunk_size:
                        logging.info('%s Not enough replicas to delete on %s (%s requested vs %s returned). Will skip any new attempts on this RSE until next cycle', prepend_str, rse_name, chunk_size, len(replicas))
                        REGION.set('pause_deletion_%s' % rse_id, True)

                except (DatabaseException, IntegrityError, DatabaseError) as error:
                    logging.error('%s %s', prepend_str, str(error))
                    continue
                except Exception:
                    logging.critical('%s %s', prepend_str, str(traceback.format_exc()))

                # Physical  deletion will take place there
                try:
                    prot = rsemgr.create_protocol(rse_info, 'delete', scheme=scheme)
                    for file_replicas in chunks(replicas, 100):
                        # Refresh heartbeat
                        live(executable, hostname, pid, hb_thread, older_than=600, hash_executable=None, payload=rse_hostname_key, session=None)
                        del_start_time = time.time()
                        for replica in file_replicas:
                            try:
                                replica['pfn'] = str(list(rsemgr.lfns2pfns(rse_settings=rse_info,
                                                                           lfns=[{'scope': replica['scope'].external, 'name': replica['name'], 'path': replica['path']}],
                                                                           operation='delete', scheme=scheme).values())[0])
                            except (ReplicaUnAvailable, ReplicaNotFound) as error:
                                logging.warning('%s Failed get pfn UNAVAILABLE replica %s:%s on %s with error %s', prepend_str, replica['scope'], replica['name'], rse_name, str(error))
                                replica['pfn'] = None

                            except Exception:
                                logging.critical('%s %s', prepend_str, str(traceback.format_exc()))

                        deleted_files = delete_from_storage(file_replicas, prot, rse_info, staging_areas, prepend_str)
                        logging.info('%s %i files processed in %s seconds', prepend_str, len(file_replicas), time.time() - del_start_time)

                        # Then finally delete the replicas
                        del_start = time.time()
                        with monitor.record_timer_block('reaper.delete_replicas'):
                            delete_replicas(rse_id=rse_id, files=deleted_files)
                        logging.debug('%s delete_replicas successed on %s : %s replicas in %s seconds', prepend_str, rse_name, len(deleted_files), time.time() - del_start)
                        monitor.record_counter(counters='reaper.deletion.done', delta=len(deleted_files))
                        DELETION_COUNTER.inc(len(deleted_files))
                except Exception:
                    logging.critical('%s %s', prepend_str, str(traceback.format_exc()))

            if once:
                break

            tottime = time.time() - start_time
            if tottime < sleep_time:
                logging.info('%s Will sleep for %s seconds', prepend_str, sleep_time - tottime)
                GRACEFUL_STOP.wait(sleep_time - tottime)

        except DatabaseException as error:
            logging.warning('%s Reaper:  %s', prepend_str, str(error))
        except Exception:
            logging.critical('%s %s', prepend_str, str(traceback.format_exc()))
        finally:
            if once:
                break

    die(executable=executable, hostname=hostname, pid=pid, thread=hb_thread)
    logging.info('%s Graceful stop requested', prepend_str)
    logging.info('%s Graceful stop done', prepend_str)
    return


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(threads=1, chunk_size=100, once=False, greedy=False, rses=None, scheme=None, exclude_rses=None, include_rses=None, vos=None, delay_seconds=0, sleep_time=60):
    """
    Starts up the reaper threads.

    :param threads:            The total number of workers.
    :param chunk_size:         The size of chunk for deletion.
    :param threads_per_worker: Total number of threads created by each worker.
    :param once:               If True, only runs one iteration of the main loop.
    :param greedy:             If True, delete right away replicas with tombstone.
    :param rses:               List of RSEs the reaper should work against.
                               If empty, it considers all RSEs.
    :param scheme:             Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param exclude_rses:       RSE expression to exclude RSEs from the Reaper.
    :param include_rses:       RSE expression to include RSEs.
    :param vos:                VOs on which to look for RSEs. Only used in multi-VO mode.
                               If None, we either use all VOs if run from "def",
                               or the current VO otherwise.
    :param delay_seconds:      The delay to query replicas in BEING_DELETED state.
    :param sleep_time:         Time between two cycles.
    """
    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('main: starting processes')

    rses_to_process = get_rses_to_process(rses, include_rses, exclude_rses, vos)
    if not rses_to_process:
        logging.error('Reaper: No RSEs found. Exiting.')
        return

    logging.info('Reaper: This instance will work on RSEs: %s', ', '.join([rse['rse'] for rse in rses_to_process]))

    # To populate the cache
    get_rses_to_hostname_mapping()

    logging.info('starting reaper threads')
    threads_list = [threading.Thread(target=reaper, kwargs={'once': once,
                                                            'rses': rses,
                                                            'include_rses': include_rses,
                                                            'exclude_rses': exclude_rses,
                                                            'vos': vos,
                                                            'chunk_size': chunk_size,
                                                            'greedy': greedy,
                                                            'sleep_time': sleep_time,
                                                            'delay_seconds': delay_seconds,
                                                            'scheme': scheme}) for _ in range(0, threads)]

    for thread in threads_list:
        thread.start()

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads_list:
        threads_list = [thread.join(timeout=3.14) for thread in threads_list if thread and thread.isAlive()]
