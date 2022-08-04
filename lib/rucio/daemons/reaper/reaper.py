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
Reaper is a daemon to manage file deletion.
'''

import functools
import logging
import os
import random
import threading
import time
import traceback
from configparser import NoOptionError, NoSectionError
from datetime import datetime, timedelta
from math import log2
from typing import TYPE_CHECKING

from dogpile.cache.api import NO_VALUE
from sqlalchemy.exc import DatabaseError, IntegrityError

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool
from rucio.common.cache import make_region_memcached
from rucio.common.exception import (DatabaseException, RSENotFound,
                                    ReplicaUnAvailable, ReplicaNotFound, ServiceUnavailable,
                                    RSEAccessDenied, ResourceTemporaryUnavailable, SourceNotFound,
                                    VONotFound)
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core import monitor
from rucio.core.credential import get_signed_url
from rucio.core.heartbeat import list_payload_counts
from rucio.core.message import add_message
from rucio.core.oidc import get_token_for_account_operation
from rucio.core.replica import list_and_mark_unlocked_replicas, list_and_mark_unlocked_replicas_no_temp_table, delete_replicas
from rucio.core.rse import list_rses, RseData
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_evaluation_backlog
from rucio.core.vo import list_vos
from rucio.daemons.common import run_daemon
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Tuple
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()

REGION = make_region_memcached(expiration_time=600)

DELETION_COUNTER = monitor.MultiCounter(prom='rucio_daemons_reaper_deletion_done', statsd='reaper.deletion.done',
                                        documentation='Number of deleted replicas')
EXCLUDED_RSE_GAUGE = monitor.MultiGauge('daemons.reaper.excluded_rses',
                                        documentation='Temporarly excluded RSEs', labelnames=('rse',))


def get_rses_to_process(rses, include_rses, exclude_rses, vos):
    """
    Return the list of RSEs to process based on rses, include_rses and exclude_rses

    :param rses:               List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param exclude_rses:       RSE expression to exclude RSEs from the Reaper.
    :param include_rses:       RSE expression to include RSEs.
    :param vos:                VOs on which to look for RSEs. Only used in multi-VO mode.
                               If None, we either use all VOs if run from "def"

    :returns: A list of RSEs to process
    """
    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logging.log(logging.WARNING, 'Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logging.log(logging.INFO, 'Reaper: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    pid = os.getpid()
    cache_key = 'rses_to_process_%s' % pid
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
    logging.log(logging.INFO, 'Reaper: This instance will work on RSEs: %s', ', '.join([rse['rse'] for rse in rses]))
    return rses


def delete_from_storage(heartbeat_handler, hb_payload, replicas, prot, rse_info, is_staging, auto_exclude_threshold, logger=logging.log):
    deleted_files = []
    rse_name = rse_info['rse']
    rse_id = rse_info['id']
    noaccess_attempts = 0
    pfns_to_bulk_delete = []
    try:
        prot.connect()
        for replica in replicas:
            # Physical deletion
            _, _, logger = heartbeat_handler.live(payload=hb_payload)
            try:
                deletion_dict = {'scope': replica['scope'].external,
                                 'name': replica['name'],
                                 'rse': rse_name,
                                 'file-size': replica['bytes'],
                                 'bytes': replica['bytes'],
                                 'url': replica['pfn'],
                                 'protocol': prot.attributes['scheme'],
                                 'datatype': replica['datatype']}
                if replica['scope'].vo != 'def':
                    deletion_dict['vo'] = replica['scope'].vo
                logger(logging.DEBUG, 'Deletion ATTEMPT of %s:%s as %s on %s', replica['scope'], replica['name'], replica['pfn'], rse_name)
                timer = monitor.Timer()
                # For STAGING RSEs, no physical deletion
                if is_staging:
                    logger(logging.WARNING, 'Deletion STAGING of %s:%s as %s on %s, will only delete the catalog and not do physical deletion', replica['scope'], replica['name'], replica['pfn'], rse_name)
                    deleted_files.append({'scope': replica['scope'], 'name': replica['name']})
                    continue

                if replica['pfn']:
                    pfn = replica['pfn']
                    # sign the URL if necessary
                    if prot.attributes['scheme'] == 'https' and rse_info['sign_url'] is not None:
                        pfn = get_signed_url(rse_id, rse_info['sign_url'], 'delete', pfn)
                    if prot.attributes['scheme'] == 'globus':
                        pfns_to_bulk_delete.append(replica['pfn'])
                    else:
                        prot.delete(pfn)
                else:
                    logger(logging.WARNING, 'Deletion UNAVAILABLE of %s:%s as %s on %s', replica['scope'], replica['name'], replica['pfn'], rse_name)

                timer.stop()
                timer.record('daemons.reaper.delete.{scheme}.{rse}', labels={'scheme': prot.attributes['scheme'], 'rse': rse_name})
                duration = timer.elapsed

                deleted_files.append({'scope': replica['scope'], 'name': replica['name']})

                deletion_dict['duration'] = duration
                add_message('deletion-done', deletion_dict)
                logger(logging.INFO, 'Deletion SUCCESS of %s:%s as %s on %s in %.2f seconds', replica['scope'], replica['name'], replica['pfn'], rse_name, duration)

            except SourceNotFound:
                duration = timer.elapsed
                err_msg = 'Deletion NOTFOUND of %s:%s as %s on %s in %.2f seconds' % (replica['scope'], replica['name'], replica['pfn'], rse_name, duration)
                logger(logging.WARNING, '%s', err_msg)
                deletion_dict['reason'] = 'File Not Found'
                deletion_dict['duration'] = duration
                add_message('deletion-not-found', deletion_dict)
                deleted_files.append({'scope': replica['scope'], 'name': replica['name']})

            except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                duration = timer.elapsed
                logger(logging.WARNING, 'Deletion NOACCESS of %s:%s as %s on %s: %s in %.2f', replica['scope'], replica['name'], replica['pfn'], rse_name, str(error), duration)
                deletion_dict['reason'] = str(error)
                deletion_dict['duration'] = duration
                add_message('deletion-failed', deletion_dict)
                noaccess_attempts += 1
                if noaccess_attempts >= auto_exclude_threshold:
                    logger(logging.INFO, 'Too many (%d) NOACCESS attempts for %s. RSE will be temporarly excluded.', noaccess_attempts, rse_name)
                    REGION.set('temporary_exclude_%s' % rse_id, True)
                    EXCLUDED_RSE_GAUGE.labels(rse=rse_name).set(1)
                    break

            except Exception as error:
                duration = timer.elapsed
                logger(logging.CRITICAL, 'Deletion CRITICAL of %s:%s as %s on %s in %.2f seconds : %s', replica['scope'], replica['name'], replica['pfn'], rse_name, duration, str(traceback.format_exc()))
                deletion_dict['reason'] = str(error)
                deletion_dict['duration'] = duration
                add_message('deletion-failed', deletion_dict)

        if pfns_to_bulk_delete and prot.attributes['scheme'] == 'globus':
            logger(logging.DEBUG, 'Attempting bulk delete on RSE %s for scheme %s', rse_name, prot.attributes['scheme'])
            prot.bulk_delete(pfns_to_bulk_delete)

    except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
        for replica in replicas:
            logger(logging.WARNING, 'Deletion NOACCESS of %s:%s as %s on %s: %s', replica['scope'], replica['name'], replica['pfn'], rse_name, str(error))
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
        logger(logging.INFO, 'Cannot connect to %s. RSE will be temporarly excluded.', rse_name)
        REGION.set('temporary_exclude_%s' % rse_id, True)
        EXCLUDED_RSE_GAUGE.labels(rse=rse_name).set(1)
    finally:
        prot.close()
    return deleted_files


def _rse_deletion_hostname(rse: RseData) -> "Optional[str]":
    """
    Retrieves the hostname of the default deletion protocol
    """
    rse.ensure_loaded(load_info=True)
    for prot in rse.info['protocols']:
        if prot['domains']['wan']['delete'] == 1:
            return prot['hostname']
    return None


def get_max_deletion_threads_by_hostname(hostname):
    """
    Internal method to check RSE usage and limits.

    :param hostname: the hostname of the SE

    :returns: The maximum deletion thread for the SE.
    """
    result = REGION.get('max_deletion_threads_%s' % hostname)
    if result is NO_VALUE:
        try:
            max_deletion_thread = config_get('reaper', 'max_deletion_threads_%s' % hostname)
        except (NoOptionError, NoSectionError, RuntimeError):
            try:
                max_deletion_thread = config_get('reaper', 'nb_workers_by_hostname')
            except (NoOptionError, NoSectionError, RuntimeError):
                max_deletion_thread = 5
        REGION.set('max_deletion_threads_%s' % hostname, max_deletion_thread)
        result = max_deletion_thread
    return result


def __try_reserve_worker_slot(heartbeat_handler: "HeartbeatHandler", rse: RseData, hostname: str, logger: "Callable[..., Any]") -> "Optional[str]":
    """
    The maximum number of concurrent workers is limited per hostname and per RSE due to storage performance reasons.
    This function tries to reserve a slot to run the deletion worker for the given RSE and hostname.

    The function doesn't guarantee strong consistency: the number of total workers may end being slightly
    higher than the configured limit.

    The reservation is done using the "payload" field of the rucio heart-beats.
    if reservation successful, returns the heartbeat payload used for the reservation. Otherwise, returns None
    """

    rse_hostname_key = '%s,%s' % (rse.id, hostname)
    payload_cnt = list_payload_counts(heartbeat_handler.executable, older_than=heartbeat_handler.older_than)
    tot_threads_for_hostname = 0
    tot_threads_for_rse = 0
    for key in payload_cnt:
        if key and key.find(',') > -1:
            if key.split(',')[1] == hostname:
                tot_threads_for_hostname += payload_cnt[key]
            if key.split(',')[0] == str(rse.id):
                tot_threads_for_rse += payload_cnt[key]
    max_deletion_thread = get_max_deletion_threads_by_hostname(hostname)
    if rse_hostname_key in payload_cnt and tot_threads_for_hostname >= max_deletion_thread:
        logger(logging.DEBUG, 'Too many deletion threads for %s on RSE %s. Back off', hostname, rse.name)
        return None
    logger(logging.INFO, 'Nb workers on %s smaller than the limit (current %i vs max %i). Starting new worker on RSE %s', hostname, tot_threads_for_hostname, max_deletion_thread, rse.name)
    _, total_workers, logger = heartbeat_handler.live(payload=rse_hostname_key)
    logger(logging.DEBUG, 'Total deletion workers for %s : %i', hostname, tot_threads_for_hostname + 1)
    return rse_hostname_key


def __check_rse_usage_cached(rse: RseData, greedy: bool = False, logger: "Callable[..., Any]" = logging.log) -> 'Tuple[int, bool]':
    """
    Wrapper around __check_rse_usage which manages the cache entry.
    """
    cache_key = 'rse_usage_%s' % rse.id
    result = REGION.get(cache_key)
    if result is NO_VALUE:
        result = __check_rse_usage(rse=rse, greedy=greedy, logger=logger)
        REGION.set(cache_key, result)
    return result


def __check_rse_usage(rse: RseData, greedy: bool = False, logger: "Callable[..., Any]" = logging.log) -> 'Tuple[int, bool]':
    """
    Internal method to check RSE usage and limits.

    :param rse_name:     The RSE name.
    :param rse_id:  The RSE id.
    :param greedy:  If True, needed_free_space will be set to 1TB regardless of actual rse usage.

    :returns: needed_free_space, only_delete_obsolete.
    """

    # First of all check if greedy mode is enabled for this RSE
    if greedy:
        return 1000000000000, False

    rse.ensure_loaded(load_limits=True, load_usage=True, load_attributes=True)

    # Get RSE limits
    min_free_space = rse.limits.get('MinFreeSpace', 0)

    # Check from which sources to get used and total spaces
    # Default is storage
    source_for_total_space = rse.attributes.get('source_for_total_space', 'storage')
    source_for_used_space = rse.attributes.get('source_for_used_space', 'storage')

    logger(logging.DEBUG, 'RSE: %s, source_for_total_space: %s, source_for_used_space: %s',
           rse.name, source_for_total_space, source_for_used_space)

    # Get total, used and obsolete space
    total_space_entry = None
    used_space_entry = None
    obsolete_entry = None
    for entry in rse.usage:
        if total_space_entry and used_space_entry and obsolete_entry:
            break

        entry_source = entry['source']
        if not total_space_entry and entry_source == source_for_total_space:
            total_space_entry = entry
        if not used_space_entry and entry_source == source_for_used_space:
            used_space_entry = entry
        if not obsolete_entry and entry_source == 'obsolete':
            obsolete_entry = entry

    obsolete = 0
    if obsolete_entry:
        obsolete = obsolete_entry['used']

    # If no information is available about disk space, do nothing except if there are replicas with Epoch tombstone
    needed_free_space = 0
    if not total_space_entry:
        if not obsolete:
            return needed_free_space, False
        return obsolete, True
    if not used_space_entry:
        return needed_free_space, False

    # Extract the total and used space
    total, used = total_space_entry['total'], used_space_entry['used']

    free = total - used
    if min_free_space:
        needed_free_space = min_free_space - free

    # If needed_free_space negative, nothing to delete except if some Epoch tombstoned replicas
    if needed_free_space <= 0:
        return obsolete, True
    else:
        return needed_free_space, False


def reaper(rses, include_rses, exclude_rses, vos=None, chunk_size=100, once=False, greedy=False,
           scheme=None, delay_seconds=0, sleep_time=60, auto_exclude_threshold=100, auto_exclude_timeout=600):
    """
    Main loop to select and delete files.

    :param rses:                   List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param include_rses:           RSE expression to include RSEs.
    :param exclude_rses:           RSE expression to exclude RSEs from the Reaper.
    :param vos:                    VOs on which to look for RSEs. Only used in multi-VO mode.
                                   If None, we either use all VOs if run from "def", or the current VO otherwise.
    :param chunk_size:             The size of chunk for deletion.
    :param once:                   If True, only runs one iteration of the main loop.
    :param greedy:                 If True, delete right away replicas with tombstone.
    :param scheme:                 Force the reaper to use a particular protocol, e.g., mock.
    :param delay_seconds:          The delay to query replicas in BEING_DELETED state.
    :param sleep_time:             Time between two cycles.
    :param auto_exclude_threshold: Number of service unavailable exceptions after which the RSE gets temporarily excluded.
    :param auto_exclude_timeout:   Timeout for temporarily excluded RSEs.
    """

    executable = 'reaper'
    oidc_account = config_get('reaper', 'oidc_account', False, 'root')
    oidc_scope = config_get('reaper', 'oidc_scope', False, 'delete')
    oidc_audience = config_get('reaper', 'oidc_audience', False, 'rse')

    run_daemon(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=executable,
        logger_prefix=executable,
        partition_wait_time=0 if once else 10,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            rses=rses,
            include_rses=include_rses,
            exclude_rses=exclude_rses,
            vos=vos,
            chunk_size=chunk_size,
            greedy=greedy,
            scheme=scheme,
            delay_seconds=delay_seconds,
            auto_exclude_threshold=auto_exclude_threshold,
            auto_exclude_timeout=auto_exclude_timeout,
            oidc_account=oidc_account,
            oidc_scope=oidc_scope,
            oidc_audience=oidc_audience,
        )
    )


def run_once(rses, include_rses, exclude_rses, vos, chunk_size, greedy, scheme,
             delay_seconds, auto_exclude_threshold, auto_exclude_timeout,
             heartbeat_handler, oidc_account, oidc_scope, oidc_audience, **_kwargs):

    must_sleep = True

    _, total_workers, logger = heartbeat_handler.live()
    logger(logging.INFO, 'Reaper started')

    # try to get auto exclude parameters from the config table. Otherwise use CLI parameters.
    auto_exclude_threshold = config_get('reaper', 'auto_exclude_threshold', default=auto_exclude_threshold, raise_exception=False)
    auto_exclude_timeout = config_get('reaper', 'auto_exclude_timeout', default=auto_exclude_timeout, raise_exception=False)
    # Check if there is a Judge Evaluator backlog
    max_evaluator_backlog_count = config_get('reaper', 'max_evaluator_backlog_count', default=None, raise_exception=False)
    max_evaluator_backlog_duration = config_get('reaper', 'max_evaluator_backlog_duration', default=None, raise_exception=False)
    if max_evaluator_backlog_count or max_evaluator_backlog_duration:
        backlog = get_evaluation_backlog()
        count_is_hit = max_evaluator_backlog_count and backlog[0] and backlog[0] > max_evaluator_backlog_count
        duration_is_hit = max_evaluator_backlog_duration and backlog[1] and backlog[1] < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration)
        if count_is_hit and duration_is_hit:
            logger(logging.ERROR, 'Reaper: Judge evaluator backlog count and duration hit, stopping operation')
            return must_sleep
        elif count_is_hit:
            logger(logging.ERROR, 'Reaper: Judge evaluator backlog count hit, stopping operation')
            return must_sleep
        elif duration_is_hit:
            logger(logging.ERROR, 'Reaper: Judge evaluator backlog duration hit, stopping operation')
            return must_sleep

    rses_to_process = get_rses_to_process(rses, include_rses, exclude_rses, vos)
    rses_to_process = [RseData(id_=rse['id'], name=rse['rse'], columns=rse) for rse in rses_to_process]
    if not rses_to_process:
        logger(logging.ERROR, 'Reaper: No RSEs found. Will sleep for 30 seconds')
        return must_sleep

    # On big deletion campaigns, we desire to re-iterate fast on RSEs which have a lot of data to delete.
    # The called function will return the RSEs which have more work remaining.
    # Call the deletion routine again on this returned subset of RSEs.
    # Scale the number of allowed iterations with the number of total reaper workers
    iteration = 0
    max_fast_reiterations = int(log2(total_workers))
    while rses_to_process and iteration <= max_fast_reiterations:
        rses_to_process = _run_once(
            rses_to_process=rses_to_process,
            chunk_size=chunk_size,
            greedy=greedy,
            scheme=scheme,
            delay_seconds=delay_seconds,
            auto_exclude_threshold=auto_exclude_threshold,
            auto_exclude_timeout=auto_exclude_timeout,
            heartbeat_handler=heartbeat_handler,
            oidc_account=oidc_account,
            oidc_scope=oidc_scope,
            oidc_audience=oidc_audience,
        )
        if rses_to_process and iteration < max_fast_reiterations:
            logger(logging.INFO, "Will perform fast-reiteration %d/%d with rses: %s", iteration + 1, max_fast_reiterations, [str(rse) for rse in rses_to_process])
        iteration += 1

    if rses_to_process:
        # There is still more work to be performed.
        # Inform the calling context that it must call reaper again (on the full list of rses)
        must_sleep = False

    return must_sleep


def _run_once(rses_to_process, chunk_size, greedy, scheme,
              delay_seconds, auto_exclude_threshold, auto_exclude_timeout,
              heartbeat_handler, oidc_account, oidc_scope, oidc_audience, **_kwargs):

    dict_rses = {}
    _, total_workers, logger = heartbeat_handler.live()
    tot_needed_free_space = 0
    for rse in rses_to_process:
        # Check if RSE is blocklisted
        if rse.columns['availability'] % 2 == 0:
            logger(logging.DEBUG, 'RSE %s is blocklisted for delete', rse.name)
            continue
        rse.ensure_loaded(load_attributes=True)
        enable_greedy = rse.attributes.get('greedyDeletion', False) or greedy
        needed_free_space, only_delete_obsolete = __check_rse_usage_cached(rse, greedy=enable_greedy, logger=logger)
        if needed_free_space:
            dict_rses[rse] = [needed_free_space, only_delete_obsolete, enable_greedy]
            tot_needed_free_space += needed_free_space
        elif only_delete_obsolete:
            dict_rses[rse] = [needed_free_space, only_delete_obsolete, enable_greedy]
        else:
            logger(logging.DEBUG, 'Nothing to delete on %s', rse.name)

    rses_with_params = [(rse, needed_free_space, only_delete_obsolete, enable_greedy)
                        for rse, (needed_free_space, only_delete_obsolete, enable_greedy) in dict_rses.items()]

    # Ordering the RSEs based on the needed free space
    sorted_rses = sorted(rses_with_params, key=lambda x: x[1], reverse=True)
    log_msg_str = ', '.join(f'{rse}:{needed_free_space}:{only_delete_obsolete}:{enable_greedy}'
                            for rse, needed_free_space, only_delete_obsolete, enable_greedy in sorted_rses)
    logger(logging.DEBUG, 'List of RSEs to process ordered by needed space desc: %s', log_msg_str)

    random.shuffle(rses_with_params)

    work_remaining_by_rse = {}
    paused_rses = []
    for rse, needed_free_space, only_delete_obsolete, enable_greedy in rses_with_params:
        result = REGION.get('pause_deletion_%s' % rse.id, expiration_time=120)
        if result is not NO_VALUE:
            paused_rses.append(rse.name)
            logger(logging.DEBUG, 'Not enough replicas to delete on %s during the previous cycle. Deletion paused for a while', rse.name)
            continue

        result = REGION.get('temporary_exclude_%s' % rse.id, expiration_time=auto_exclude_timeout)
        if result is not NO_VALUE:
            logger(logging.WARNING, 'Too many failed attempts for %s in last cycle. RSE is temporarly excluded.', rse.name)
            EXCLUDED_RSE_GAUGE.labels(rse=rse.name).set(1)
            continue
        EXCLUDED_RSE_GAUGE.labels(rse=rse.name).set(0)

        percent = 0
        if tot_needed_free_space:
            percent = needed_free_space / tot_needed_free_space * 100
        logger(logging.DEBUG, 'Working on %s. Percentage of the total space needed %.2f', rse.name, percent)

        rse_hostname = _rse_deletion_hostname(rse)
        if not rse_hostname:
            logger(logging.WARNING, 'No default delete protocol for %s', rse.name)
            REGION.set('pause_deletion_%s' % rse.id, True)
            continue

        hb_payload = __try_reserve_worker_slot(heartbeat_handler=heartbeat_handler, rse=rse, hostname=rse_hostname, logger=logger)
        if not hb_payload:
            # Might need to reschedule a try on this RSE later in the same cycle
            continue

        # List and mark BEING_DELETED the files to delete
        del_start_time = time.time()
        try:
            use_temp_tables = config_get_bool('core', 'use_temp_tables', default=False)
            with monitor.Timer('reaper.list_unlocked_replicas'):
                if only_delete_obsolete:
                    logger(logging.DEBUG, 'Will run list_and_mark_unlocked_replicas on %s. No space needed, will only delete EPOCH tombstoned replicas', rse.name)
                if use_temp_tables:
                    replicas = list_and_mark_unlocked_replicas(limit=chunk_size,
                                                               bytes_=needed_free_space,
                                                               rse_id=rse.id,
                                                               delay_seconds=delay_seconds,
                                                               only_delete_obsolete=only_delete_obsolete,
                                                               session=None)
                else:
                    replicas = list_and_mark_unlocked_replicas_no_temp_table(limit=chunk_size,
                                                                             bytes_=needed_free_space,
                                                                             rse_id=rse.id,
                                                                             delay_seconds=delay_seconds,
                                                                             only_delete_obsolete=only_delete_obsolete,
                                                                             session=None)
            logger(logging.DEBUG, 'list_and_mark_unlocked_replicas on %s for %s bytes in %s seconds: %s replicas', rse.name, needed_free_space, time.time() - del_start_time, len(replicas))
            if (len(replicas) == 0 and enable_greedy) or (len(replicas) < chunk_size and not enable_greedy):
                logger(logging.DEBUG, 'Not enough replicas to delete on %s (%s requested vs %s returned). Will skip any new attempts on this RSE until next cycle', rse.name, chunk_size, len(replicas))
                REGION.set('pause_deletion_%s' % rse.id, True)
                work_remaining_by_rse[rse] = False
            else:
                work_remaining_by_rse[rse] = True

        except (DatabaseException, IntegrityError, DatabaseError) as error:
            logger(logging.ERROR, '%s', str(error))
            continue
        except Exception:
            logger(logging.CRITICAL, 'Exception', exc_info=True)
            continue
        # Physical  deletion will take place there
        try:
            rse.ensure_loaded(load_info=True, load_attributes=True)
            auth_token = None
            if oidc_account and rse.attributes.get('oidc_support', False):
                account = InternalAccount(oidc_account, vo=rse.columns['vo'])
                token_dict = get_token_for_account_operation(account, req_audience=oidc_audience, req_scope=oidc_scope, admin=True)
                if token_dict is not None and 'token' in token_dict:
                    auth_token = token_dict['token']
                    logger(logging.DEBUG, 'OIDC authentication used for deletion.')
            prot = rsemgr.create_protocol(rse.info, 'delete', scheme=scheme, auth_token=auth_token, logger=logger)
            for file_replicas in chunks(replicas, chunk_size):
                # Refresh heartbeat
                _, total_workers, logger = heartbeat_handler.live(payload=hb_payload)
                del_start_time = time.time()
                for replica in file_replicas:
                    try:
                        replica['pfn'] = str(list(rsemgr.lfns2pfns(rse_settings=rse.info,
                                                                   lfns=[{'scope': replica['scope'].external, 'name': replica['name'], 'path': replica['path']}],
                                                                   operation='delete', scheme=scheme).values())[0])
                    except (ReplicaUnAvailable, ReplicaNotFound) as error:
                        logger(logging.WARNING, 'Failed get pfn UNAVAILABLE replica %s:%s on %s with error %s', replica['scope'], replica['name'], rse.name, str(error))
                        replica['pfn'] = None

                    except Exception:
                        logger(logging.CRITICAL, 'Exception', exc_info=True)

                is_staging = rse.columns['staging_area']
                deleted_files = delete_from_storage(heartbeat_handler, hb_payload, file_replicas, prot, rse.info, is_staging, auto_exclude_threshold, logger=logger)
                logger(logging.INFO, '%i files processed in %s seconds', len(file_replicas), time.time() - del_start_time)

                # Then finally delete the replicas
                del_start = time.time()
                with monitor.Timer('reaper.delete_replicas'):
                    delete_replicas(rse_id=rse.id, files=deleted_files)
                logger(logging.DEBUG, 'delete_replicas successed on %s : %s replicas in %s seconds', rse.name, len(deleted_files), time.time() - del_start)
                DELETION_COUNTER.inc(len(deleted_files))
        except Exception:
            logger(logging.CRITICAL, 'Exception', exc_info=True)

    if paused_rses:
        logger(logging.INFO, 'Deletion paused for a while for following RSEs: %s', ', '.join(paused_rses))

    rses_with_more_work = [rse for rse, has_more_work in work_remaining_by_rse.items() if has_more_work]
    return rses_with_more_work


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(threads=1, chunk_size=100, once=False, greedy=False, rses=None, scheme=None, exclude_rses=None, include_rses=None, vos=None, delay_seconds=0, sleep_time=60, auto_exclude_threshold=100, auto_exclude_timeout=600):
    """
    Starts up the reaper threads.

    :param threads:                The total number of workers.
    :param chunk_size:             The size of chunk for deletion.
    :param threads_per_worker:     Total number of threads created by each worker.
    :param once:                   If True, only runs one iteration of the main loop.
    :param greedy:                 If True, delete right away replicas with tombstone.
    :param rses:                   List of RSEs the reaper should work against.
                                   If empty, it considers all RSEs.
    :param scheme:                 Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param exclude_rses:           RSE expression to exclude RSEs from the Reaper.
    :param include_rses:           RSE expression to include RSEs.
    :param vos:                    VOs on which to look for RSEs. Only used in multi-VO mode.
                                   If None, we either use all VOs if run from "def",
                                   or the current VO otherwise.
    :param delay_seconds:          The delay to query replicas in BEING_DELETED state.
    :param sleep_time:             Time between two cycles.
    :param auto_exclude_threshold: Number of service unavailable exceptions after which the RSE gets temporarily excluded.
    :param auto_exclude_timeout:   Timeout for temporarily excluded RSEs.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    logging.log(logging.INFO, 'main: starting processes')
    rses_to_process = get_rses_to_process(rses, include_rses, exclude_rses, vos)
    if not rses_to_process:
        logging.log(logging.ERROR, 'Reaper: No RSEs found. Exiting.')
        return

    logging.log(logging.INFO, 'Reaper: This instance will work on RSEs: %s', ', '.join([rse['rse'] for rse in rses_to_process]))

    logging.log(logging.INFO, 'starting reaper threads')
    threads_list = [threading.Thread(target=reaper, kwargs={'once': once,
                                                            'rses': rses,
                                                            'include_rses': include_rses,
                                                            'exclude_rses': exclude_rses,
                                                            'vos': vos,
                                                            'chunk_size': chunk_size,
                                                            'greedy': greedy,
                                                            'sleep_time': sleep_time,
                                                            'delay_seconds': delay_seconds,
                                                            'scheme': scheme,
                                                            'auto_exclude_threshold': auto_exclude_threshold,
                                                            'auto_exclude_timeout': auto_exclude_timeout}) for _ in range(0, threads)]

    for thread in threads_list:
        thread.start()

    logging.log(logging.INFO, 'waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads_list:
        threads_list = [thread.join(timeout=3.14) for thread in threads_list if thread and thread.is_alive()]
