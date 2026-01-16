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

"""
Reaper is a daemon to manage file deletion.
"""

import concurrent.futures.thread  # noqa (https://github.com/rucio/rucio/issues/6548)

import functools
import logging
import random
import threading
import time
import traceback
from configparser import NoOptionError, NoSectionError
from datetime import datetime, timedelta
from math import log2
from typing import TYPE_CHECKING, Any, Optional

from dogpile.cache.api import NoValue
from sqlalchemy.exc import DatabaseError, IntegrityError

import rucio.db.sqla.util
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get_bool, config_get_int
from rucio.common.constants import RseAttr, DEFAULT_VO
from rucio.common.exception import DatabaseException, ReplicaNotFound, ReplicaUnAvailable, ResourceTemporaryUnavailable, RSEAccessDenied, RSENotFound, RSEProtocolNotSupported, ServiceUnavailable, SourceNotFound, VONotFound
from rucio.common.logging import setup_logging
from rucio.common.stopwatch import Stopwatch
from rucio.common.utils import chunks
from rucio.core.credential import get_signed_url
from rucio.core.heartbeat import list_payload_counts
from rucio.core.message import add_message
from rucio.core.monitor import MetricManager
from rucio.core.oidc import request_token
from rucio.core.replica import delete_replicas, list_and_mark_unlocked_replicas, refresh_replicas
from rucio.core.rse import RseData, determine_audience_for_rse, determine_scope_for_rse, list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_evaluation_backlog
from rucio.core.vo import list_vos
from rucio.daemons.common import run_daemon
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from types import FrameType

    from rucio.common.types import LFNDict, LoggerFunction
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()
METRICS = MetricManager(module=__name__)
REGION = MemcacheRegion(expiration_time=600)
DAEMON_NAME = 'reaper'

EXCLUDED_RSE_GAUGE = METRICS.gauge('excluded_rses.{rse}', documentation='Temporarly excluded RSEs')


def get_rses_to_process(
        rses: Optional["Iterable[str]"],
        include_rses: Optional[str],
        exclude_rses: Optional[str],
        vos: Optional["Sequence[str]"]
) -> Optional[list[dict[str, Any]]]:
    """
    Return the list of RSEs to process based on rses, include_rses and exclude_rses

    :param rses:               List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param exclude_rses:       RSE expression to exclude RSEs from the Reaper.
    :param include_rses:       RSE expression to include RSEs.
    :param vos:                VOs on which to look for RSEs. Only used in multi-VO mode.
                               If None, we either use all VOs if run from DEFAULT_VO

    :returns: A list of RSEs to process
    """
    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logging.log(logging.WARNING, 'Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = [DEFAULT_VO]
    else:
        with db_session(DatabaseOperationType.READ) as session:
            if vos:
                invalid = set(vos) - set([v['vo'] for v in list_vos(session=session)])
                if invalid:
                    msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                    raise VONotFound(msg)
            else:
                vos = [v['vo'] for v in list_vos(session=session)]
        logging.log(logging.INFO, 'Reaper: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    cache_key = 'rses_to_process_1%s2%s3%s' % (str(rses), str(include_rses), str(exclude_rses))
    if multi_vo:
        cache_key += '@%s' % '-'.join(vo for vo in vos)

    result = REGION.get(cache_key)
    if not isinstance(result, NoValue):
        return result

    all_rses: list[dict[str, Any]] = []
    for vo in vos:
        all_rses.extend(list_rses(filters={'vo': vo}))

    if rses:
        invalid = set(rses) - set([rse['rse'] for rse in all_rses])
        if invalid:
            msg = 'RSE{} {} cannot be found'.format('s' if len(invalid) > 1 else '',
                                                    ', '.join([repr(rse) for rse in invalid]))
            raise RSENotFound(msg)
        rses_to_process = [rse for rse in all_rses if rse['rse'] in rses]
    else:
        rses_to_process = all_rses

    if include_rses:
        included_rses = parse_expression(include_rses)
        rses_to_process = [rse for rse in rses_to_process if rse in included_rses]

    if exclude_rses:
        excluded_rses = parse_expression(exclude_rses)
        rses_to_process = [rse for rse in rses_to_process if rse not in excluded_rses]

    REGION.set(cache_key, rses_to_process)
    logging.log(logging.INFO, 'Reaper: This instance will work on RSEs: %s', ', '.join([rse['rse'] for rse in rses_to_process]))
    return rses_to_process


def delete_from_storage(heartbeat_handler, hb_payload, replicas, prot, rse_info, is_staging, auto_exclude_threshold, delay_seconds: int = 600, logger=logging.log) -> tuple[list[dict[str, Any]], int]:
    """
    Delete replicas from storage and manage database cleanup.

    By default, this function follows the traditional approach where all successfully
    deleted replicas are returned to the caller for database cleanup after all
    physical deletions are complete.

    Optionally, an optimization can be enabled where successfully deleted replicas are
    immediately removed from the database in batches during physical deletion. This
    reduces database load and prevents race conditions with other workers, but changes
    the traditional flow.

    The immediate cleanup optimization can be enabled using the 'enable_immediate_cleanup'
    parameter in the [reaper] section of rucio.cfg (default: False).

    When immediate cleanup is enabled:
    - Immediate batched database cleanup of successfully deleted replicas
    - Dynamic refresh timing based on delay_seconds parameter
    - Race condition prevention through processed replica tracking
    - Configurable batch sizes for different deployment scenarios

    :param heartbeat_handler: Heartbeat handler for worker coordination
    :param hb_payload: Heartbeat payload for this worker
    :param replicas: List of replicas to delete
    :param prot: Protocol object for storage operations
    :param rse_info: RSE information dictionary
    :param is_staging: Whether this is a staging RSE
    :param auto_exclude_threshold: Threshold for auto-excluding problematic RSEs
    :param delay_seconds: The delay to query replicas in BEING_DELETED state. Used to calculate refresh trigger time.
    :param logger: Logging function to use

    :returns: Tuple containing:
              - List of files that need database cleanup. In traditional mode (default),
                this contains all successfully deleted files. In immediate cleanup mode,
                this only contains files that failed immediate cleanup.
              - Number of replicas successfully processed (for metric accounting).
    """
    deleted_files: list[dict[str, Any]] = []
    successful_replicas: int = 0
    rse_name = rse_info['rse']
    rse_id = rse_info['id']
    noaccess_attempts = 0
    pfns_to_bulk_delete = []

    # Batch configuration for immediate database cleanup (optional optimization)
    enable_immediate_cleanup = config_get_bool('reaper', 'enable_immediate_cleanup', default=False, raise_exception=False)
    db_batch_size = config_get_int('reaper', 'db_batch_size', default=50, raise_exception=False)
    pending_db_deletions = []
    processed_replicas = []  # Track replicas that have been processed (successfully or not)

    # Debug: Log initial configuration
    logger(logging.DEBUG, 'Starting deletion for RSE %s with %d replicas, enable_immediate_cleanup=%s, db_batch_size=%d, delay_seconds=%d',
           rse_name, len(replicas), enable_immediate_cleanup, db_batch_size, delay_seconds)

    refresh_start_time = time.time()
    # Calculate trigger time based on delay_seconds. Default to 80% of delay_seconds to provide buffer
    # before other workers can pick up the replicas (which happens after delay_seconds)
    refresh_trigger_ratio = config_get_int('reaper', 'refresh_trigger_ratio', default=80, raise_exception=False) / 100.0
    logger(logging.DEBUG, 'Refresh trigger time calculation: refresh_trigger_ratio=%.2f%%, delay_seconds=%d',
           refresh_trigger_ratio * 100, delay_seconds)

    # Validate configuration parameters and log warnings for potential issues (only when immediate cleanup enabled)
    if enable_immediate_cleanup:
        if db_batch_size <= 0:
            logger(logging.WARNING, 'Invalid db_batch_size=%d, using default=50', db_batch_size)
            db_batch_size = 50
        elif db_batch_size > len(replicas):
            logger(logging.DEBUG, 'db_batch_size (%d) larger than replica count (%d) - will clean all at once',
                   db_batch_size, len(replicas))

    if refresh_trigger_ratio <= 0 or refresh_trigger_ratio > 1:
        logger(logging.WARNING, 'Invalid refresh_trigger_ratio=%.2f, using default=0.8', refresh_trigger_ratio)
        refresh_trigger_ratio = 0.8

    # Recalculate trigger_time after validation
    trigger_time = delay_seconds * refresh_trigger_ratio
    logger(logging.DEBUG, 'Refresh trigger time set to %.1f seconds (%.0f%% of delay_seconds=%d)',
           trigger_time, refresh_trigger_ratio * 100, delay_seconds)

    try:
        prot.connect()
        num_replicas_processed = 0  # counts how many replicas have already been processed

        # Debug: Track optimization metrics
        immediate_cleanups = 0  # Number of immediate cleanup batches performed
        total_immediate_cleaned = 0  # Total replicas cleaned immediately

        logger(logging.DEBUG, 'Connected to protocol %s, starting replica deletion loop', prot.attributes['scheme'])

        for replica in replicas:
            # Physical deletion
            _, _, logger = heartbeat_handler.live(payload=hb_payload)
            stopwatch = Stopwatch()
            deletion_dict = {'scope': replica['scope'].external,
                             'name': replica['name'],
                             'rse': rse_name,
                             'file-size': replica['bytes'],
                             'bytes': replica['bytes'],
                             'url': replica['pfn'],
                             'protocol': prot.attributes['scheme'],
                             'datatype': replica['datatype']}
            try:
                if replica['scope'].vo != DEFAULT_VO:
                    deletion_dict['vo'] = replica['scope'].vo
                logger(logging.DEBUG, 'Deletion ATTEMPT of %s:%s as %s on %s', replica['scope'], replica['name'], replica['pfn'], rse_name)
                # For STAGING RSEs, no physical deletion
                if is_staging:
                    logger(logging.WARNING, 'Deletion STAGING of %s:%s as %s on %s, '
                           'will only delete the catalog and not do physical deletion',
                           replica['scope'], replica['name'], replica['pfn'], rse_name)
                    deleted_files.append({'scope': replica['scope'], 'name': replica['name']})
                    successful_replicas += 1
                    # Add to pending database deletions for batched cleanup (only if immediate cleanup enabled)
                    if enable_immediate_cleanup:
                        pending_db_deletions.append({'scope': replica['scope'], 'name': replica['name']})
                        logger(logging.DEBUG, 'Added staging replica %s:%s to pending_db_deletions (count: %d)',
                               replica['scope'], replica['name'], len(pending_db_deletions))
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

                duration = stopwatch.elapsed
                METRICS.timer('delete.{scheme}.{rse}').labels(scheme=prot.attributes['scheme'], rse=rse_name).observe(duration)

                deleted_files.append({'scope': replica['scope'], 'name': replica['name']})
                successful_replicas += 1
                # Add to pending database deletions for batched cleanup (only if immediate cleanup enabled)
                if enable_immediate_cleanup:
                    pending_db_deletions.append({'scope': replica['scope'], 'name': replica['name']})
                    logger(logging.DEBUG, 'Added successfully deleted replica %s:%s to pending_db_deletions (count: %d)',
                           replica['scope'], replica['name'], len(pending_db_deletions))

                deletion_dict['duration'] = duration
                add_message('deletion-done', deletion_dict)
                logger(logging.INFO, 'Deletion SUCCESS of %s:%s as %s on %s in %.2f seconds', replica['scope'], replica['name'], replica['pfn'], rse_name, duration)

            except SourceNotFound:
                duration = stopwatch.elapsed
                err_msg = 'Deletion NOTFOUND of %s:%s as %s on %s in %.2f seconds' % (replica['scope'], replica['name'], replica['pfn'], rse_name, duration)
                logger(logging.WARNING, '%s', err_msg)
                deletion_dict['reason'] = 'File Not Found'
                deletion_dict['duration'] = duration
                add_message('deletion-not-found', deletion_dict)
                deleted_files.append({'scope': replica['scope'], 'name': replica['name']})
                successful_replicas += 1
                # Add to pending database deletions for batched cleanup (only if immediate cleanup enabled)
                if enable_immediate_cleanup:
                    pending_db_deletions.append({'scope': replica['scope'], 'name': replica['name']})
                    logger(logging.DEBUG, 'Added NOTFOUND replica %s:%s to pending_db_deletions (count: %d)',
                           replica['scope'], replica['name'], len(pending_db_deletions))

            except (ServiceUnavailable, RSEAccessDenied, ResourceTemporaryUnavailable) as error:
                duration = stopwatch.elapsed
                logger(logging.WARNING, 'Deletion NOACCESS of %s:%s as %s on %s: %s in %.2f',
                       replica['scope'], replica['name'], replica['pfn'], rse_name, str(error), duration)
                logger(logging.DEBUG, 'NOACCESS error for replica %s:%s - not added to pending_db_deletions',
                       replica['scope'], replica['name'])
                deletion_dict['reason'] = str(error)
                deletion_dict['duration'] = duration
                add_message('deletion-failed', deletion_dict)
                noaccess_attempts += 1
                if noaccess_attempts >= auto_exclude_threshold:
                    logger(logging.INFO, 'Too many (%d) NOACCESS attempts for %s. RSE will be temporarily excluded.', noaccess_attempts, rse_name)
                    REGION.set('temporary_exclude_%s' % rse_id, True)
                    METRICS.gauge('excluded_rses.{rse}').labels(rse=rse_name).set(1)

                    EXCLUDED_RSE_GAUGE.labels(rse=rse_name).set(1)
                    break

            except Exception as error:
                duration = stopwatch.elapsed
                logger(logging.CRITICAL, 'Deletion CRITICAL of %s:%s as %s on %s in %.2f seconds : %s',
                       replica['scope'], replica['name'], replica['pfn'], rse_name, duration, str(traceback.format_exc()))
                logger(logging.DEBUG, 'CRITICAL error for replica %s:%s - not added to pending_db_deletions',
                       replica['scope'], replica['name'])
                deletion_dict['reason'] = str(error)
                deletion_dict['duration'] = duration
                add_message('deletion-failed', deletion_dict)

            finally:
                # Track that this replica has been processed
                processed_replicas.append(replica)

                # Debug: Log replica processing status
                logger(logging.DEBUG, 'Processed replica %s:%s (%d/%d total), pending_db_deletions=%d',
                       replica['scope'], replica['name'], len(processed_replicas), len(replicas), len(pending_db_deletions))

                # Perform batched database cleanup for successfully deleted files (only if immediate cleanup enabled)
                if enable_immediate_cleanup and len(pending_db_deletions) >= db_batch_size:
                    try:
                        logger(logging.DEBUG, 'Triggering immediate cleanup for %d replicas (batch size reached)',
                               len(pending_db_deletions))
                        delete_replicas(rse_id=rse_id, files=pending_db_deletions)
                        immediate_cleanups += 1
                        total_immediate_cleaned += len(pending_db_deletions)
                        logger(logging.DEBUG, 'Immediate cleanup SUCCESS: deleted %d replicas from database (batch #%d)',
                               len(pending_db_deletions), immediate_cleanups)
                        # Remove successfully cleaned up files from deleted_files to avoid duplicate processing
                        for replica_dict in pending_db_deletions:
                            if replica_dict in deleted_files:
                                deleted_files.remove(replica_dict)
                        pending_db_deletions.clear()
                    except Exception as db_error:
                        logger(logging.WARNING, 'Failed to immediately delete replicas from database: %s', str(db_error))
                        logger(logging.DEBUG, 'Keeping %d files in pending_db_deletions for retry in main loop',
                               len(pending_db_deletions))
                        # Keep the files in pending_db_deletions for retry in the main loop

                # This control loop will run indefinitely until all deletions have gone through (or failed).
                # It assumes that for each deletion a timeout will occur (which will fail the deletion).
                # If that assumption is not true, we need to introduce a maximum retry counter to avoid the worker hanging
                # on individual deletions.
                num_replicas_processed += 1

                # After each replica is deleted we evaluate how much time we have left to delete.
                # If we are not able to delete all the replicas we got in, other workers will take the replicas because their update time will
                # be more than delay_seconds (refer to function list_and_mark_unlocked_replicas).
                # After trigger_time has passed, and if we still have some replicas to process, we bump the replicas updated_at field to current time
                # (which will delay the selectability by other workers by delay_seconds+ minutes).
                elapsed_time = time.time() - refresh_start_time
                if elapsed_time > trigger_time:  # trigger_time has passed
                    # Only refresh replicas that haven't been processed yet
                    remaining_replicas = [r for r in replicas if r not in processed_replicas]
                    if remaining_replicas:
                        logger(logging.DEBUG, 'Refresh triggered after %.1f seconds - refreshing %d remaining replicas (out of %d total)',
                               elapsed_time, len(remaining_replicas), len(replicas))
                        ok = refresh_replicas(rse_id=rse_id, replicas=remaining_replicas)
                        if not ok:
                            logger(logging.WARNING, "Failed to bump updated_at for remaining replicas BEING_DELETED")
                        else:
                            logger(logging.DEBUG, 'Successfully refreshed %d remaining replicas after %.1f seconds',
                                   len(remaining_replicas), elapsed_time)
                        refresh_start_time = time.time()  # reset it so we can trigger new refresh cycles.
                    else:
                        logger(logging.DEBUG, 'No remaining replicas to refresh after %.1f seconds', elapsed_time)

        if pfns_to_bulk_delete and prot.attributes['scheme'] == 'globus':
            logger(logging.DEBUG, 'Attempting bulk delete on RSE %s for scheme %s with %d files',
                   rse_name, prot.attributes['scheme'], len(pfns_to_bulk_delete))
            prot.bulk_delete(pfns_to_bulk_delete)

        # Clean up any remaining pending database deletions (only if immediate cleanup enabled)
        if enable_immediate_cleanup and pending_db_deletions:
            try:
                logger(logging.DEBUG, 'Final cleanup - deleting %d remaining replicas from database', len(pending_db_deletions))
                delete_replicas(rse_id=rse_id, files=pending_db_deletions)
                total_immediate_cleaned += len(pending_db_deletions)
                logger(logging.DEBUG, 'Final cleanup SUCCESS: deleted %d remaining replicas from database', len(pending_db_deletions))
                # Remove successfully cleaned up files from deleted_files to avoid duplicate processing
                for replica_dict in pending_db_deletions:
                    if replica_dict in deleted_files:
                        deleted_files.remove(replica_dict)
            except Exception as db_error:
                logger(logging.WARNING, 'Failed to delete remaining replicas from database: %s', str(db_error))
                logger(logging.DEBUG, 'Keeping %d files in deleted_files for main loop handling', len(pending_db_deletions))
                # Keep them in deleted_files so the main loop can handle them

        # Debug: Log final optimization statistics
        if enable_immediate_cleanup:
            logger(logging.DEBUG, 'Deletion complete for RSE %s - processed %d replicas, '
                   'performed %d immediate cleanups, total immediate cleaned: %d, remaining for main loop: %d',
                   rse_name, len(processed_replicas), immediate_cleanups, total_immediate_cleaned, len(deleted_files))
        else:
            logger(logging.DEBUG, 'Deletion complete for RSE %s - processed %d replicas, '
                   'all %d will be cleaned up by main loop (traditional mode)',
                   rse_name, len(processed_replicas), len(deleted_files))

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
            if replica['scope'].vo != DEFAULT_VO:
                payload['vo'] = replica['scope'].vo
            add_message('deletion-failed', payload)
        logger(logging.INFO, 'Cannot connect to %s. RSE will be temporarily excluded.', rse_name)
        REGION.set('temporary_exclude_%s' % rse_id, True)
        EXCLUDED_RSE_GAUGE.labels(rse=rse_name).set(1)
    finally:
        prot.close()
    return deleted_files, successful_replicas


def _rse_deletion_hostname(rse: RseData, scheme: Optional[str]) -> Optional[str]:
    """Retrieve the hostname of the highest-priority WAN deletion protocol."""
    rse.ensure_loaded(load_info=True)
    delete_protocols = [prot for prot in rse.info['protocols']
                        if prot['domains']['wan']['delete'] is not None]
    for prot in sorted(delete_protocols, key=lambda p: p['domains']['wan']['delete']):    # type: ignore (None excluded above)
        if scheme and prot['scheme'] != scheme:
            continue
        return prot['hostname']
    return None


def get_max_deletion_threads_by_hostname(hostname: str) -> int:
    """
    Internal method to check RSE usage and limits.

    :param hostname: the hostname of the SE

    :returns: The maximum deletion thread for the SE.
    """
    result = REGION.get('max_deletion_threads_%s' % hostname)
    if isinstance(result, NoValue):
        try:
            max_deletion_thread = config_get_int('reaper', 'max_deletion_threads_%s' % hostname)
        except (NoOptionError, NoSectionError, RuntimeError):
            try:
                max_deletion_thread = config_get_int('reaper', 'nb_workers_by_hostname')
            except (NoOptionError, NoSectionError, RuntimeError):
                max_deletion_thread = 5
        REGION.set('max_deletion_threads_%s' % hostname, max_deletion_thread)
        result = max_deletion_thread
    return result


def __try_reserve_worker_slot(heartbeat_handler: "HeartbeatHandler", rse: RseData, hostname: str, logger: "LoggerFunction") -> Optional[str]:
    """
    The maximum number of concurrent workers is limited per hostname and per RSE due to storage performance reasons.
    This function tries to reserve a slot to run the deletion worker for the given RSE and hostname.

    The function doesn't guarantee strong consistency: the number of total workers may end being slightly
    higher than the configured limit.

    The reservation is done using the "payload" field of the rucio heart-beats.
    if reservation successful, returns the heartbeat payload used for the reservation. Otherwise, returns None
    """

    rse_hostname_key = '%s,%s' % (rse.id, hostname)
    payload_cnt = list_payload_counts(heartbeat_handler.executable, older_than=heartbeat_handler.older_than)  # type: ignore (argument missing: session)
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


def __check_rse_usage_cached(rse: RseData, greedy: bool = False, logger: "LoggerFunction" = logging.log) -> tuple[int, bool]:
    """
    Wrapper around __check_rse_usage which manages the cache entry.
    """
    cache_key = 'rse_usage_%s' % rse.id
    result = REGION.get(cache_key)
    if isinstance(result, NoValue):
        result = __check_rse_usage(rse=rse, greedy=greedy, logger=logger)
        REGION.set(cache_key, result)
    return result


def __check_rse_usage(rse: RseData, greedy: bool = False, logger: "LoggerFunction" = logging.log) -> tuple[int, bool]:
    """
    Internal method to check RSE usage and limits.

    :param rse_name:     The RSE name.
    :param rse_id:  The RSE id.
    :param greedy:  If True, needed_free_space will be set to 1TB regardless of actual rse usage.

    :returns: needed_free_space, only_delete_obsolete.
    """

    needed_free_space = 0
    # First of all check if greedy mode is enabled for this RSE
    if greedy:
        return 1000000000000, False

    rse.ensure_loaded(load_limits=True, load_usage=True, load_attributes=True)
    available_sources = {}
    available_sources['total'] = {key['source']: key['total'] for key in rse.usage}
    available_sources['used'] = {key['source']: key['used'] for key in rse.usage}

    # Get RSE limits
    min_free_space = rse.limits.get('MinFreeSpace', 0)

    # Check from which sources to get used and total spaces (default storage)
    # If specified sources do not exist, only delete obsolete
    source_for_total_space = rse.attributes.get(RseAttr.SOURCE_FOR_TOTAL_SPACE, 'storage')
    if source_for_total_space not in available_sources['total']:
        logger(logging.WARNING, 'RSE: %s, \'%s\' requested for source_for_total_space but cannot be found. Will only delete obsolete',
               rse.name, source_for_total_space)
        return 0, True
    source_for_used_space = rse.attributes.get(RseAttr.SOURCE_FOR_USED_SPACE, 'storage')
    if source_for_used_space not in available_sources['used']:
        logger(logging.WARNING, 'RSE: %s, \'%s\' requested for source_for_used_space but cannot be found. Will only delete obsolete',
               rse.name, source_for_used_space)
        return 0, True

    logger(logging.DEBUG, 'RSE: %s, source_for_total_space: %s, source_for_used_space: %s',
           rse.name, source_for_total_space, source_for_used_space)

    # Get total and used space
    total = available_sources['total'][source_for_total_space]
    used = available_sources['used'][source_for_used_space]

    free = total - used
    if min_free_space:
        needed_free_space = min_free_space - free

    # If needed_free_space negative, nothing to delete except if some Epoch tombstoned replicas
    if needed_free_space > 0:
        return needed_free_space, False

    return 0, True


def reaper(
        rses: "Sequence[str]",
        include_rses: Optional[str],
        exclude_rses: Optional[str],
        vos: Optional["Sequence[str]"] = None,
        chunk_size: int = 100,
        once: bool = False,
        greedy: bool = False,
        scheme: Optional[str] = None,
        delay_seconds: int = 0,
        sleep_time: int = 60,
        auto_exclude_threshold: int = 100,
        auto_exclude_timeout: int = 600
) -> None:
    """
    Main loop to select and delete files.

    :param rses:                   List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param include_rses:           RSE expression to include RSEs.
    :param exclude_rses:           RSE expression to exclude RSEs from the Reaper.
    :param vos:                    VOs on which to look for RSEs. Only used in multi-VO mode.
                                   If None, we either use all VOs if run from DEFAULT_VO, or the current VO otherwise.
    :param chunk_size:             The size of chunk for deletion.
    :param once:                   If True, only runs one iteration of the main loop.
    :param greedy:                 If True, delete right away replicas with tombstone.
    :param scheme:                 Force the reaper to use a particular protocol, e.g., mock.
    :param delay_seconds:          The delay to query replicas in BEING_DELETED state.
    :param sleep_time:             Time between two cycles.
    :param auto_exclude_threshold: Number of service unavailable exceptions after which the RSE gets temporarily excluded.
    :param auto_exclude_timeout:   Timeout for temporarily excluded RSEs.
    """
    run_daemon(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=DAEMON_NAME,
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
        )
    )


def run_once(
        rses: "Sequence[str]",
        include_rses: Optional[str],
        exclude_rses: Optional[str],
        vos: Optional["Sequence[str]"],
        chunk_size: int,
        greedy: bool,
        scheme: Optional[str],
        delay_seconds: int,
        auto_exclude_threshold: int,
        auto_exclude_timeout: int,
        heartbeat_handler: "HeartbeatHandler",
        **_kwargs
) -> bool:

    must_sleep = True

    _, total_workers, logger = heartbeat_handler.live()
    logger(logging.INFO, 'Reaper started')

    # Debug: Log key optimization parameters
    enable_immediate_cleanup = config_get_bool('reaper', 'enable_immediate_cleanup', default=False, raise_exception=False)
    db_batch_size = config_get_int('reaper', 'db_batch_size', default=50, raise_exception=False)
    refresh_trigger_ratio = config_get_int('reaper', 'refresh_trigger_ratio', default=80, raise_exception=False)
    logger(logging.DEBUG, 'Optimization configuration - enable_immediate_cleanup=%s, db_batch_size=%d, refresh_trigger_ratio=%d%%, delay_seconds=%d, chunk_size=%d, total_workers=%d',
           enable_immediate_cleanup, db_batch_size, refresh_trigger_ratio, delay_seconds, chunk_size, total_workers)

    # try to get auto exclude parameters from the config table. Otherwise use CLI parameters.
    auto_exclude_threshold = config_get_int('reaper', 'auto_exclude_threshold', default=auto_exclude_threshold, raise_exception=False)
    auto_exclude_timeout = config_get_int('reaper', 'auto_exclude_timeout', default=auto_exclude_timeout, raise_exception=False)
    # Check if there is a Judge Evaluator backlog
    max_evaluator_backlog_count = config_get_int('reaper', 'max_evaluator_backlog_count', default=None, raise_exception=False)
    max_evaluator_backlog_duration = config_get_int('reaper', 'max_evaluator_backlog_duration', default=None, raise_exception=False)
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
    if not rses_to_process:
        logger(logging.WARNING, 'Reaper: No RSEs found, sleeping')
        return must_sleep
    else:
        rses_to_process = [RseData(id_=rse['id'], name=rse['rse'], columns=rse) for rse in rses_to_process]

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
        )
        if rses_to_process and iteration < max_fast_reiterations:
            logger(logging.INFO, "Will perform fast-reiteration %d/%d with rses: %s", iteration + 1, max_fast_reiterations, [str(rse) for rse in rses_to_process])
        iteration += 1

    if rses_to_process:
        # There is still more work to be performed.
        # Inform the calling context that it must call reaper again (on the full list of rses)
        must_sleep = False

    return must_sleep


def _run_once(
        rses_to_process: "Iterable[RseData]",
        chunk_size: int,
        greedy: bool,
        scheme: Optional[str],
        delay_seconds: int,
        auto_exclude_threshold: int,
        auto_exclude_timeout: int,
        heartbeat_handler: "HeartbeatHandler",
        **_kwargs
) -> list[RseData]:

    dict_rses = {}
    _, total_workers, logger = heartbeat_handler.live()
    tot_needed_free_space = 0

    # Debug: Track optimization metrics for this cycle
    cycle_total_replicas_processed = 0
    cycle_rses_processed = 0
    for rse in rses_to_process:
        # Check if RSE is blocklisted
        if not rse.columns['availability_delete']:
            logger(logging.DEBUG, 'RSE %s is blocklisted for delete', rse.name)
            continue
        rse.ensure_loaded(load_attributes=True)
        enable_greedy = rse.attributes.get(RseAttr.GREEDYDELETION, False) or greedy
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
        if not isinstance(result, NoValue):
            paused_rses.append(rse.name)
            logger(logging.DEBUG, 'Not enough replicas to delete on %s during the previous cycle. Deletion paused for a while', rse.name)
            continue

        result = REGION.get('temporary_exclude_%s' % rse.id, expiration_time=auto_exclude_timeout)
        if not isinstance(result, NoValue):
            logger(logging.WARNING, 'Too many failed attempts for %s in last cycle. RSE is temporarily excluded.', rse.name)
            EXCLUDED_RSE_GAUGE.labels(rse=rse.name).set(1)
            continue
        EXCLUDED_RSE_GAUGE.labels(rse=rse.name).set(0)

        percent = 0
        if tot_needed_free_space:
            percent = needed_free_space / tot_needed_free_space * 100
        logger(logging.DEBUG, 'Working on %s. Percentage of the total space needed %.2f', rse.name, percent)

        rse_hostname = _rse_deletion_hostname(rse, scheme)
        if not rse_hostname:
            if scheme:
                logger(logging.WARNING, 'Protocol %s not supported on %s', scheme, rse.name)
            else:
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
            with METRICS.timer('list_unlocked_replicas'):
                if only_delete_obsolete:
                    logger(logging.DEBUG, 'Will run list_and_mark_unlocked_replicas on %s. No space needed, will only delete EPOCH tombstoned replicas', rse.name)
                replicas = list_and_mark_unlocked_replicas(limit=chunk_size,
                                                           bytes_=needed_free_space,
                                                           rse_id=rse.id,
                                                           delay_seconds=delay_seconds,
                                                           only_delete_obsolete=only_delete_obsolete,
                                                           session=None)  # type: ignore (argument missing: session)
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
            prot = rsemgr.create_protocol(rse.info, 'delete', scheme=scheme, logger=logger)
            if rse.attributes.get(RseAttr.OIDC_SUPPORT) is True and prot.attributes['scheme'] == 'davs':
                audience = determine_audience_for_rse(rse.id)
                # FIXME: At the time of writing, StoRM requires `storage.read`
                # in order to perform a stat operation.
                scope = determine_scope_for_rse(rse.id, scopes=['storage.modify', 'storage.read'])
                auth_token = request_token(audience, scope)
                if auth_token:
                    logger(logging.INFO, 'Using a token to delete on RSE %s', rse.name)
                    prot = rsemgr.create_protocol(rse.info, 'delete', scheme=scheme, auth_token=auth_token, logger=logger)
                else:
                    logger(logging.WARNING, 'Failed to procure a token to delete on RSE %s', rse.name)
            for file_replicas in chunks(replicas, chunk_size):
                # Refresh heartbeat
                _, total_workers, logger = heartbeat_handler.live(payload=hb_payload)

                del_start_time = time.time()

                # for each replica object obtain the pfn
                for replica in file_replicas:
                    try:
                        lfn: "LFNDict" = {
                            'scope': replica['scope'].external,
                            'name': replica['name'],
                            'path': replica['path']
                        }
                        replica['pfn'] = str(list(rsemgr.lfns2pfns(rse_settings=rse.info,
                                                                   lfns=[lfn],
                                                                   operation='delete', scheme=scheme).values())[0])
                    except (ReplicaUnAvailable, ReplicaNotFound) as error:
                        logger(logging.WARNING, 'Failed get pfn UNAVAILABLE replica %s:%s on %s with error %s', replica['scope'], replica['name'], rse.name, str(error))
                        replica['pfn'] = None

                    except Exception:
                        logger(logging.CRITICAL, 'Exception', exc_info=True)

                is_staging = rse.columns['staging_area']

                # First, delete the physical files associated with a replica
                deleted_files, successful_replicas = delete_from_storage(heartbeat_handler, hb_payload, file_replicas, prot, rse.info, is_staging, auto_exclude_threshold, delay_seconds, logger=logger)
                logger(logging.INFO, '%i files processed in %s seconds', len(file_replicas), time.time() - del_start_time)

                # Then delete any remaining replicas that weren't handled by immediate cleanup
                if deleted_files:
                    logger(logging.DEBUG, 'Main loop cleanup - %d files remaining for database deletion after immediate cleanup optimization', len(deleted_files))
                    del_start = time.time()
                    delete_replicas(rse_id=rse.id, files=deleted_files)  # type: ignore (argument missing: session)
                    logger(logging.DEBUG, 'Main loop cleanup SUCCESS - deleted %d remaining replicas in %.2f seconds', len(deleted_files), time.time() - del_start)
                else:
                    logger(logging.DEBUG, 'Main loop cleanup - no files remaining, all handled by immediate cleanup optimization')
                METRICS.counter('deletion.done').inc(successful_replicas)

                # Debug: Track cycle metrics
                cycle_total_replicas_processed += len(file_replicas)
                cycle_rses_processed += 1

        except RSEProtocolNotSupported:
            logger(logging.WARNING, 'Protocol %s not supported on %s', scheme, rse.name)
        except Exception:
            logger(logging.CRITICAL, 'Exception', exc_info=True)

    if paused_rses:
        logger(logging.INFO, 'Deletion paused for a while for following RSEs: %s', ', '.join(paused_rses))

    # Debug: Log cycle summary
    logger(logging.DEBUG, 'Cycle complete - processed %d RSEs, %d total replicas',
           cycle_rses_processed, cycle_total_replicas_processed)

    rses_with_more_work = [rse for rse, has_more_work in work_remaining_by_rse.items() if has_more_work]

    if rses_with_more_work:
        logger(logging.DEBUG, '%d RSEs have more work remaining: %s',
               len(rses_with_more_work), [rse.name for rse in rses_with_more_work])

    return rses_with_more_work


def stop(signum: Optional[int] = None, frame: Optional["FrameType"] = None) -> None:
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(
        threads: int = 1,
        chunk_size: int = 100,
        once: bool = False,
        greedy: bool = False,
        rses: Optional["Sequence[str]"] = None,
        scheme: Optional[str] = None,
        exclude_rses: Optional[str] = None,
        include_rses: Optional[str] = None,
        vos: Optional["Sequence[str]"] = None,
        delay_seconds: int = 0,
        sleep_time: int = 60,
        auto_exclude_threshold: int = 100,
        auto_exclude_timeout: int = 600
) -> None:
    """
    Starts up the reaper threads.

    :param threads:                The total number of workers.
    :param chunk_size:             The size of chunk for deletion.
    :param once:                   If True, only runs one iteration of the main loop.
    :param greedy:                 If True, delete right away replicas with tombstone.
    :param rses:                   List of RSEs the reaper should work against.
                                   If empty, it considers all RSEs.
    :param scheme:                 Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param exclude_rses:           RSE expression to exclude RSEs from the Reaper.
    :param include_rses:           RSE expression to include RSEs.
    :param vos:                    VOs on which to look for RSEs. Only used in multi-VO mode.
                                   If None, we either use all VOs if run from DEFAULT_VO,
                                   or the current VO otherwise.
    :param delay_seconds:          The delay to query replicas in BEING_DELETED state.
    :param sleep_time:             Time between two cycles.
    :param auto_exclude_threshold: Number of service unavailable exceptions after which the RSE gets temporarily excluded.
    :param auto_exclude_timeout:   Timeout for temporarily excluded RSEs.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

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
