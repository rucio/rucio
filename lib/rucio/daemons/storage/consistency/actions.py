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

"""
Storage-Consistency-Actions is a daemon to delete dark files, and re-subscribe the missing ones, identified previously in a Storage-Consistency-Scanner run.
"""

import csv
import glob
import json
import logging
import os
import re
import socket
import time
import threading
import traceback

from datetime import datetime

from rucio.common import exception
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import daemon_sleep
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_gauge, record_counter
from rucio.core.quarantined_replica import add_quarantined_replicas
from rucio.core.replica import __exist_replicas, update_replicas_states
from rucio.core.rse import list_rses, get_rse_id
from rucio.rse.rsemanager import lfns2pfns, get_rse_info, parse_pfns

# FIXME: these are needed by local version of declare_bad_file_replicas()
# TODO: remove after move of this code to core/replica.py - see https://github.com/rucio/rucio/pull/5068
from rucio.db.sqla import models
from rucio.db.sqla.session import transactional_session
from rucio.db.sqla.constants import (ReplicaState, BadFilesStatus)
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm.exc import FlushError

graceful_stop = threading.Event()

# FIXME: declare_bad_file_replicas will be used directly from core/replica.py when handling of DID is added there
# TODO: remove after move to core/replica.py


@transactional_session
def declare_bad_file_replicas(dids, rse_id, reason, issuer,
                              status=BadFilesStatus.BAD, scheme=None, session=None):
    """
    Declare a list of bad replicas.

    :param dids: The list of DIDs.
    :param rse_id: The RSE id.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param status: Either BAD or SUSPICIOUS.
    :param scheme: The scheme of the PFNs.
    :param session: The database session in use.
    """
    unknown_replicas = []
    replicas = []
    for did in dids:
        scope = InternalScope(did['scope'], vo=issuer.vo)
        name = did['name']
        path = None
        scope, name, path, exists, already_declared, size = __exist_replicas(rse_id, [(scope, name, path)],
                                                                             session=session)[0]
        if exists and ((str(status) == str(BadFilesStatus.BAD) and not
                        already_declared) or str(status) == str(BadFilesStatus.SUSPICIOUS)):
            replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id,
                             'state': ReplicaState.BAD})
            new_bad_replica = models.BadReplicas(scope=scope, name=name, rse_id=rse_id,
                                                 reason=reason, state=status, account=issuer,
                                                 bytes=size)
            new_bad_replica.save(session=session, flush=False)
            session.query(models.Source).filter_by(scope=scope, name=name,
                                                   rse_id=rse_id).delete(synchronize_session=False)
        else:
            if already_declared:
                unknown_replicas.append('%s:%s %s' % (did['scope'], did['name'],
                                        'Already declared'))
            else:
                unknown_replicas.append('%s:%s %s' % (did['scope'], did['name'],
                                        'Unknown replica'))
    if str(status) == str(BadFilesStatus.BAD):
        # For BAD file, we modify the replica state, not for suspicious
        try:
            # there shouldn't be any exceptions since all replicas exist
            update_replicas_states(replicas, session=session)
        except exception.UnsupportedOperation:
            raise exception.ReplicaNotFound("One or several replicas don't exist.")
    try:
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)
    except DatabaseError as error:
        raise exception.RucioException(error.args)
    except FlushError as error:
        raise exception.RucioException(error.args)

    return unknown_replicas


# TODO: This is Igor's Stats class.It will be factored out as a separate class in a future version of the code.
# - Igor Mandrichenko <ivm@fnal.gov>, 2018

class Stats(object):

    def __init__(self, path):
        self.path = path
        self.Data = {}

    def __getitem__(self, name):
        return self.Data[name]

    def __setitem__(self, name, value):
        self.Data[name] = value
        self.save()

    def get(self, name, default=None):
        return self.Data.get(name, default)

    def update(self, data):
        self.Data.update(data)
        self.save()

    def save(self):
        try:
            with open(self.path, "r") as f:
                data = f.read()
        except:
            data = ""
        data = json.loads(data or "{}")
        data.update(self.Data)
        open(self.path, "w").write(json.dumps(data, indent=4))


def write_stats(my_stats, stats_file, stats_key=None):
    if stats_file:
        stats = {}
        if os.path.isfile(stats_file):
            with open(stats_file, "r") as f:
                stats = json.loads(f.read())
        if stats_key:
            stats[stats_key] = my_stats
        else:
            stats.update(my_stats)
        open(stats_file, "w").write(json.dumps(stats))
# TODO: Consider throwing an error here if stats_file is not defined
# TODO: Consider breaking the logic into two functions, following discussion in https://github.com/rucio/rucio/pull/5120#discussion_r792673599


def cmp2dark(new_list, old_list, comm_list, stats_file):

    t0 = time.time()
    stats_key = "cmp2dark"
    my_stats = stats = None

    with open(new_list, "r") as a_list, open(old_list, "r") as b_list,\
         open(comm_list, "w") as out_list:

        if stats_file is not None:
            stats = Stats(stats_file)
            my_stats = {
                "elapsed": None,
                "start_time": t0,
                "end_time": None,
                "new_list": new_list,
                "old_list": old_list,
                "out_list": out_list.name,
                "status": "started"
            }
            stats[stats_key] = my_stats

        a_set = set(line.strip() for line in a_list)
        b_set = set(line.strip() for line in b_list)


# The intersection of the two sets is what can be deleted
        out_set = a_set & b_set
        out_list.writelines("\n".join(sorted(list(out_set))))

    t1 = time.time()

    if stats_file:
        my_stats.update({
            "elapsed": t1 - t0,
            "end_time": t1,
            "status": "done"
        })
        stats[stats_key] = my_stats


# TODO: Changes suggested in https://github.com/rucio/rucio/pull/5120#discussion_r792681245
def parse_filename(fn):
    # filename looks like this:
    #
    #   <rse>_%Y_%m_%d_%H_%M_<type>.<extension>
    #
    fn, ext = fn.rsplit(".", 1)
    parts = fn.split("_")
    typ = parts[-1]
    timestamp_parts = parts[-6:-1]
    timestamp = "_".join(timestamp_parts)
    rse = "_".join(parts[:-6])
    return rse, timestamp, typ, ext


def list_cc_scanned_rses(path):
    files = glob.glob(f"{path}/*_stats.json")
    rses = set()
    for path in files:
        fn = path.rsplit("/", 1)[-1]
        rse, timestamp, typ, ext = parse_filename(fn)
        rses.add(rse)
    return sorted(list(rses))


def list_runs_by_age(path, rse, reffile):
    files = glob.glob(f"{path}/{rse}_*_stats.json")
    r, reftimestamp, typ, ext = parse_filename(reffile)
    reftime = datetime.strptime(reftimestamp, '%Y_%m_%d_%H_%M')
    runs = {}
    for path in files:
        fn = path.rsplit("/", 1)[-1]
        if os.stat(path).st_size > 0:
            r, timestamp, typ, ext = parse_filename(fn)
            filetime = datetime.strptime(timestamp, '%Y_%m_%d_%H_%M')
            fileagedays = (reftime - filetime).days
            if r == rse:
                # if the RSE was X, then rses like X_Y will appear in this list too,
                # so double check that we get the right RSE
                runs.update({path: fileagedays})

    return {k: v for k, v in sorted(runs.items(), reverse=True)}


def list_runs(path, rse, nlast=0):
    files = glob.glob(f"{path}/{rse}_*_stats.json")
    runs = []
    for path in files:
        fn = path.rsplit("/", 1)[-1]
        if os.stat(path).st_size > 0:
            r, timestamp, typ, ext = parse_filename(fn)
            if r == rse:
                # if the RSE was X, then rses like X_Y will appear in this list too,
                # so double check that we get the right RSE
                runs.append(path)
    if nlast == 0:
        nlast = len(runs)
    return sorted(runs, reverse=False)[-nlast:]


def list_unprocessed_runs(path, rse, nlast=0):
    files = glob.glob(f"{path}/{rse}_*_stats.json")
    unproc_runs = []
    for path in files:
        fn = path.rsplit("/", 1)[-1]
        if os.stat(path).st_size > 0:
            r, timestamp, typ, ext = parse_filename(fn)
            if r == rse:
                # if the RSE was X, then rses like X_Y will appear in this list too,
                # so double check that we get the right RSE
                if not was_cc_attempted(path):
                    unproc_runs.append(timestamp)
    if nlast == 0:
        nlast = len(unproc_runs)
    return sorted(unproc_runs, reverse=True)[-nlast:]


def was_cc_attempted(stats_file):
    try:
        f = open(stats_file, "r")
    except:
        print("get_data: error ", stats_file)
        return None
    stats = json.loads(f.read())
    if "cc_dark" in stats or "cc_miss" in stats:
        return True
    else:
        return False


def was_cc_processed(stats_file):
    try:
        f = open(stats_file, "r")
    except:
        print("get_data: error ", stats_file)
        return None
    stats = json.loads(f.read())
    cc_dark_status = ''
    cc_miss_status = ''
    if "cc_dark" in stats:
        if "status" in stats['cc_dark']:
            cc_dark_status = stats['cc_dark']['status']
    if "cc_miss" in stats:
        if "status" in stats['cc_miss']:
            cc_miss_status = stats['cc_miss']['status']
    if cc_dark_status == 'done' or cc_miss_status == 'done':
        return True
    else:
        return False


def process_dark_files(path, scope, rse, latest_run, max_dark_fraction,
                       max_files_at_site, old_enough_run, force_proceed):

    """
    Process the Dark Files.
    """

    prefix = 'storage-consistency-actions (process_dark_files())'
    logger = formatted_logger(logging.log, prefix + '%s')

# Create a cc_dark section in the stats file

    t0 = time.time()
    stats_key = "cc_dark"
    cc_stats = stats = None
    stats = Stats(latest_run)
    cc_stats = {
        "start_time": t0,
        "end_time": None,
        "initial_dark_files": 0,
        "confirmed_dark_files": 0,
        "x-check_run": old_enough_run,
        "status": "started"
    }
    stats[stats_key] = cc_stats

# Compare the two lists, and take only the dark files that are in both
    latest_dark = re.sub('_stats.json$', '_D.list', latest_run)
    old_enough_dark = re.sub('_stats.json$', '_D.list', old_enough_run)
    logger(logging.INFO, 'latest_dark = %s' % latest_dark)
    logger(logging.INFO, 'old_enough_dark = %s' % old_enough_dark)
    confirmed_dark = re.sub('_stats.json$', '_DeletionList.csv', latest_run)
    cmp2dark(new_list=latest_dark, old_list=old_enough_dark,
             comm_list=confirmed_dark, stats_file=latest_run)

###
#   SAFEGUARD
#   If a large fraction (larger than 'max_dark_fraction') of the files at a site
#   are reported as 'dark', do NOT proceed with the deletion.
#   Instead, put a warning in the _stats.json file, so that an operator can have a look.
###

# Get the number of files recorded by the scanner
    dark_files = sum(1 for line in open(latest_dark))
    confirmed_dark_files = sum(1 for line in open(confirmed_dark))
    logger(logging.INFO, 'dark_files %d' % dark_files)
    logger(logging.INFO, 'confirmed_dark_files %d' % confirmed_dark_files)
    logger(logging.INFO, 'confirmed_dark_files/max_files_at_sit = %f'
           % (confirmed_dark_files / max_files_at_site))
    logger(logging.INFO, 'max_dark_fraction configured for this RSE: %f'
           % max_dark_fraction)

# Labels for the Prometheus counters/gauges
    labels = {'rse': rse}

    record_gauge('storage.consistency.actions_dark_files_found',
                 confirmed_dark_files, labels=labels)
    record_gauge('storage.consistency.actions_dark_files_confirmed',
                 confirmed_dark_files, labels=labels)

    deleted_files = 0
    if confirmed_dark_files / max_files_at_site < max_dark_fraction or force_proceed is True:
        logger(logging.INFO, 'Can proceed with dark files deletion')

# Then, do the real deletion (code from DeleteReplicas.py)
        issuer = InternalAccount('root')
        with open(confirmed_dark, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for name, in reader:
                logger(logging.INFO, 'Processing a dark file:\n RSE %s  Scope: %s  Name: %s'
                       % (rse, scope, name))
                rse_id = get_rse_id(rse=rse)
                Intscope = InternalScope(scope=scope, vo=issuer.vo)
                lfns = [{'scope': scope, 'name': name}]

                attributes = get_rse_info(rse=rse)
                pfns = lfns2pfns(rse_settings=attributes, lfns=lfns, operation='delete')
                pfn_key = scope + ':' + name
                url = pfns[pfn_key]
                urls = [url]
                paths = parse_pfns(attributes, urls, operation='delete')
                replicas = [{'scope': Intscope, 'rse_id': rse_id, 'name': name,
                             'path': paths[url]['path'] + paths[url]['name']}]
                add_quarantined_replicas(rse_id, replicas, session=None)
                deleted_files += 1
                labels = {'rse': rse}
                record_counter('storage.consistency.actions_dark_files_deleted_counter',
                               delta=1, labels=labels)

# Update the stats
        t1 = time.time()

        cc_stats.update({
            "end_time": t1,
            "initial_dark_files": dark_files,
            "confirmed_dark_files": deleted_files,
            "status": "done"
        })
        stats[stats_key] = cc_stats
        record_gauge('storage.consistency.actions_dark_files_deleted',
                     deleted_files, labels=labels)

    else:
        darkperc = 100. * confirmed_dark_files / max_files_at_site
        logger(logging.WARNING, '\n ATTENTION: Too many DARK files! (%3.2f%%) \n\
               Stopping and asking for operators help.' % darkperc)

# Update the stats
        t1 = time.time()

        cc_stats.update({
            "end_time": t1,
            "initial_dark_files": dark_files,
            "confirmed_dark_files": 0,
            "status": "ABORTED",
            "aborted_reason": "%3.2f%% dark" % darkperc,
        })
        stats[stats_key] = cc_stats
        record_gauge('storage.consistency.actions_dark_files_deleted', 0, labels=labels)


def process_miss_files(path, scope, rse, latest_run, max_miss_fraction,
                       max_files_at_site, old_enough_run, force_proceed):

    """
    Process the Missing Replicas.
    """

    prefix = 'storage-consistency-actions (process_miss_files())'
    logger = formatted_logger(logging.log, prefix + '%s')

    latest_miss = re.sub('_stats.json$', '_M.list', latest_run)
    logger(logging.INFO, 'latest_missing = %s' % latest_miss)

# Create a cc_miss section in the stats file

    t0 = time.time()
    stats_key = "cc_miss"
    cc_stats = stats = None
    stats = Stats(latest_run)
    cc_stats = {
        "start_time": t0,
        "end_time": None,
        "initial_miss_files": 0,
        "confirmed_miss_files": 0,
        "x-check_run": old_enough_run,
        "status": "started"
    }
    stats[stats_key] = cc_stats

###
#   SAFEGUARD
#   If a large fraction (larger than 'max_miss_fraction') of the files at a site are reported as
#   'missing', do NOT proceed with the invalidation.
#   Instead, put a warning in the _stats.json file, so that an operator can have a look.
###

    miss_files = sum(1 for line in open(latest_miss))
    logger(logging.INFO, 'miss_files = %d' % miss_files)
    logger(logging.INFO, 'miss_files/max_files_at_site = %f' % (miss_files / max_files_at_site))
    logger(logging.INFO, 'max_miss_fraction configured for this RSE (in %%): %f' % max_miss_fraction)

    labels = {'rse': rse}
    record_gauge('storage.consistency.actions_miss_files_found', miss_files, labels=labels)

    if miss_files / max_files_at_site < max_miss_fraction or force_proceed is True:
        logger(logging.INFO, 'Can proceed with missing files retransfer')

        invalidated_files = 0
        issuer = InternalAccount('root')
        with open(latest_miss, 'r') as csvfile:
            reader = csv.reader(csvfile)
            reason = "invalidating damaged/missing replica"
            for name, in reader:
                logger(logging.INFO, 'Processing invalid replica:\n RSE: %s Scope: %s Name: %s'
                       % (rse, scope, name))

                rse_id = get_rse_id(rse=rse)
                dids = [{'scope': scope, 'name': name}]
                declare_bad_file_replicas(dids=dids, rse_id=rse_id, reason=reason,
                                          issuer=issuer)
                invalidated_files += 1
                record_counter('storage.consistency.actions_miss_files_to_retransfer_counter',
                               delta=1, labels=labels)

# TODO: The stats updating can be refactored in a future version of the Stats class.
# See: https://github.com/rucio/rucio/pull/5120#discussion_r792688019
# Update the stats
            t1 = time.time()

            cc_stats.update({
                "end_time": t1,
                "initial_miss_files": miss_files,
                "confirmed_miss": invalidated_files,
                "status": "done"
            })
            stats[stats_key] = cc_stats
            record_gauge('storage.consistency.actions_miss_files_to_retransfer',
                         invalidated_files, labels=labels)

    else:
        missperc = 100. * miss_files / max_files_at_site
        logger(logging.WARNING, '\n Too many MISS files (%3.2f%%)!\n\
         Stopping and asking for operators help.' % missperc)

# Update the stats
        t1 = time.time()

        cc_stats.update({
            "end_time": t1,
            "initial_miss_files": miss_files,
            "confirmed_miss_files": 0,
            "status": "ABORTED",
            "aborted_reason": "%3.2f%% miss" % missperc,
        })
        stats[stats_key] = cc_stats
        record_gauge('storage.consistency.actions_miss_files_to_retransfer',
                     0, labels=labels)


def deckard(scope, rse, dark_min_age, dark_threshold_percent, miss_threshold_percent,
            force_proceed, scanner_files_path):

    """
    The core of CC actions.
    Use the results of the CC Scanner to check one RSE for confirmed dark files and delete them.
    Re-subscribe missing files.
    """

    prefix = 'storage-consistency-actions (running original deckard code)'
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Now running the original deckard code...')

    path = scanner_files_path
    minagedark = dark_min_age
    max_dark_fraction = dark_threshold_percent
    max_miss_fraction = miss_threshold_percent
    logger(logging.INFO, 'Scanner Output Path: %s \n minagedark: %d \n max_dark_fraction: %f\
      \n max_miss_fraction: %f' % (path, minagedark, max_dark_fraction, max_miss_fraction))

    scanner_files = 0
    dbdump_before_files = 0
    dbdump_after_files = 0

# Check if we have any scans available for that RSE
    if rse in list_cc_scanned_rses(path):

        # Have any of them still not been processed?
        # (no CC_dark or CC-miss sections in _stats.json)
        np_runs = list_unprocessed_runs(path, rse)
        logger(logging.INFO, 'Found %d unprocessed runs for RSE: %s' % (len(np_runs), rse))

        latest_run = list_runs(path, rse, 1)[0]

        # Get the number of files recorded by the scanner
        logger(logging.INFO, 'latest_run %s' % latest_run)
        with open(latest_run, "r") as f:
            fstats = json.loads(f.read())
            if "scanner" in fstats:
                scanner_stats = fstats["scanner"]
                if "total_files" in scanner_stats:
                    scanner_files = scanner_stats["total_files"]
                else:
                    scanner_files = 0
                    for root_info in scanner_stats["roots"]:
                        scanner_files += root_info["files"]
            if "dbdump_before" in fstats:
                dbdump_before_files = fstats["dbdump_before"]["files"]
            if "dbdump_after" in fstats:
                dbdump_after_files = fstats["dbdump_after"]["files"]

        max_files_at_site = max(scanner_files, dbdump_before_files, dbdump_after_files)
        if max_files_at_site == 0:
            logger(logging.WARNING, '\n No files reported by scanner for this run.\
             Will skip processing.')

        logger(logging.INFO, 'scanner_files: %d \n dbdump_before_files: %d\
          \n dbdump_after_files: %d \n max_files_at_site: %d' %
               (scanner_files, dbdump_before_files, dbdump_after_files, max_files_at_site))


# Was the latest run ever attempted to be processed?
        logger(logging.INFO, 'Was the latest run %s attempted to be processed already? - %s'
               % (latest_run, was_cc_attempted(latest_run)))
        if max_files_at_site > 0 and (was_cc_attempted(latest_run) is False or force_proceed is True):
            logger(logging.INFO, 'Will try to process the run')

# Is there another run, at least "minagedark" old, for this RSE?
            old_enough_run = None
            d = list_runs_by_age(path, rse, latest_run)
            if len([k for k in d if d[k] > minagedark]) > 0:
                # i.e. there is another dark run with appropriate age
                old_enough_run = [k for k in d if d[k] > minagedark][0]
                logger(logging.INFO, 'Found another run %d days older than the latest.\
                  \n Will compare the dark files in the two.' % minagedark)
                logger(logging.INFO, 'The first  %d days older run is: %s'
                       % (minagedark, old_enough_run))

                process_dark_files(path, scope, rse, latest_run, max_dark_fraction,
                                   max_files_at_site, old_enough_run, force_proceed)
            else:
                logger(logging.INFO, 'There is no other run for this RSE at least %d days older,\
                 so cannot safely proceed with dark files deleteion.' % minagedark)

            process_miss_files(path, scope, rse, latest_run, max_miss_fraction,
                               max_files_at_site, old_enough_run, force_proceed)

        else:
            # This run was already processed
            logger(logging.INFO, 'Nothing to do here')

    else:
        # No scans outputs are available for this RSE
        logger(logging.INFO, 'No scans available for this RSE')


def deckard_loop(scope, rses, dark_min_age, dark_threshold_percent, miss_threshold_percent,
                 force_proceed, scanner_files_path):

    prefix = 'storage-consistency-actions (deckard_loop())'
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'A loop over all RSEs')
    for rse in rses:
        logger(logging.INFO, 'Now processing RSE: %s' % rse)
        deckard(scope, rse, dark_min_age, dark_threshold_percent, miss_threshold_percent,
                force_proceed, scanner_files_path)


def actions_loop(once, scope, rses, sleep_time, dark_min_age, dark_threshold_percent,
                 miss_threshold_percent, force_proceed, scanner_files_path):

    """
    Main loop to apply the CC actions
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    executable = 'storage-consistency-actions'
    heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)

    # Make an initial heartbeat
    # so that all storage-consistency-actions have the correct worker number on the next try
    prefix = 'storage-consistency-actions[%i/%i] ' %\
             (heartbeat['assign_thread'], heartbeat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'hostname: %s  pid: %d  current_thread: %s' %
           (hostname, pid, current_thread))

    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            heartbeat = live(executable=executable, hostname=hostname, pid=pid,
                             thread=current_thread)
            logger(logging.INFO, 'heartbeat? %s' % heartbeat)

            prefix = 'storage-consistency-actions[%i/%i] ' %\
                     (heartbeat['assign_thread'], heartbeat['nr_threads'])
            logger(logging.INFO, 'prefix: %s' % prefix)
            start = time.time()
            logger(logging.DEBUG, 'Start time: %f' % start)

            deckard_loop(scope, rses, dark_min_age, dark_threshold_percent, miss_threshold_percent,
                         force_proceed, scanner_files_path)
            daemon_sleep(start_time=start, sleep_time=sleep_time, graceful_stop=graceful_stop,
                         logger=logger)

        except Exception as e:
            traceback.print_exc()
            logger(logging.WARNING, '\n Something went wrong here... %s' % e)
            logger(logging.WARNING, '\n Something went wrong here... %s ' % (e.__class__.__name__))
        if once:
            break

    die(executable=executable, hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, scope=None, rses=None, sleep_time=60, default_dark_min_age=28, default_dark_threshold_percent=1.0,
        default_miss_threshold_percent=1.0, force_proceed=False, default_scanner_files_path="/var/cache/consistency-dump",
        threads=1):
    """
    Starts up the Consistency-Actions.
    """

    setup_logging()

    prefix = 'storage-consistency-actions (run())'
    logger = formatted_logger(logging.log, prefix + '%s')

    # TODO: These variables should be sourced from the RSE config in the future.
    # For now, they are passed as arguments, and to emphasize that fact, we are re-assigning them:
    dark_min_age = default_dark_min_age
    dark_threshold_percent = default_dark_threshold_percent
    miss_threshold_percent = default_miss_threshold_percent
    scanner_files_path = default_scanner_files_path

    if rses == []:
        logger(logging.INFO, 'NO RSEs passed. Will loop over all writable RSEs.')

        rses = [rse['rse'] for rse in list_rses({'availability_write': True})]

# Could limit it only to Tier-2s:
#        rses = [rse['rse'] for rse in list_rses({'tier': 2, 'availability_write': True})]

    logging.info('\n RSEs: %s' % rses)
    logger(logging.INFO, '\n RSEs: %s  \n run once: %r \n Sleep time: %d  \n Dark min age (days): %d\
     \n Dark files threshold %%: %f  \n Missing files threshold %%: %f  \n Force proceed: %r\
     \n Scanner files path: %s ' % (rses, once, sleep_time, dark_min_age, dark_threshold_percent,
           miss_threshold_percent, force_proceed, scanner_files_path))

    executable = 'storage-consistency-actions'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

# It was decided that for the time being this daemon is best executed in a single thread
# TODO: If this decicion is reversed in the future, the following line should be removed.
    threads = 1

    if once:
        actions_loop(once, scope, rses, sleep_time, dark_min_age, dark_threshold_percent,
                     miss_threshold_percent, force_proceed, scanner_files_path)
    else:
        logging.info('Consistency Actions starting %s threads' % str(threads))
        threads = [threading.Thread(target=actions_loop,
                                    kwargs={'once': once, 'scope': scope, 'rses': rses, 'sleep_time': sleep_time,
                                            'dark_min_age': dark_min_age,
                                            'dark_threshold_percent': dark_threshold_percent,
                                            'miss_threshold_percent': miss_threshold_percent,
                                            'force_proceed': force_proceed,
                                            'scanner_files_path': scanner_files_path}) for i in range(0, threads)]
        logger(logging.INFO, 'Threads: %d' % len(threads))
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
