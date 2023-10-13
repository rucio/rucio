#!/usr/bin/env python3
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
Suspicious-Replica-Recoverer is a daemon that deals with suspicious replicas based on if they are found available on other RSEs
or if they are the last remaining copy, on how many suspicious replicas are on a given RSE and on a replica's metadata.
Consequently, automatic replica recovery is triggered via necromancer daemon, which creates a rule for such bad replica(s).
"""

import functools
import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional

import rucio.db.sqla.util
from rucio.common.config import config_get_bool
from rucio.common.constants import SuspiciousAvailability
from rucio.common.exception import DatabaseException, VONotFound
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.core.did import get_metadata
from rucio.core.replica import (
    add_bad_pfns,
    declare_bad_file_replicas,
    get_suspicious_files,
    get_suspicious_reason,
    list_replicas,
)
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import add_rule
from rucio.core.vo import list_vos
from rucio.daemons.common import run_daemon
from rucio.db.sqla.util import get_db_time

if TYPE_CHECKING:
    from types import FrameType

GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'suspicious-replica-recoverer'


def check_suspicious_policy(policy: dict[str, str], file_metadata_datatype: str, file_metadata_scope: str) -> str:
    match_scope = False
    match_datatype = False
    action = ""

    if not policy.get("scope", []):
        match_scope = True
    for scope in policy.get("scope", []):
        if re.match(scope, file_metadata_scope):
            match_scope = True
            break

    if not policy.get("datatype", []):
        match_datatype = True
    for datatype in policy.get("datatype", []):
        if re.match(datatype, file_metadata_datatype):
            match_datatype = True
            break

    if match_scope and match_datatype:
        action = policy["action"]

    return action


def declare_suspicious_replicas_bad(once: bool = False, younger_than: int = 5, nattempts: int = 5, vos: Optional[list[str]] = None, limit_suspicious_files_on_rse: int = 5, json_file_name: str = "/opt/rucio/etc/suspicious_replica_recoverer.json", sleep_time: int = 3600, active_mode: bool = False) -> None:
    """
    Main loop to check for available replicas which are labeled as suspicious.

    Gets a list of suspicious replicas that are listed as AVAILABLE in 'replicas' table
    and available on other RSE. Finds surls of these replicas and declares them as bad.
    Replicas that are the last remaining copy of a file have additional checks (checksum
    comparison, etc.) before being declared bad.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param younger_than: The number of days since which bad_replicas table will be searched
                         for finding replicas declared 'SUSPICIOUS' at a specific RSE ('rse_expression'),
                         but 'AVAILABLE' on other RSE(s).
    :param nattempts: The minimum number of appearances in the bad_replica DB table
                      in order to appear in the resulting list of replicas for recovery.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If empty, we either use all VOs if run from "def",
    :param limit_suspicious_files_on_rse: Maximum number of suspicious replicas on an RSE before that RSE
                                          is considered problematic and the suspicious replicas on that RSE
                                          are labeled as 'TEMPORARY_UNAVAILABLE'.
    :param sleep_time: The daemon should not run too often. If the daemon's runtime is quicker than sleep_time, then
                       it should sleep until sleep_time is over.
    :returns: None
    """

    run_daemon(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            younger_than=younger_than,
            nattempts=nattempts,
            vos=vos,
            limit_suspicious_files_on_rse=limit_suspicious_files_on_rse,
            json_file_name=json_file_name,
            active_mode=active_mode
        ),
    )


def run_once(heartbeat_handler: Any, younger_than: int, nattempts: int, vos: Optional[list[str]], limit_suspicious_files_on_rse: int, json_file_name: str, active_mode: int, **_kwargs) -> bool:

    worker_number, total_workers, logger = heartbeat_handler.live()

    vos = vos or []

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logger(logging.WARNING, 'Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logger(logging.INFO, 'This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    start = time.time()

    try:
        json_file = open(json_file_name, mode="r")
        logger(logging.INFO, "JSON file has been opened.")
    except:
        logger(logging.WARNING, "An error occured while trying to open the JSON file.")
        must_sleep = True
        return must_sleep

    try:
        json_data = json.load(json_file)
    except ValueError as e:
        logger(logging.WARNING, "No JSON object could be decoded. Error: %s", e)
        return True

    # Checking that the json file is formatedd properly.
    for i, entry in enumerate(json_data):
        if ("datatype" not in entry or "scope" not in entry or "action" not in entry):
            logger(logging.ERROR, 'Entry %s in the json file is incomplete (missing either "datatype" or "action").', i)
            break

    logger(logging.INFO, 'Ready to query replicas that were reported as suspicious in the last %s days at least %s times.', younger_than, nattempts)

    getfileskwargs = {'younger_than': younger_than,
                      'nattempts': nattempts,
                      'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                      'is_suspicious': True}
    getfileskwargs_nattempts_1 = {'younger_than': younger_than,
                                  'nattempts': 1,
                                  'nattempts_exact': True,
                                  'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                                  'is_suspicious': True}

    for vo in vos:
        logger(logging.INFO, 'Start replica recovery for VO: %s', vo)
        recoverable_replicas = {}
        if vo not in recoverable_replicas:
            recoverable_replicas[vo] = {}
        # Separate replicas that have only been declared suspicious once from the rest,
        # as they will be handled differently and shouldn't be considered when deciding
        # if an RSE is problematic (due to a high number of suspicious replicas)
        replicas_nattempts_1 = {}
        if vo not in replicas_nattempts_1:
            replicas_nattempts_1[vo] = {}

        rse_list = sorted([rse for rse in parse_expression('enable_suspicious_file_recovery=true') if rse['vo'] == vo], key=lambda k: k['rse'])

        logger(logging.DEBUG, "List of RSEs with enable_suspicious_file_recovery = True: (total: %i)", len(rse_list))
        for i in rse_list:
            logger(logging.DEBUG, '%s', i)

        for rse in rse_list:
            time_start_rse = time.time()
            rse_expr = rse['rse']
            cnt_surl_not_found = 0
            cnt_surl_not_found_nattempts_1 = 0
            if rse_expr not in recoverable_replicas[vo]:
                recoverable_replicas[vo][rse_expr] = {}
            if rse_expr not in replicas_nattempts_1[vo]:
                replicas_nattempts_1[vo][rse_expr] = {}
            # Get a dictionary of the suspicious replicas on the RSE that have available copies on other RSEs
            suspicious_replicas_avail_elsewhere = get_suspicious_files(rse_expr, available_elsewhere=SuspiciousAvailability["EXIST_COPIES"].value, filter_={'vo': vo}, **getfileskwargs)
            # Get the suspicious replicas that are the last remaining copies
            suspicious_replicas_last_copy = get_suspicious_files(rse_expr, available_elsewhere=SuspiciousAvailability["LAST_COPY"].value, filter_={'vo': vo}, **getfileskwargs)
            # Get the suspicious replicas that have only been declared once
            suspicious_replicas_nattempts_1 = get_suspicious_files(rse_expr, available_elsewhere=SuspiciousAvailability["ALL"].value, filter_={'vo': vo}, **getfileskwargs_nattempts_1)

            logger(logging.DEBUG, 'Suspicious replicas on %s:', rse_expr)
            logger(logging.DEBUG, 'Replicas with copies on other RSEs (%s):', len(suspicious_replicas_avail_elsewhere))
            for i in suspicious_replicas_avail_elsewhere:
                logger(logging.DEBUG, '%s', i)
            logger(logging.DEBUG, 'Replicas that are the last remaining copy (%s):', len(suspicious_replicas_last_copy))
            for i in suspicious_replicas_last_copy:
                logger(logging.DEBUG, '%s', i)
            logger(logging.DEBUG, 'Replicas that have only been declared once (%s):', len(suspicious_replicas_nattempts_1))
            for i in suspicious_replicas_nattempts_1:
                logger(logging.DEBUG, '%s', i)

            # RSEs that aren't available shouldn't have suspicious replicas showing up. Skip to next RSE.
            if not rse['availability_read'] and ((len(suspicious_replicas_avail_elsewhere) > 0) or (len(suspicious_replicas_last_copy) > 0)):
                logger(logging.WARNING, "%s is not available (availability: %s), yet it has suspicious replicas. Please investigate. \n", rse_expr, rse['availability_read'])
                continue

            if suspicious_replicas_avail_elsewhere:
                for replica in suspicious_replicas_avail_elsewhere:
                    if vo == replica['scope'].vo:
                        scope = replica['scope']
                        rep_name = replica['name']
                        rse_id = replica['rse_id']
                        surl_not_found = True
                        for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                            for rse_ in rep['rses']:
                                if rse_ == rse_id:
                                    recoverable_replicas[vo][rse_expr][rep_name] = {'name': rep_name, 'rse_id': rse_id, 'scope': scope, 'surl': rep['rses'][rse_][0], 'available_elsewhere': True}
                                    surl_not_found = False

                        if surl_not_found:
                            cnt_surl_not_found += 1
                            logger(logging.WARNING, 'Skipping suspicious replica %s on %s, no surls were found.', rep_name, rse_expr)

            if suspicious_replicas_last_copy:
                for replica in suspicious_replicas_last_copy:
                    if vo == replica['scope'].vo:
                        scope = replica['scope']
                        rep_name = replica['name']
                        rse_id = replica['rse_id']
                        surl_not_found = True
                        # Should only return one rse, as there is only one replica remaining
                        for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                            recoverable_replicas[vo][rse_expr][rep_name] = {'name': rep_name, 'rse_id': rse_id, 'scope': scope, 'surl': rep['rses'][rse_id][0], 'available_elsewhere': False}
                            surl_not_found = False
                        if surl_not_found:
                            cnt_surl_not_found += 1
                            logger(logging.WARNING, 'Skipping suspicious replica %s on %s, no surls were found.', rep_name, rse_expr)

            if suspicious_replicas_nattempts_1:
                for replica in suspicious_replicas_nattempts_1:
                    if vo == replica['scope'].vo:
                        scope = replica['scope']
                        rep_name = replica['name']
                        rse_id = replica['rse_id']
                        surl_not_found = True
                        for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                            for rse_ in rep['rses']:
                                if rse_ == rse_id:
                                    replicas_nattempts_1[vo][rse_expr][rep_name] = {'name': rep_name, 'rse_id': rse_id, 'scope': scope, 'surl': rep['rses'][rse_][0], 'available_elsewhere': True}
                                    surl_not_found = False
                        if surl_not_found:
                            cnt_surl_not_found_nattempts_1 += 1
                            logger(logging.WARNING, 'Skipping suspicious replica %s on %s, no surls were found.', rep_name, rse_expr)

            logger(logging.INFO, 'Suspicious replica query took %s seconds on %s and found %i suspicious replica(s) with a minimum of nattempts=%i. The pfns for %s/%s replicas were found.',
                   time.time() - time_start_rse,
                   rse_expr,
                   len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy),
                   nattempts,
                   len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy) - cnt_surl_not_found,
                   len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy))

            logger(logging.INFO, 'A total of %i replicas with exactly nattempts=1 were found. The pfns for %s/%s replicas were found.',
                   len(suspicious_replicas_nattempts_1),
                   len(suspicious_replicas_nattempts_1) - cnt_surl_not_found_nattempts_1,
                   len(suspicious_replicas_nattempts_1))

            if len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy) != 0:
                logger(logging.DEBUG, 'List of replicas on %s for which the pfns have been found:', rse_expr)
                for i in recoverable_replicas[vo][rse_expr]:
                    logger(logging.DEBUG, '%s', i)

            if len(suspicious_replicas_nattempts_1) != 0:
                logger(logging.DEBUG, 'List of replicas on %s with nattempts=1 for which the pfns have been found:', rse_expr)
                for i in replicas_nattempts_1[vo][rse_expr]:
                    logger(logging.DEBUG, '%s', i)

        logger(logging.INFO, 'All RSEs have been checked for suspicious replicas. Total time: %s seconds.', time.time() - start)

        # Checking that everything is still working properly
        worker_number, total_workers, logger = heartbeat_handler.live()

        logger(logging.INFO, 'Create rules for replicas with nattempts=1.')

        # Create as many rules as necessary for the replicas to be picked up by the daemon on the next run
        # Create rules only for replicas that can be declared bad.
        # Replicas from the auditor should be declared bad regardless of suspicious declarations, so no rules necessary.
        for rse_key in list(replicas_nattempts_1[vo].keys()):
            if not replicas_nattempts_1[vo][rse_key]:
                # This is needed for testing purposes.
                continue
            files_to_be_declared_bad_nattempts_1 = []
            dids_nattempts_1 = []
            # Get the rse_id by going to one of the suspicious replicas from that RSE and reading it from there
            rse_id = list(replicas_nattempts_1[vo][rse_key].values())[0]['rse_id']
            for replica_key in replicas_nattempts_1[vo][rse_key].keys():
                from_auditor = False
                file_scope = replicas_nattempts_1[vo][rse_key][replica_key]["scope"]
                file_name = replicas_nattempts_1[vo][rse_key][replica_key]["name"]
                file_metadata = get_metadata(file_scope, file_name)
                replicas_nattempts_1[vo][rse_key][replica_key]["datatype"] = str(file_metadata["datatype"])

                # Auditor
                suspicious_reason = get_suspicious_reason(replicas_nattempts_1[vo][rse_key][replica_key]["rse_id"], file_scope, file_name, nattempts)
                for reason in suspicious_reason:
                    if "auditor" in reason["reason"].lower():
                        from_auditor = True
                        files_to_be_declared_bad_nattempts_1.append(recoverable_replicas[vo][rse_key][replica_key])
                        break

                # Bad
                if not from_auditor:
                    if (file_name.startswith("log.")) or (file_name.startswith("user")):
                        # Don't keep log files or user files
                        files_to_be_declared_bad_nattempts_1.append(recoverable_replicas[vo][rse_key][replica_key])
                        action = ""
                    else:
                        # Deal with replicas based on their metadata.
                        if file_metadata["datatype"] is None:  # "None" type has no function "split()"
                            logger(logging.WARNING, "RSE: %s, replica name %s, surl %s: Replica does not have a data type associated with it. No action will be taken.",
                                   rse_key, replica_key, replicas_nattempts_1[vo][rse_key][replica_key]['surl'])
                            continue
                        file_metadata_datatype = str(file_metadata["datatype"])
                        file_metadata_scope = str(file_metadata["scope"])
                        action = ""
                        if file_metadata_datatype:
                            # Some files don't have a datatype. They should be ignored.
                            for policy in json_data:
                                action = check_suspicious_policy(policy=policy, file_metadata_datatype=file_metadata_datatype, file_metadata_scope=file_metadata_scope)
                                if action:
                                    logger(logging.INFO, "The action that will be performed is %s", action)
                                    break
                    if action:
                        # Rules will be created for these replicas.
                        dids = {'scope': file_scope, 'name': file_name, 'rse': rse_key}
                        dids_nattempts_1.append(dids)
            if active_mode:
                if len(dids_nattempts_1) > 0:
                    add_rule(dids=dids_nattempts_1, account=InternalAccount('root', vo=vo), copies=nattempts, rse_expression='type=SCRATCHDISK', grouping=None, weight=None, lifetime=5 * 24 * 3600, locked=False, subscription_id=None)
                    logger(logging.INFO, 'Rules have been created for %i replicas on %s.', len(dids_nattempts_1), rse_key)
                else:
                    logger(logging.INFO, 'No rules have been created for replicas on %s.', rse_key)
                if len(files_to_be_declared_bad_nattempts_1) > 0:
                    logger(logging.INFO, 'Ready to declare %s bad replica(s) with nattempts=1 on %s (RSE id: %s).', len(files_to_be_declared_bad_nattempts_1), rse_key, str(rse_id))
                    declare_bad_file_replicas(replicas=files_to_be_declared_bad_nattempts_1, reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), session=None)
                else:
                    logger(logging.INFO, 'No suspicious replica(s) with nattempts=1 on %s (RSE id: %s) have been declared bad.', rse_key, str(rse_id))
            else:
                logger(logging.INFO, 'No replicas on %s with nattempts=1.', rse_key)

        logger(logging.INFO, 'Begin check for problematic RSEs.')
        time_start_check_probl = time.time()

        # If an RSE has more than *limit_suspicious_files_on_rse* suspicious files, then there might be a problem with the RSE.
        # The suspicious files are marked as temporarily unavailable.
        list_problematic_rses = []
        for rse_key in list(recoverable_replicas[vo].keys()):
            if len(recoverable_replicas[vo][rse_key].values()) > limit_suspicious_files_on_rse:
                list_problematic_rses.append(rse_key)
                surls_list = []
                for replica_value in recoverable_replicas[vo][rse_key].values():
                    surls_list.append(replica_value['surl'])

                if active_mode:
                    add_bad_pfns(pfns=surls_list, account=InternalAccount('root', vo=vo), state='TEMPORARY_UNAVAILABLE', expires_at=datetime.utcnow() + timedelta(days=3))

                logger(logging.INFO, "%s is problematic (more than %s suspicious replicas). Send a Jira ticket for the RSE (to be implemented).", rse_key, limit_suspicious_files_on_rse)
                logger(logging.INFO, "The following files on %s have been marked as TEMPORARILY UNAVAILABLE:", rse_key)
                for replica_values in recoverable_replicas[vo][rse_key].values():
                    logger(logging.INFO, 'Temporarily unavailable: RSE: %s    Scope: %s    Name: %s    PFN: %s', rse_key, replica_values['scope'], replica_values['name'], replica_values['surl'])
                # Remove the RSE from the dictionary as it has been dealt with.
                del recoverable_replicas[vo][rse_key]

        logger(logging.INFO, "Following RSEs were deemed problematic (total: %s)", len(list_problematic_rses))
        for rse in list_problematic_rses:
            logger(logging.INFO, "%s", rse)

        # Checking that everything is still working properly
        worker_number, total_workers, logger = heartbeat_handler.live()

        auditor = 0
        checksum = 0

        # Label suspicious replicas as bad if they have oher copies on other RSEs (that aren't also marked as suspicious).
        # If they are the last remaining copies, deal with them differently.
        for rse_key in list(recoverable_replicas[vo].keys()):
            files_to_be_declared_bad = []
            files_to_be_ignored = []
            files_dry_run_monitoring = []
            # Remove RSEs from dictionary that don't have any suspicious replicas
            if len(recoverable_replicas[vo][rse_key]) == 0:
                del recoverable_replicas[vo][rse_key]
                continue
            # Get the rse_id by going to one of the suspicious replicas from that RSE and reading it from there
            rse_id = list(recoverable_replicas[vo][rse_key].values())[0]['rse_id']
            for replica_key in list(recoverable_replicas[vo][rse_key].keys()):
                from_auditor = False
                file_scope = recoverable_replicas[vo][rse_key][replica_key]["scope"]
                file_name = recoverable_replicas[vo][rse_key][replica_key]["name"]
                file_metadata = get_metadata(file_scope, file_name)
                recoverable_replicas[vo][rse_key][replica_key]["datatype"] = str(file_metadata["datatype"])

                suspicious_reason = get_suspicious_reason(recoverable_replicas[vo][rse_key][replica_key]["rse_id"],
                                                          file_scope,
                                                          file_name,
                                                          nattempts)
                for reason in suspicious_reason:
                    if "auditor" in reason["reason"].lower():
                        auditor += 1
                        files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key])
                        from_auditor = True
                        break

                if not from_auditor:
                    if recoverable_replicas[vo][rse_key][replica_key]['available_elsewhere'] is True:
                        # Replicas with other copies on at least one other RSE can safely be labeled as bad
                        files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key])
                        # Remove replica from dictionary
                        del recoverable_replicas[vo][rse_key][replica_key]
                    elif recoverable_replicas[vo][rse_key][replica_key]['available_elsewhere'] is False:
                        if (file_name.startswith("log.")) or (file_name.startswith("user")):
                            # Don't keep log files or user files
                            files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key])
                            del recoverable_replicas[vo][rse_key][replica_key]
                        else:
                            # Deal with replicas based on their metadata.
                            if file_metadata["datatype"] is None:  # "None" type has no function "split()"
                                files_to_be_ignored.append(recoverable_replicas[vo][rse_key][replica_key])
                                logger(logging.WARNING, "RSE: %s, replica name %s, surl %s: Replica does not have a data type associated with it. No action will be taken.",
                                       rse_key, replica_key, recoverable_replicas[vo][rse_key][replica_key]['surl'])
                                continue

                            file_metadata_datatype = str(file_metadata["datatype"])
                            file_metadata_scope = str(file_metadata["scope"])
                            action = ""
                            if file_metadata_datatype:
                                # Some files don't have a datatype. They should be ignored.
                                for policy in json_data:
                                    action = check_suspicious_policy(policy=policy, file_metadata_datatype=file_metadata_datatype, file_metadata_scope=file_metadata_scope)
                                    if action:
                                        logger(logging.INFO, "The action that will be performed is %s", action)
                                        break

                            if not action:
                                logger(logging.WARNING, "No recognised actions (ignore/declare bad) found in policy file (etc/suspicious_replica_recoverer.json). Replica will be ignored by default.")

                            if action:
                                if action == "dry run":
                                    # Monitoring purposes: Will look like a file has been declared bad, even though no
                                    # actions will be taken.
                                    files_dry_run_monitoring.append(recoverable_replicas[vo][rse_key][replica_key])
                                elif action == "ignore":
                                    files_to_be_ignored.append(recoverable_replicas[vo][rse_key][replica_key])
                                elif action == "declare bad":
                                    suspicious_reason = get_suspicious_reason(recoverable_replicas[vo][rse_key][replica_key]["rse_id"],
                                                                              file_scope,
                                                                              file_name,
                                                                              nattempts)
                                    for reason in suspicious_reason:
                                        if "checksum" in reason["reason"].lower():
                                            checksum += 1
                                            files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key])
                                            break
                            else:
                                # If no policy has been set, default to ignoring the file (no action taken).
                                files_to_be_ignored.append(recoverable_replicas[vo][rse_key][replica_key])

            logger(logging.INFO, '(%s) Remaining replicas (pfns) that will be ignored:', rse_key)
            for i in files_to_be_ignored:
                logger(logging.INFO, 'Ignore: RSE: %s    Scope: %s    Name: %s    Datatype: %s    PFN: %s', rse_key, i["scope"], i["name"], i["datatype"], i["surl"])
            logger(logging.INFO, '(%s) Remaining replica (pfns) that will be declared BAD:', rse_key)
            for i in files_to_be_declared_bad:
                logger(logging.INFO, 'Declare bad: RSE: %s    Scope: %s    Name: %s    Datatype: %s    PFN: %s', rse_key, i["scope"], i["name"], i["datatype"], i["surl"])
            for i in files_dry_run_monitoring:
                logger(logging.INFO, 'Declare bad (dry run): RSE: %s    Scope: %s    Name: %s    Datatype: %s    PFN: %s', rse_key, i["scope"], i["name"], i["datatype"], i["surl"])

            if files_to_be_declared_bad:
                logger(logging.INFO, 'Ready to declare %s bad replica(s) on %s (RSE id: %s).', len(files_to_be_declared_bad), rse_key, str(rse_id))
                logger(logging.INFO, 'Number of replicas with checksum problems: %i', checksum)
                logger(logging.INFO, 'Number of replicas that were declared suspicious by the auditor: %i', auditor)

                if active_mode:
                    declare_bad_file_replicas(replicas=files_to_be_declared_bad, reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), session=None)

                logger(logging.INFO, 'Finished declaring bad replicas on %s.\n', rse_key)
            else:
                logger(logging.INFO, 'No files were declared bad on %s.\n', rse_key)

        logger(logging.INFO, 'Finished checking for problematic RSEs and declaring bad replicas on VO "%s". Total time: %s seconds.', vo, time.time() - time_start_check_probl)

        time_passed = time.time() - start
        logger(logging.INFO, 'Total time for VO "%s": %s seconds', vo, time_passed)

    time_passed = time.time() - start
    logger(logging.INFO, 'Total time: %s seconds', time_passed)
    must_sleep = True
    return must_sleep


def run(once: bool = False, younger_than: int = 5, nattempts: int = 5, vos: list[str] = None, limit_suspicious_files_on_rse: int = 5, json_file_name: str = "/opt/rucio/etc/suspicious_replica_recoverer.json", sleep_time: int = 3600, active_mode: bool = False) -> None:
    """
    Starts up the Suspicious-Replica-Recoverer threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if isinstance(db_time, datetime):
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Suspicious-Replica-Recoverer.')
            return

    logging.info('Suspicious file replicas recovery starting 1 worker.')
    t = threading.Thread(target=declare_suspicious_replicas_bad,
                         kwargs={'once': once,
                                 'younger_than': younger_than,
                                 'nattempts': nattempts,
                                 'vos': vos,
                                 'limit_suspicious_files_on_rse': limit_suspicious_files_on_rse,
                                 'json_file_name': json_file_name,
                                 'sleep_time': sleep_time,
                                 'active_mode': active_mode})
    t.start()
    logging.info('Waiting for interrupts')

    # Interruptible joins require a timeout.
    while t.is_alive():
        t.join(timeout=3.14)


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
