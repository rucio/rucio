# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

"""
Suspicious-Replica-Recoverer is a daemon that declares suspicious replicas as bad if they are found available on other RSE.
Consequently, automatic replica recovery is triggered via necromancer daemon, which creates a rule for such bad replica(s).
"""

from __future__ import print_function

import logging
import os
import socket
import threading
import time
import traceback
from datetime import datetime, timedelta
from re import match
from sys import argv

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get_bool
from rucio.common.exception import DatabaseException, VONotFound, InvalidRSEExpression
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.replica import list_replicas, declare_bad_file_replicas, get_suspicious_files
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.constants import BadFilesStatus, ReplicaState
from rucio.db.sqla.util import get_db_time

from rucio.core.rse import list_rses

# # From example (sent by Cedric)
# import json
# import sys
# import requests
# import rucio.common.policy
# import rucio.core.did
# import rucio.core.rule
# from rucio.core.lifetime_exception import list_exceptions
# from rucio.db.sqla.constants import LifetimeExceptionsState
# from rucio.core.did import get_metadata
# from rucio.common.utils import sizefmt
# from rucio.common.exception import DataIdentifierNotFound


GRACEFUL_STOP = threading.Event()


def declare_suspicious_replicas_bad(once=False, younger_than=3, nattempts=10, rse_expression='MOCK', vos=None, max_replicas_per_rse=100):

    """
    Main loop to check for available replicas which are labeled as suspicious

    Gets a list of suspicious replicas that are listed as AVAILABLE in 'replicas' table
    and available on other RSE. Finds surls of these replicas and declares them as bad.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param younger_than: The number of days since which bad_replicas table will be searched
                         for finding replicas declared 'SUSPICIOUS' at a specific RSE ('rse_expression'),
                         but 'AVAILABLE' on other RSE(s).
    :param nattempts: The minimum number of appearances in the bad_replica DB table
                      in order to appear in the resulting list of replicas for recovery.
    :param rse_expression: Search for suspicious replicas on RSEs matching the 'rse_expression'.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If None, we either use all VOs if run from "def",
    :param max_replicas_per_rse: Maximum number of replicas which are allowed to be labeled as bad per RSE.
                                 If more is found, processing is skipped and warning is printed.
    :returns: None
    """

    # assembling the worker name identifier ('executable') including the rses from <rse_expression>
    # in order to have the possibility to detect a start of a second instance with the same set of RSES

    executable = argv[0]

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
        logging.info('replica_recoverer: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
    rses = []
    exceptions_raised = 0
    for vo in vos:
        try:
            parsed_rses = parse_expression(expression=rse_expression, filter={'vo': vo})
        except InvalidRSEExpression:
            exceptions_raised += 1
            parsed_rses = []
        for rse in parsed_rses:
            rses.append(rse['id'])
    if exceptions_raised == len(vos):
        raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

    rses.sort()
    executable += ' --rse-expression ' + str(rses)

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat - expected only one replica-recoverer thread on one node
    # heartbeat mechanism is used in this daemon only for information purposes
    # (due to expected low load, the actual DB query does not filter the result based on worker number)
    live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        try:
            # issuing the heartbeat for a second time to make all workers aware of each other (there is only 1 worker allowed for this daemon)
            heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
            total_workers = heartbeat['nr_threads']
            worker_number = heartbeat['assign_thread']

            # there is only 1 worker allowed for this daemon
            if total_workers != 1:
                logging.error('replica_recoverer: Another running instance on %s has been detected. Stopping gracefully.', socket.gethostname())
                die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
                break

            start = time.time()

            logging.info('replica_recoverer[%i/%i]: ready to query replicas at RSE %s,'
                         + ' reported suspicious in the last %i days at least %i times which are available on other RSEs.',  # NOQA: W503
                         worker_number, total_workers, rse_expression, younger_than, nattempts)

            getfileskwargs = {'younger_than': younger_than,
                              'nattempts': nattempts,
                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                              'available_elsewhere': True,
                              'is_suspicious': True}

            # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
            recoverable_replicas = []
            exceptions_raised = 0
            for vo in vos:
                try:
                    recoverable_replicas.extend(get_suspicious_files(rse_expression, filter={'vo': vo}, **getfileskwargs))
                except InvalidRSEExpression:
                    exceptions_raised += 1
            if exceptions_raised == len(vos):
                raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

            logging.info('replica_recoverer[%i/%i]: suspicious replica query took %.2f seconds, total of %i replicas were found.',
                         worker_number, total_workers, time.time() - start, len(recoverable_replicas))

            if not recoverable_replicas and not once:
                logging.info('replica_recoverer[%i/%i]: found %i recoverable suspicious replicas. Sleeping for 60 seconds.', worker_number, total_workers, len(recoverable_replicas))
                GRACEFUL_STOP.wait(60)
            else:
                logging.info('replica_recoverer[%i/%i]: looking for replica surls.', worker_number, total_workers)

                start = time.time()
                surls_to_recover = {}  # dictionary of { vo1: {rse1: [surl1, surl2, ... ], rse2: ...}, vo2:... }
                cnt_surl_not_found = 0
                for replica in recoverable_replicas:
                    scope = replica['scope']
                    name = replica['name']
                    vo = scope.vo
                    rse = replica['rse']
                    rse_id = replica['rse_id']
                    if GRACEFUL_STOP.is_set():
                        break
                    if vo not in surls_to_recover:
                        surls_to_recover[vo] = {}
                    if rse_id not in surls_to_recover[vo]:
                        surls_to_recover[vo][rse_id] = []
                    # for each suspicious replica, we get its surl through the list_replicas function
                    surl_not_found = True
                    for rep in list_replicas([{'scope': scope, 'name': name}]):
                        for site in rep['rses']:
                            if site == rse_id:
                                surls_to_recover[vo][rse_id].append(rep['rses'][site][0])
                                surl_not_found = False
                    if surl_not_found:
                        cnt_surl_not_found += 1
                        logging.warning('replica_recoverer[%i/%i]: skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, name, rse)

                logging.info('replica_recoverer[%i/%i]: found %i/%i surls (took %.2f seconds), declaring them as bad replicas now.',
                             worker_number, total_workers, len(recoverable_replicas) - cnt_surl_not_found, len(recoverable_replicas), time.time() - start)

                for vo in surls_to_recover:
                    for rse_id in surls_to_recover[vo]:
                        logging.info('replica_recoverer[%i/%i]: ready to declare %i bad replica(s) on %s: %s.',
                                     worker_number, total_workers, len(surls_to_recover[vo][rse_id]), rse, str(surls_to_recover[vo][rse_id]))
                        if len(surls_to_recover[vo][rse_id]) > max_replicas_per_rse:
                            logging.warning('replica_recoverer[%i/%i]: encountered more than %i suspicious replicas (%s) on %s. Please investigate.',
                                            worker_number, total_workers, max_replicas_per_rse, str(len(surls_to_recover[vo][rse_id])), rse)
                        else:
                            declare_bad_file_replicas(pfns=surls_to_recover[vo][rse_id], reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), status=BadFilesStatus.BAD, session=None)
                            logging.info('replica_recoverer[%i/%i]: finished declaring bad replicas on %s.', worker_number, total_workers, rse)

        except (DatabaseException, DatabaseError) as err:
            if match('.*QueuePool.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
            elif match('.*ORA-03135.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
        except Exception as err:
            logging.critical(traceback.format_exc())
            record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
        if once:
            break

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logging.info('replica_recoverer[%i/%i]: graceful stop done', worker_number, total_workers)





def recover_suspicious_replicas(vos, younger_than, nattempts):

    # key_project = 'ATLASCREM'
    # issuetype = 'Task'

    # sessionid = None
    # with open('cookiefile.txt', 'r') as f:
    #     for line in f:
    #         line = line.rstrip('\n')
    #         if line.find('JSESSIONID') > - 1:
    #             sessionid = line.split()[-1]
    #
    # if not sessionid:
    #     sys.exit()
    #
    # headers={'cookie': 'JSESSIONID=%s' % (sessionid), 'Content-Type': 'application/json'}

    getfileskwargs = {'younger_than': younger_than,
                        'nattempts': nattempts,
                        'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                        'is_suspicious': True}

    recoverable_replicas = {}
    # Goal: {vo1: {site1: {rse1: [surl1, surl2, ...], rse_2: [...], ...}, site2: {...}  },    vo2: {...}}
    # Each surl describes a replica
    for vo in vos:
        if vo not in recoverable_replicas:
            recoverable_replicas[vo]={}

        # Get list of RSEs
        rse_list = list_rses()
        # Get a list of all site expressions
        for rse in rse_list:
            site = rse.split('_')[0] # This assumes that the RSE expression has the strucutre site_X, e.g. LRZ-LMU_DATADISK
            if site not in recoverable_replicas[vo]:
                recoverable_replicas[vo][site] = {}
            if rse not in recoverable_replicas[vo][site]:
                recoverable_replicas[vo][site][rse] = []
            # recoverable_replicas should now look like this:
            # {vo1: {site1: {rse1: [], rse_2: [], ...}, site2: {...}  },    vo2: {...}}

            suspicious_replicas = get_suspicious_files(rse, filter={'vo': vo}, **getfileskwargs)

            # Not all RSEs have suspicious replicas on them. However, they should still be added to the list as makes it possibl to
            # check if a site has problems (by checking whether all the RSEs on it have a certain number of suspicious files).

            # Get the pfns/surls for all suspicious replicas on all RSEs of all sites. This is required to be able to mark them as TEMPORARY_UNAVAILABLE
            if suspicious_replicas:
                # If suspicious replicas isn't empty then there is at least one suspcicious replica on the RSE
                # cnt_surl_not_found = 0
                for replica in suspicious_replicas:
                    if vo == replica['scope'].vo:
                        scope = replica['scope']
                        name = replica['name']
                        # rse = replica['rse']
                        rse_id = replica['rse_id']

                        # if GRACEFUL_STOP.is_set():
                        #     break

                        # for each suspicious replica, we get its surl through the list_replicas function
                        surl_not_found = True
                        for rep in list_replicas([{'scope': scope, 'name': name}]):
                            for rse_ in rep['rses']:
                                if rse_ == rse_id: ###### What is he difference between rse and rse_id?
                                    # Add the surl to the list
                                    recoverable_replicas[vo][site][rse].append(rep['rses'][site][0])
                                    surl_not_found = False
                # if surl_not_found:
                    # cnt_surl_not_found += 1
                    # logging.warning('replica_recoverer[%i/%i]: skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, name, rse)



            # recoverable_replicas should now look like this: {vo1: {site1: {rse1: [surl1, surl2, ...], rse_2: [...], ...}, site2: {...}  },    vo2: {...}}
            # At this point in time there will be RSEs with empty lists, as they have no suspicious replicas



        down_sites = requests.get('https://atlas-cric.cern.ch/api/core/downtime/query/?json&preset=sites', headers=headers)
        for site in recoverable_replicas[vo].keys():
        # Deleting dictionary elements whilst iterating over the dict will cause an error
        # Workaround is to use keys() (apparently)

        # Check if a site is in the list of known unavailable sites. If it is, remove it from the dictionary (should probably also send some sort of logging warning, as
        # replicas on a site that is down during a scheduled time shouldn't be labeled as suspicious when there is an attempt to access them).
            if site in down_sites.json():
                del recoverable_replicas[vo][site]
            clean_rses = 0
            for rse in site:
                if len(rse) == 0: # If RSE has no suspicious replicas
                    clean_rses += 1
            # Remove sites where all RSEs have empty lists (these sites have no suspicious replicas)
            if len(site) == clean_rses:
                del recoverable_replicas[vo][site]

        # recoverable_replicas should now only have sites where at least one RSE has a suspicious replica

        # Set a limit to the total count of all suspicious replicas on an RSE combined. If this limit if exceeded on all RSEs of a site, then the site is considered
        # problematic, meaning the replicas are marked as TEMPORARY_UNAVAILABLE and a ticket is sent to the site managers.

        # If an RSE has more than limit_suspicious_files_on_rse suspicious files, it is marked as problematic
        limit_suspicious_files_on_rse = 5 # Filler value. Probably shouldn't be hard-coded.

        for site in recoverable_replicas[vo]:
            count_problematic_rse = 0 # Number of RSEs with a total count less than limit_suspicious_files_on_rse
            list_problematic_rse = [] # Dict with the RSEs as the keys and their total number of counts as the values
            for rse in site:
                if len(rse) > limit_suspicious_files_on_rse:
                    count_problematic_rse += 1
                    list_problematic_rse.append(rse.key())
            if len(site) == problematic_rse:
                # Site has a problem
                # Set all of the replicas on the site as TEMPORARY_UNAVAILABLE
                for rse in site:
                    add_bad_pfns(pfns=recoverable_replicas[vo][site][rse], account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE)
                print("All RSEs on site %s are problematic. Send a Jira ticket for the site." % site)

                # Send a ticket
                # tickets = requests.get('https://its.cern.ch/jira/projects/ALARMTESTING') # Url used for testing, not the final solution
                # list_tickets = []
                # for issue in tickets.json()['issues']: # Don't know if correct
                #     list_tickets.append(issue['fields']['summary'])
                # # Rough draft:
                # summary = 'All RSEs of the site %s have a high count of suspicious replicas.' %site
                # if summary not in list_tickets:
                #     # Send ticket (to whom?) (Is this even necessary? Wouldn't the site managers already know that the site is down?)
                #     text = 'There is possibly a problem with %s. TEXT HERE' %site
                #     text += 'RSE expression, number of suspicious replicas, combined number of attepts for all replicas:'
                #     for rse in rses_on_site:
                #         text += 'X, Y, Z'
                #     ##
                #     ## The following is copied from the example below, although it isn't clear what the structure of the request needs to be.
                #     data = {
                #         'fields':{
                #             "project":
                #             {
                #                 "key": key_project
                #             },
                #             "summary": summary,
                #             "description": text,
                #         }
                #     }
                #     result = requests.post('?', headers='?', data=json.dumps(data))



            # Only specific RSEs of a site have a problem. Check RSEs individually
            for rse in list_problematic_rse:
                if len(rse) > limit_suspicious_files_on_rse:
                    add_bad_pfns(pfns=recoverable_replicas[vo][site][rse], account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE)
                    print("RSE %s of site %s are problematic. Send a Jira ticket for the RSE." % (rse, site))

    return

















def run(once=False, younger_than=3, nattempts=10, rse_expression='MOCK', vos=None, max_replicas_per_rse=100):
    """
    Starts up the Suspicious-Replica-Recoverer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if isinstance(db_time, datetime):
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Suspicious-Replica-Recoverer.')
            return

    sanity_check(executable='rucio-replica-recoverer', hostname=socket.gethostname())

    if once:
        declare_suspicious_replicas_bad(once, younger_than, nattempts, rse_expression, vos, max_replicas_per_rse)
    else:
        logging.info('Suspicious file replicas recovery starting 1 worker.')
        t = threading.Thread(target=declare_suspicious_replicas_bad,
                             kwargs={'once': once, 'younger_than': younger_than,
                                     'nattempts': nattempts, 'rse_expression': rse_expression,
                                     'vos': vos, 'max_replicas_per_rse': max_replicas_per_rse})
        t.start()
        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while t.isAlive():
            t.join(timeout=3.14)


def stop():
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
