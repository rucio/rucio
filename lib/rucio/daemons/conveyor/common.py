# -*- coding: utf-8 -*-
# Copyright 2014-2022 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2020
# - Wen Guan <wen.guan@cern.ch>, 2014-2016
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2021
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Eric Vaandering <ewv@fnal.gov>, 2018-2020
# - dciangot <diego.ciangottini@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Matt Snyder <msnyder@bnl.gov>, 2019
# - Gabriele Fronze' <gfronze@cern.ch>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022
# - Nick Smith <nick.smith@cern.ch>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021

"""
Methods common to different conveyor submitter daemons.
"""

from __future__ import division

import datetime
import logging
import os
import socket
import threading
import time

from rucio.common.config import config_get
from rucio.common.exception import (InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound,
                                    DuplicateFileTransferSubmission, VONotFound)
from rucio.common.logging import formatted_logger
from rucio.common.utils import PriorityQueue
from rucio.core import heartbeat, request, transfer as transfer_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.request import set_request_state
from rucio.core.rse import list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.constants import RequestState
from rucio.rse import rsemanager as rsemgr


class HeartbeatHandler:
    """
    Simple contextmanager which sets a heartbeat and associated logger on entry and cleans up the heartbeat on exit.
    """

    def __init__(self, executable, logger_prefix=None):
        self.executable = executable
        self.logger_prefix = logger_prefix or executable

        self.hostname = socket.getfqdn()
        self.pid = os.getpid()
        self.hb_thread = threading.current_thread()

        self.logger = None
        self.last_heart_beat = None

    def __enter__(self):
        heartbeat.sanity_check(executable=self.executable, hostname=self.hostname)
        self.live()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.last_heart_beat:
            heartbeat.die(self.executable, self.hostname, self.pid, self.hb_thread)
            if self.logger:
                self.logger(logging.INFO, 'Heartbeat cleaned up')

    def live(self, older_than=None):
        if older_than:
            self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread, older_than=older_than)
        else:
            self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread)

        prefix = '%s[%i/%i]: ' % (self.logger_prefix, self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'])
        self.logger = formatted_logger(logging.log, prefix + '%s')

        if not self.last_heart_beat:
            self.logger(logging.DEBUG, 'First heartbeat set')
        else:
            self.logger(logging.DEBUG, 'Heartbeat renewed')

        return self.last_heart_beat, self.logger


def run_conveyor_daemon(once, graceful_stop, executable, logger_prefix, partition_wait_time, sleep_time, run_once_fnc, activities=None, heart_beat_older_than=None):

    with HeartbeatHandler(executable=executable, logger_prefix=logger_prefix) as heartbeat_handler:
        logger = heartbeat_handler.logger
        logger(logging.INFO, 'started')

        if partition_wait_time:
            graceful_stop.wait(partition_wait_time)

        activity_next_exe_time = PriorityQueue()
        for activity in activities or [None]:
            activity_next_exe_time[activity] = time.time()

        while not graceful_stop.is_set() and activity_next_exe_time:
            if once:
                activity = activity_next_exe_time.pop()
                time_to_sleep = 0
            else:
                activity = activity_next_exe_time.top()
                time_to_sleep = activity_next_exe_time[activity] - time.time()

            if time_to_sleep > 0:
                if activity:
                    logger(logging.DEBUG, 'Switching to activity %s and sleeping %s seconds', activity, time_to_sleep)
                else:
                    logger(logging.DEBUG, 'Sleeping %s seconds', time_to_sleep)
                graceful_stop.wait(time_to_sleep)
            else:
                if activity:
                    logger(logging.DEBUG, 'Switching to activity %s', activity)
                else:
                    logger(logging.DEBUG, 'Starting next iteration')

            heart_beat, logger = heartbeat_handler.live(older_than=heart_beat_older_than)

            must_sleep = True
            try:
                must_sleep = run_once_fnc(activity=activity, total_workers=heart_beat['nr_threads'], worker_number=heart_beat['assign_thread'], logger=logger)
            except Exception:
                logger(logging.CRITICAL, "Exception", exc_info=True)
                if once:
                    raise

            if not once:
                if must_sleep:
                    activity_next_exe_time[activity] = time.time() + sleep_time
                else:
                    activity_next_exe_time[activity] = time.time() + 1


def submit_transfer(transfertool_obj, transfers, job_params, submitter='submitter', timeout=None, logger=logging.log):
    """
    Submit a transfer or staging request

    :param transfertool_obj:      The transfertool object to be used for submission
    :param transfers:             Transfer objects to be submitted
    :param job_params:            Parameters to be used for all transfers in the given job.
    :param submitter:             Name of the submitting entity.
    :param timeout:               Timeout
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    """

    for transfer in transfers:
        try:
            transfer_core.mark_submitting_and_prepare_sources_for_transfer(transfer, external_host=transfertool_obj.external_host, logger=logger)
        except RequestNotFound as error:
            logger(logging.ERROR, str(error))
            return
        except Exception:
            logger(logging.ERROR, 'Failed to prepare requests %s state to SUBMITTING. Mark it SUBMISSION_FAILED and abort submission.' % [str(t.rws) for t in transfers], exc_info=True)
            set_request_state(request_id=transfer.rws.request_id, new_state=RequestState.SUBMISSION_FAILED)
            return

    try:
        _submit_transfers(transfertool_obj, transfers, job_params, submitter, timeout, logger)
    except DuplicateFileTransferSubmission as error:
        logger(logging.WARNING, 'Failed to bulk submit a job because of duplicate file : %s', str(error))
        logger(logging.INFO, 'Submitting files one by one')
        for transfer in transfers:
            _submit_transfers(transfertool_obj, [transfer], job_params, submitter, timeout, logger)


def _submit_transfers(transfertool_obj, transfers, job_params, submitter='submitter', timeout=None, logger=logging.log):
    """
    helper function for submit_transfers. Performs the actual submission of one or more transfers.

    If the bulk submission of multiple transfers fails due to duplicate submissions, the exception
    is propagated to the caller context, which is then responsible for calling this function again for each
    of the transfers separately.
    """
    logger(logging.INFO, 'About to submit job to %s with timeout %s' % (transfertool_obj, timeout))
    # A eid is returned if the job is properly submitted otherwise an exception is raised
    is_bulk = len(transfers) > 1
    eid = None
    start_time = time.time()
    state_to_set = RequestState.SUBMISSION_FAILED
    try:
        record_counter('core.request.submit_transfer')
        eid = transfertool_obj.submit(transfers, job_params, timeout)
        state_to_set = RequestState.SUBMITTED
    except DuplicateFileTransferSubmission:
        if is_bulk:
            raise
    except (TransferToolTimeout, TransferToolWrongAnswer) as error:
        logger(logging.ERROR, 'Failed to submit a job with error %s', str(error), exc_info=True)
    except Exception as error:
        logger(logging.ERROR, 'Failed to submit a job with error %s', str(error), exc_info=True)
        # Keep the behavior from before the refactoring: in case of unexpected exception, only
        # update request state on individual transfers, and do nothing for bulks.
        # Don't know why it's like that.
        #
        # FIXME: shouldn't we always set the state to SUBMISSION_FAILED?
        if is_bulk:
            state_to_set = None

    if eid is not None:
        duration = time.time() - start_time
        logger(logging.INFO, 'Submit job %s to %s in %s seconds' % (eid, transfertool_obj, duration))
        record_timer('daemons.conveyor.{submitter}.submit_bulk_transfer.per_file', (time.time() - start_time) * 1000 / len(transfers) or 1, labels={'submitter': submitter})
        record_counter('daemons.conveyor.{submitter}.submit_bulk_transfer', delta=len(transfers), labels={'submitter': submitter})
        record_timer('daemons.conveyor.{submitter}.submit_bulk_transfer.files', len(transfers), labels={'submitter': submitter})

    if state_to_set:
        try:
            transfer_core.set_transfers_state(transfers, state=state_to_set, external_host=transfertool_obj.external_host,
                                              external_id=eid, submitted_at=datetime.datetime.utcnow(), logger=logger)
        except Exception:
            logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
            if eid is not None:
                # The job is still submitted in the file transfer service but the request is not updated.
                # Possibility to have a double submission during the next cycle. Try to cancel the external request.
                try:
                    logger(logging.INFO, 'Cancel transfer %s on %s', eid, transfertool_obj)
                    request.cancel_request_external_id(transfertool_obj, eid)
                except Exception:
                    logger(logging.ERROR, 'Failed to cancel transfers %s on %s with error' % (eid, transfertool_obj), exc_info=True)


def get_conveyor_rses(rses=None, include_rses=None, exclude_rses=None, vos=None, logger=logging.log):
    """
    Get a list of rses for conveyor

    :param rses:          List of rses (Single-VO only)
    :param include_rses:  RSEs to include
    :param exclude_rses:  RSEs to exclude
    :param vos:           VOs on which to look for RSEs. Only used in multi-VO mode.
                          If None, we either use all VOs if run from "def", or the current VO otherwise.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    :return:              List of working rses
    """
    multi_vo = config_get('common', 'multi_vo', raise_exception=False, default=False)
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

    working_rses = []
    rses_list = []
    for vo in vos:
        rses_list.extend(list_rses(filters={'vo': vo}))
    if rses:
        working_rses = [rse for rse in rses_list if rse['rse'] in rses]

    if include_rses:
        for vo in vos:
            try:
                parsed_rses = parse_expression(include_rses, filter_={'vo': vo}, session=None)
            except InvalidRSEExpression:
                logger(logging.ERROR, "Invalid RSE exception %s to include RSEs", include_rses)
            else:
                for rse in parsed_rses:
                    if rse not in working_rses:
                        working_rses.append(rse)

    if not (rses or include_rses):
        working_rses = rses_list

    if exclude_rses:
        try:
            parsed_rses = parse_expression(exclude_rses, session=None)
        except InvalidRSEExpression as error:
            logger(logging.ERROR, "Invalid RSE exception %s to exclude RSEs: %s", exclude_rses, error)
        else:
            working_rses = [rse for rse in working_rses if rse not in parsed_rses]

    working_rses = [rsemgr.get_rse_info(rse_id=rse['id']) for rse in working_rses]
    return working_rses
