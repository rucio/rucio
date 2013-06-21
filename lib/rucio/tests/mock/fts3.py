# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import datetime
import random

from sqlalchemy import and_, or_

from rucio.common.utils import generate_uuid
from rucio.core.monitor import record_counter
from rucio.db import test_models
from rucio.db.constants import FTSState
from rucio.db.session import read_session, transactional_session

"""
This mock FTS3 server provides basic job control, with a random job progression model.
"""


@read_session
def list_all(session):
    """
    List all transfer jobs.

    :returns: List of dictionaries with job information
    """

    record_counter('daemons.mock.fts3.list_all')

    query = session.query(test_models.MockFTSTransfer).order_by(test_models.MockFTSTransfer.lastmodified.desc())
    for row in query.yield_per(5):
        yield row


@transactional_session
def submit(tinfo, session):
    """
    Create a new transfer job in state QUEUED.

    :param tinfo: The transfer job information as a string.
    :returns: The transfer job id.
    """

    record_counter('daemons.mock.fts3.submit')

    tid = generate_uuid()

    new_transfer = test_models.MockFTSTransfer(transfer_id=tid, transfer_metadata=str(tinfo))
    new_transfer.save(session=session)

    return {'job_id': tid}


@transactional_session
def query(tid, session):
    """
    Query the transfer job information of a single job. Has a chance to progress the job from QUEUED to either DONE or FAILED.

    :param tid: The transfer job id.
    :returns: The transfer job information.
    """

    record_counter('daemons.mock.fts3.query')

    new_state = random.sample(sum([[FTSState.FINISHED]*15, [FTSState.FAILED]*3, [FTSState.FINISHEDDIRTY]*2, [FTSState.ACTIVE]*80], []), 1)[0]

    query = session.query(test_models.MockFTSTransfer).filter(and_(test_models.MockFTSTransfer.transfer_id == tid,
                                                                   or_(test_models.MockFTSTransfer.state == FTSState.SUBMITTED,
                                                                       test_models.MockFTSTransfer.state == FTSState.ACTIVE)))
    query.update({'state': new_state,
                  'last_modified': datetime.datetime.utcnow()})

    r = {'job_state': str(new_state)}

    if new_state == FTSState.FAILED or new_state == FTSState.FINISHEDDIRTY:
        r['reason'] = 'Mock FTS decided to kill your transfer.'
        r['files'] = [{'source_surl': 'mock_src', 'dest_surl': 'mock_dest', 'reason': 'mock failure'}]

    return r


@transactional_session
def cancel(tid, session):
    """
    Kills a transfer by setting its state to CANCELLED.

    :param tid: The transfer job id.
    """

    record_counter('daemons.mock.fts3.cancel')

    query = session.query(test_models.MockFTSTransfer).filter(tid=tid)
    query.update({'state': FTSState.CANCELED,
                  'last_modified': datetime.datetime.utcnow()})
