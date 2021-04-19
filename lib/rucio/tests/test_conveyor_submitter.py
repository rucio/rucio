# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
# - Radu Carpa <radu.carpa@cern.ch>, 2021

import itertools
from datetime import datetime, timedelta
from random import randint
from unittest.mock import patch

from rucio.core import distance as distance_core
from rucio.core import request as request_core
from rucio.core import rule as rule_core
from rucio.daemons.conveyor.submitter import submitter
from rucio.db.sqla.models import Request
from rucio.db.sqla.constants import RequestState
from rucio.db.sqla.session import transactional_session


def test_request_submitted_in_order(rse_factory, file_factory, root_account):

    src_rses = [rse_factory.make_posix_rse() for _ in range(2)]
    dst_rses = [rse_factory.make_posix_rse() for _ in range(3)]
    for _, src_rse_id in src_rses:
        for _, dst_rse_id in dst_rses:
            distance_core.add_distance(src_rse_id=src_rse_id, dest_rse_id=dst_rse_id, ranking=10)
            distance_core.add_distance(src_rse_id=dst_rse_id, dest_rse_id=src_rse_id, ranking=10)

    # Create a certain number of files on source RSEs with replication rules towards random destination RSEs
    nb_files = 15
    dids = []
    requests = []
    src_rses_iterator = itertools.cycle(src_rses)
    dst_rses_iterator = itertools.cycle(dst_rses)
    for _ in range(nb_files):
        src_rse_name, src_rse_id = next(src_rses_iterator)
        dst_rse_name, dst_rse_id = next(dst_rses_iterator)
        did = file_factory.upload_test_file(rse_name=src_rse_name)
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        requests.append(request_core.get_request_by_did(rse_id=dst_rse_id, **did))
        dids.append(did)

    # Forge request creation time to a random moment in the past hour
    @transactional_session
    def _forge_requests_creation_time(session=None):
        base_time = datetime.utcnow().replace(microsecond=0, minute=0) - timedelta(hours=1)
        assigned_times = set()
        for request in requests:
            request_creation_time = None
            while not request_creation_time or request_creation_time in assigned_times:
                # Ensure uniqueness to avoid multiple valid submission orders and make tests deterministic with simple sorting techniques
                request_creation_time = base_time + timedelta(minutes=randint(0, 3600))
            assigned_times.add(request_creation_time)
            session.query(Request).filter(Request.id == request['id']).update({'created_at': request_creation_time})
            request['created_at'] = request_creation_time

    _forge_requests_creation_time()
    requests = sorted(requests, key=lambda r: r['created_at'])

    for request in requests:
        assert request_core.get_request(request_id=request['id'])['state'] == RequestState.QUEUED

    requests_id_in_submission_order = []
    with patch('rucio.transfertool.mock.MockTransfertool.submit') as mock_transfertool_submit:
        # Record the order of requests passed to MockTranfertool.submit()
        mock_transfertool_submit.side_effect = lambda jobs, _: requests_id_in_submission_order.extend([j['metadata']['request_id'] for j in jobs])

        submitter(once=True, rses=[{'id': rse_id} for _, rse_id in dst_rses], mock=True, transfertool='mock', transfertype='single', filter_transfertool=None)

    for request in requests:
        assert request_core.get_request(request_id=request['id'])['state'] == RequestState.SUBMITTED

    # Requests must be submitted in the order of their creation
    assert requests_id_in_submission_order == [r['id'] for r in requests]
