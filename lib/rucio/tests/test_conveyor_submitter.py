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

from rucio.core import distance as distance_core
from rucio.core import request as request_core
from rucio.core import rule as rule_core
from rucio.daemons.conveyor.submitter import submitter
from rucio.db.sqla.constants import RequestState


def test_request_submitted(rse_factory, file_factory, root_account):
    """ Conveyor (DAEMON): Test the submitter"""
    src_rse_name, src_rse_id = rse_factory.make_posix_rse()
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    distance_core.add_distance(src_rse_id=src_rse_id, dest_rse_id=dst_rse_id, ranking=10)
    distance_core.add_distance(src_rse_id=dst_rse_id, dest_rse_id=src_rse_id, ranking=10)
    did = file_factory.upload_test_file(rse_name=src_rse_name)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.QUEUED

    # run submitter with a RSE filter which doesn't contain the needed one
    submitter(once=True, rses=[{'id': src_rse_id}], mock=True, transfertool='mock', transfertype='bulk', filter_transfertool=None, bulk=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.QUEUED

    submitter(once=True, rses=[{'id': dst_rse_id}], mock=True, transfertool='mock', transfertype='bulk', filter_transfertool=None, bulk=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.SUBMITTED
