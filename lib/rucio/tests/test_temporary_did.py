# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2018
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019

from nose.tools import assert_equal

from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.temporary_did import (add_temporary_dids, compose, delete_temporary_dids,
                                      list_expired_temporary_dids)
from rucio.core.rse import get_rse_id

from rucio.client.didclient import DIDClient


def test_core_temporary_dids():
    """ TMP DATA IDENTIFIERS (CORE): """

    scope = InternalScope('mock')
    root = InternalAccount('root')
    temporary_dids = []
    rse = 'MOCK'
    rse_id = get_rse_id(rse=rse)
    for _ in range(10):
        temporary_dids.append({'scope': scope,
                               'name': 'object_%s' % generate_uuid(),
                               'rse_id': rse_id,
                               'bytes': 1,
                               'path': None})

    add_temporary_dids(dids=temporary_dids, account=root)

    compose(scope=scope, name='file_%s' % generate_uuid(), rse_id=rse_id,
            bytes=10, sources=temporary_dids, account=root,
            md5=None, adler32=None, pfn=None, meta={}, rules=[],
            parent_scope=None, parent_name=None)

    dids = list_expired_temporary_dids(rse_id=rse_id, limit=10)

    rowcount = delete_temporary_dids(dids=dids)

    assert_equal(rowcount, 10)


def test_client_temporary_dids():
    """ TMP DATA IDENTIFIERS (CLIENT): """
    client = DIDClient()
    temporary_dids = []
    for _ in range(10):
        temporary_dids.append({'scope': 'mock',
                               'name': 'object_%s' % generate_uuid(),
                               'rse': 'MOCK',
                               'bytes': 1,
                               'path': None})

    client.add_temporary_dids(dids=temporary_dids)
