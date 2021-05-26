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

import json
import os
from rucio.common.utils import generate_uuid
from rucio.tests.common import file_generator
from rucio.core.rse import add_protocol, add_rse_attribute


def test_multiple_protocols_same_scheme(rse_factory, did_factory, mock_scope, tmp_path):
    """ Upload (CLIENT): Ensure domain correctly selected when multiple protocols exist with the same scheme """

    rse, rse_id = rse_factory.make_rse()

    # Ensure client site and rse site are identical. So that "lan" is preferred.
    add_rse_attribute(rse_id, 'site', 'ROAMING')

    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': 'file-wan.aperture.com',
                          'port': 0,
                          'prefix': '/prefix1/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 0, 'write': 0, 'delete': 0},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': 'file-lan.aperture.com',
                          'port': 0,
                          'prefix': '/prefix2/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 0, 'write': 0, 'delete': 0}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': 'root.aperture.com',
                          'port': 1403,
                          'prefix': '/prefix3/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 2, 'write': 2, 'delete': 2},
                              'wan': {'read': 2, 'write': 2, 'delete': 2}}})

    # Upload a file
    path = file_generator()
    name = os.path.basename(path)
    item = {
        'path': path,
        'rse': rse,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid(),
    }
    summary_path = tmp_path / 'summary'
    did_factory.upload_client.upload([item], summary_file_path=summary_path)

    # Verify that the lan protocol was used for the upload
    with open(summary_path) as json_file:
        data = json.load(json_file)
        assert 'file-lan.aperture.com' in data['{}:{}'.format(mock_scope, name)]['pfn']
