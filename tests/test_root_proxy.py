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

from urllib.parse import urlencode

import pytest

from rucio.common.types import InternalAccount, InternalScope
from rucio.core.config import set as config_set
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, add_rse_attribute, del_rse, add_protocol
from rucio.tests.common import rse_name_generator, vohdr, headers

client_location_without_proxy = {'ip': '192.168.0.1',
                                 'fqdn': 'anomalous-materials.blackmesa.com',
                                 'site': 'BLACKMESA1'}

client_location_with_proxy = {'ip': '10.0.1.1',
                              'fqdn': 'test-chamber.aperture.com',
                              'site': 'APERTURE1'}


@pytest.fixture(scope='module', autouse=True)
def root_proxy_example_data(vo):
    rse_without_proxy = rse_name_generator()
    rse_without_proxy_id = add_rse(rse_without_proxy, vo=vo)
    add_rse_attribute(rse_id=rse_without_proxy_id,
                      key='site',
                      value='BLACKMESA1')

    rse_with_proxy = rse_name_generator()
    rse_with_proxy_id = add_rse(rse_with_proxy, vo=vo)
    add_rse_attribute(rse_id=rse_with_proxy_id,
                      key='site',
                      value='APERTURE1')

    # APERTURE1 site has an internal proxy
    config_set('root-proxy-internal', 'APERTURE1', 'proxy.aperture.com:1094')

    files = [{'scope': InternalScope('mock', vo=vo),
              'name': 'half-life_%s' % i,
              'bytes': 1234,
              'adler32': 'deadbeef',
              'meta': {'events': 666}} for i in range(1, 4)]
    for rse_id in [rse_with_proxy_id, rse_without_proxy_id]:
        add_replicas(rse_id=rse_id,
                     files=files,
                     account=InternalAccount('root', vo=vo),
                     ignore_availability=True)

    add_protocol(rse_without_proxy_id, {'scheme': 'root',
                                        'hostname': 'root.blackmesa.com',
                                        'port': 1409,
                                        'prefix': '//training/facility/',
                                        'impl': 'rucio.rse.protocols.xrootd.Default',
                                        'domains': {
                                            'lan': {'read': 1,
                                                    'write': 1,
                                                    'delete': 1},
                                            'wan': {'read': 1,
                                                    'write': 1,
                                                    'delete': 1}}})

    add_protocol(rse_with_proxy_id, {'scheme': 'root',
                                     'hostname': 'root.aperture.com',
                                     'port': 1409,
                                     'prefix': '//test/chamber/',
                                     'impl': 'rucio.rse.protocols.xrootd.Default',
                                     'domains': {
                                         'lan': {'read': 1,
                                                 'write': 1,
                                                 'delete': 1},
                                         'wan': {'read': 1,
                                                 'write': 1,
                                                 'delete': 1}}})

    yield {'files': files, 'rse_without_proxy': rse_without_proxy, 'rse_with_proxy': rse_with_proxy}

    for rse_id in [rse_with_proxy_id, rse_without_proxy_id]:
        delete_replicas(rse_id=rse_id, files=files)
    del_rse(rse_with_proxy_id)
    del_rse(rse_without_proxy_id)


@pytest.mark.noparallel(reason='fixture changes global configuration value')
def test_client_list_replicas1(replica_client, root_proxy_example_data):
    """ ROOT (CLIENT): No proxy involved """

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock',
                                                               'name': f['name'],
                                                               'type': 'FILE'} for f in root_proxy_example_data['files']],
                                                        rse_expression=root_proxy_example_data['rse_without_proxy'],
                                                        client_location=client_location_without_proxy)]

    expected_pfns = ['root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1',
                     'root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2',
                     'root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3']
    found_pfns = [list(replica['pfns'].keys())[0] for replica in replicas]
    assert sorted(found_pfns) == sorted(expected_pfns)


@pytest.mark.noparallel(reason='fixture changes global configuration value')
def test_client_list_replicas2(replica_client, root_proxy_example_data):
    """ ROOT (CLIENT): Outgoing proxy needs to be prepended"""

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock',
                                                               'name': f['name'],
                                                               'type': 'FILE'} for f in root_proxy_example_data['files']],
                                                        rse_expression=root_proxy_example_data['rse_without_proxy'],
                                                        client_location=client_location_with_proxy)]

    expected_pfns = ['root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1',
                     'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2',
                     'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3']
    found_pfns = [list(replica['pfns'].keys())[0] for replica in replicas]
    assert sorted(found_pfns) == sorted(expected_pfns)


@pytest.mark.noparallel(reason='fixture changes global configuration value')
def test_client_list_replicas3(replica_client, root_proxy_example_data):
    """ ROOT (CLIENT): Outgoing proxy at destination does not matter"""

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock',
                                                               'name': f['name'],
                                                               'type': 'FILE'} for f in root_proxy_example_data['files']],
                                                        rse_expression=root_proxy_example_data['rse_with_proxy'],
                                                        client_location=client_location_without_proxy)]

    expected_pfns = ['root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1',
                     'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2',
                     'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3']
    found_pfns = [list(replica['pfns'].keys())[0] for replica in replicas]
    assert sorted(found_pfns) == sorted(expected_pfns)


@pytest.mark.noparallel(reason='fixture changes global configuration value')
def test_client_list_replicas4(replica_client, root_proxy_example_data):
    """ ROOT (CLIENT): Outgoing proxy does not matter when staying at site"""

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock',
                                                               'name': f['name'],
                                                               'type': 'FILE'} for f in root_proxy_example_data['files']],
                                                        rse_expression=root_proxy_example_data['rse_with_proxy'],
                                                        client_location=client_location_with_proxy)]
    expected_pfns = ['root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1',
                     'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2',
                     'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3']
    found_pfns = [list(replica['pfns'].keys())[0] for replica in replicas]
    assert sorted(found_pfns) == sorted(expected_pfns)


@pytest.mark.noparallel(reason='fixture changes global configuration value')
def test_redirect_metalink_list_replicas(vo, rest_client):
    """ ROOT (REDIRECT REST): Test internal proxy prepend with metalink"""
    # default behaviour - no location -> no proxy
    response = rest_client.get('/redirect/mock/half-life_1/metalink', headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1' in body
    assert 'proxy' not in body
    response = rest_client.get('/redirect/mock/half-life_2/metalink', headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2' in body
    assert 'proxy' not in body
    response = rest_client.get('/redirect/mock/half-life_3/metalink', headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3' in body
    assert 'proxy' not in body

    # site without proxy
    response = rest_client.get('/redirect/mock/half-life_1/metalink?' + urlencode(client_location_without_proxy), headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1' in body
    assert 'proxy' not in body
    response = rest_client.get('/redirect/mock/half-life_2/metalink?' + urlencode(client_location_without_proxy), headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2' in body
    assert 'proxy' not in body
    response = rest_client.get('/redirect/mock/half-life_3/metalink?' + urlencode(client_location_without_proxy), headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3' in body
    assert 'proxy' not in body

    # at location with outgoing proxy, prepend for wan replica
    response = rest_client.get('/redirect/mock/half-life_1/metalink?' + urlencode(client_location_with_proxy), headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1' in body
    response = rest_client.get('/redirect/mock/half-life_2/metalink?' + urlencode(client_location_with_proxy), headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2' in body
    response = rest_client.get('/redirect/mock/half-life_3/metalink?' + urlencode(client_location_with_proxy), headers=headers(vohdr(vo)))
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3' in body
    assert 'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3' in body
