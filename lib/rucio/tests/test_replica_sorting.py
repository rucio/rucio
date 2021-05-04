# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import copy
import json
from unittest import mock
from urllib.parse import urlparse

import pytest

from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import parse_replicas_from_string
from rucio.core import rse_expression_parser, replica_sorter
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, del_rse, add_rse_attribute, add_protocol, del_rse_attribute
from rucio.tests.common import rse_name_generator, headers, auth, vohdr, Mime, accept

base_rse_info = [
    {'site': 'APERTURE', 'address': 'aperture.com'},
    {'site': 'BLACKMESA', 'address': 'blackmesa.com'},
]
schemes = ['root', 'gsiftp', 'davs']


@pytest.fixture
def protocols_setup(vo):
    rse_info = copy.deepcopy(base_rse_info)

    files = [{'scope': InternalScope('mock', vo=vo), 'name': 'element_0', 'bytes': 1234, 'adler32': 'deadbeef'}]
    root = InternalAccount('root', vo=vo)

    for idx in range(len(rse_info)):
        rse_info[idx]['name'] = '%s_%s' % (rse_info[idx]['site'], rse_name_generator())
        rse_info[idx]['id'] = add_rse(rse_info[idx]['name'], vo=vo)
        add_rse_attribute(rse_id=rse_info[idx]['id'], key='site', value=base_rse_info[idx]['site'])
        add_replicas(rse_id=rse_info[idx]['id'], files=files, account=root)

    # invalidate cache for parse_expression('site=…')
    rse_expression_parser.REGION.invalidate()

    # check sites
    for idx in range(len(rse_info)):
        site_rses = rse_expression_parser.parse_expression('site=' + base_rse_info[idx]['site'])
        assert len(site_rses) > 0
        assert rse_info[idx]['id'] in [rse['id'] for rse in site_rses]

    add_protocol(rse_info[0]['id'], {'scheme': schemes[0],
                                     'hostname': ('root.%s' % base_rse_info[0]['address']),
                                     'port': 1409,
                                     'prefix': '//test/chamber/',
                                     'impl': 'rucio.rse.protocols.xrootd.Default',
                                     'domains': {
                                         'lan': {'read': 1, 'write': 1, 'delete': 1},
                                         'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_info[0]['id'], {'scheme': schemes[2],
                                     'hostname': ('davs.%s' % base_rse_info[0]['address']),
                                     'port': 443,
                                     'prefix': '/test/chamber/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': 2, 'write': 2, 'delete': 2},
                                         'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    add_protocol(rse_info[0]['id'], {'scheme': schemes[1],
                                     'hostname': ('gsiftp.%s' % base_rse_info[0]['address']),
                                     'port': 8446,
                                     'prefix': '/test/chamber/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': 0, 'write': 0, 'delete': 0},
                                         'wan': {'read': 3, 'write': 3, 'delete': 3}}})

    add_protocol(rse_info[1]['id'], {'scheme': schemes[1],
                                     'hostname': ('gsiftp.%s' % base_rse_info[1]['address']),
                                     'port': 8446,
                                     'prefix': '/lambda/complex/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': 2, 'write': 2, 'delete': 2},
                                         'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_info[1]['id'], {'scheme': schemes[2],
                                     'hostname': ('davs.%s' % base_rse_info[1]['address']),
                                     'port': 443,
                                     'prefix': '/lambda/complex/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': 0, 'write': 0, 'delete': 0},
                                         'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    add_protocol(rse_info[1]['id'], {'scheme': schemes[0],
                                     'hostname': ('root.%s' % base_rse_info[1]['address']),
                                     'port': 1409,
                                     'prefix': '//lambda/complex/',
                                     'impl': 'rucio.rse.protocols.xrootd.Default',
                                     'domains': {
                                         'lan': {'read': 1, 'write': 1, 'delete': 1},
                                         'wan': {'read': 3, 'write': 3, 'delete': 3}}})

    yield {'files': files, 'rse_info': rse_info}

    for info in rse_info:
        delete_replicas(rse_id=info['id'], files=files)
        del_rse_attribute(rse_id=info['id'], key='site')
        del_rse(info['id'])


@pytest.mark.noparallel(reason='fails when run in parallel, lists replicas and checks for length of returned list')
@pytest.mark.parametrize("content_type", [
    Mime.METALINK,
    pytest.param(Mime.JSON_STREAM, marks=pytest.mark.xfail(reason='see https://github.com/rucio/rucio/issues/4105')),
])
def test_sort_geoip_wan(vo, rest_client, auth_token, protocols_setup, content_type):
    """Replicas: test sorting a few WANs via geoip."""
    n = 10
    nmap = {}

    def fake_get_distance(se1, se2, *args, **kwargs):
        nonlocal n, nmap
        n = n - 1
        print("fake_get_distance", {'se1': se1, 'se2': se2, 'n': n})
        assert se1, 'pfn host must be se1 for this test'
        nmap[se1] = n
        return n

    data = {
        'dids': [{'scope': f['scope'].external, 'name': f['name'], 'type': 'FILE'} for f in protocols_setup['files']],
        'schemes': schemes,
        'sort': 'geoip',
    }

    with mock.patch('rucio.core.replica_sorter.__get_distance', side_effect=fake_get_distance):
        response = rest_client.post(
            '/replicas/list',
            headers=headers(auth(auth_token), vohdr(vo), accept(content_type)),
            json=data
        )
    assert response.status_code == 200

    replicas_response = response.get_data(as_text=True)
    assert replicas_response

    # because urlparse hostname result is lower case
    sorted_hosts = list(map(str.lower, sorted(nmap, key=nmap.get)))

    if content_type == Mime.METALINK:
        replicas = parse_replicas_from_string(replicas_response)
        print(replicas)
        assert len(replicas) == 1
        sources_list = replicas[0]['sources']
        print(sources_list)
        assert len(sources_list) == 6

        sorted_replica_hosts = list(sorted(sources_list, key=lambda source: source['priority']))
        sorted_replica_hosts = list(map(lambda source: urlparse(source['pfn']).hostname, sorted_replica_hosts))
        assert sorted_hosts == sorted_replica_hosts, 'assert sorting of result as distance suggested'

    elif content_type == Mime.JSON_STREAM:
        replicas = list(map(json.loads, filter(bool, map(str.strip, replicas_response.splitlines(keepends=False)))))
        print(replicas)
        assert len(replicas) == 1
        sources_dict = replicas[0]['pfns']
        assert len(sources_dict) == 6

        sorted_replica_hosts = list(sorted(sources_dict, key=lambda pfn: sources_dict[pfn]['priority']))
        sorted_replica_hosts = list(map(lambda source: urlparse(source).hostname, sorted_replica_hosts))
        assert sorted_hosts == sorted_replica_hosts, 'assert sorting of result as distance suggested'


def prepare_sort_geoip_lan_before_wan_params():
    argvalues = [
        (Mime.METALINK, 0),
        (Mime.METALINK, 1),
        pytest.param(Mime.JSON_STREAM, 0, marks=pytest.mark.xfail(reason='see https://github.com/rucio/rucio/issues/4105')),
        pytest.param(Mime.JSON_STREAM, 1, marks=pytest.mark.xfail(reason='see https://github.com/rucio/rucio/issues/4105')),
    ]
    rargvalues = map(lambda p: p.values if hasattr(p, 'values') else p, argvalues)
    ids = [f'mime={repr(mime)}, lan-site={repr(base_rse_info[iid]["site"])}' for mime, iid in rargvalues]
    return dict(argvalues=argvalues, ids=ids)


@pytest.mark.noparallel(reason='fails when run in parallel, uses site=… as rse expression with non-unique sites')
@pytest.mark.parametrize("content_type,info_id", **prepare_sort_geoip_lan_before_wan_params())
def test_sort_geoip_lan_before_wan(vo, rest_client, auth_token, protocols_setup, content_type, info_id):
    """Replicas: test sorting LAN sites before WANs via geoip."""
    n = 2
    nmap = {}

    def fake_get_distance(se1, se2, *args, **kwargs):
        nonlocal n, nmap
        n = n - 1
        print("fake_get_distance", {'se1': se1, 'se2': se2, 'n': n})
        assert se1, 'pfn host must be se1 for this test'
        nmap[se1] = n
        return n

    data = {
        'dids': [{'scope': f['scope'].external, 'name': f['name'], 'type': 'FILE'} for f in protocols_setup['files']],
        'client_location': {'site': protocols_setup['rse_info'][info_id]['site']},
        'schemes': schemes,
        'sort': 'geoip',
    }

    # invalidate cache for parse_expression('site=…')
    rse_expression_parser.REGION.invalidate()

    with mock.patch('rucio.core.replica_sorter.__get_distance', side_effect=fake_get_distance):
        response = rest_client.post(
            '/replicas/list',
            headers=headers(auth(auth_token), vohdr(vo), accept(content_type)),
            json=data
        )
    assert response.status_code == 200

    replicas_response = response.get_data(as_text=True)
    assert replicas_response

    # because urlparse hostname result is lower case
    sorted_wan_hosts = list(map(str.lower, sorted(nmap, key=nmap.get)))

    if content_type == Mime.METALINK:
        replicas = parse_replicas_from_string(replicas_response)
        print(replicas)
        assert len(replicas) == 1
        sources_list = replicas[0]['sources']
        print(sources_list)
        # 3 for wan and 2 for lan, since one is blocked for lan for each site
        assert len(sources_list) == 5

        sorted_replica_hosts = list(sorted(sources_list, key=lambda source: source['priority']))
        print(sorted_replica_hosts)
        lan_pfns = list(filter(lambda source: source['domain'] == 'lan', sorted_replica_hosts))
        assert len(lan_pfns) == 2
        for lanpfn in lan_pfns:
            assert protocols_setup['rse_info'][info_id]['name'] == lanpfn['rse']

        sorted_replica_wan_hosts = list(map(lambda source: urlparse(source['pfn']).hostname,
                                            filter(lambda source: source['domain'] != 'lan', sorted_replica_hosts)))
        assert sorted_wan_hosts == sorted_replica_wan_hosts

    elif content_type == Mime.JSON_STREAM:
        replicas = list(map(json.loads, filter(bool, map(str.strip, replicas_response.splitlines(keepends=False)))))
        print(replicas)
        assert len(replicas) == 1
        sources_dict = replicas[0]['pfns']
        # 3 for wan and 2 for lan, since one is blocked for lan for each site
        assert len(sources_dict) == 5

        sorted_replica_hosts = list(sorted(sources_dict, key=lambda pfn: sources_dict[pfn]['priority']))
        lan_pfns = list(filter(lambda pfn: sources_dict[pfn]['domain'] == 'lan', sorted_replica_hosts))
        assert len(lan_pfns) == 2
        for lanpfn in lan_pfns:
            assert protocols_setup['rse_info'][info_id]['id'] == sources_dict[lanpfn]['rse_id']

        wan_pfns = filter(lambda pfn: sources_dict[pfn]['domain'] != 'lan', sorted_replica_hosts)
        sorted_replica_wan_hosts = list(map(lambda pfn: urlparse(pfn).hostname, wan_pfns))
        assert sorted_wan_hosts == sorted_replica_wan_hosts


@pytest.mark.noparallel(reason='fails when run in parallel, uses site=… as rse expression with non-unique sites')
@pytest.mark.parametrize("content_type", [Mime.METALINK, Mime.JSON_STREAM])
def test_not_sorting_lan_replicas(vo, rest_client, auth_token, protocols_setup, content_type):
    """Replicas: test not sorting only LANs."""

    data = {
        'dids': [{'scope': f['scope'].external, 'name': f['name'], 'type': 'FILE'} for f in protocols_setup['files']],
        # yes, this is rather a hack (but works on the API as well). I would like to have an rse_expression parameter instead.
        'client_location': {'site': '|site='.join(map(lambda info: info['site'], protocols_setup['rse_info']))},
        'schemes': schemes,
    }

    def fake_sort_replicas(dictreplica, *args, **kwargs):
        # test that nothing is passed to sort_replicas
        assert not dictreplica
        return []

    # invalidate cache for parse_expression('site=…')
    rse_expression_parser.REGION.invalidate()

    with mock.patch('rucio.web.rest.flaskapi.v1.replicas.sort_replicas', side_effect=fake_sort_replicas):
        response = rest_client.post(
            '/replicas/list',
            headers=headers(auth(auth_token), vohdr(vo), accept(content_type)),
            json=data
        )
    assert response.status_code == 200

    replicas_response = response.get_data(as_text=True)
    assert replicas_response

    if content_type == Mime.METALINK:
        replicas = parse_replicas_from_string(replicas_response)
        print(replicas)
        assert len(replicas) == 1
        sources_list = replicas[0]['sources']
        print(sources_list)
        # 4 for lan, since one is blocked for lan for each site
        assert len(sources_list) == 4

    elif content_type == Mime.JSON_STREAM:
        replicas = list(map(json.loads, filter(bool, map(str.strip, replicas_response.splitlines(keepends=False)))))
        print(replicas)
        assert len(replicas) == 1
        sources_dict = replicas[0]['pfns']
        # 4 for lan, since one is blocked for lan for each site
        assert len(sources_dict) == 4


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("content_type", [
    Mime.METALINK,
    pytest.param(Mime.JSON_STREAM, marks=pytest.mark.xfail(reason='see https://github.com/rucio/rucio/issues/4105')),
])
def test_sort_geoip_address_not_found_error(vo, rest_client, auth_token, protocols_setup, content_type):
    """Replicas: test sorting via geoip with ignoring geoip errors."""

    class MockedGeoIPError(Exception):
        def __init__(self, *args):
            super(MockedGeoIPError, self).__init__(*args)

    def fake_get_geoip_db(*args, **kwargs):
        raise MockedGeoIPError()

    data = {
        'dids': [{'scope': f['scope'].external, 'name': f['name'], 'type': 'FILE'} for f in protocols_setup['files']],
        'schemes': schemes,
        'sort': 'geoip',
    }

    # invalidate cache for __get_distance so that __get_geoip_db is called
    replica_sorter.REGION.invalidate()

    with mock.patch('rucio.core.replica_sorter.__get_geoip_db', side_effect=fake_get_geoip_db) as get_geoip_db_mock:
        response = rest_client.post(
            '/replicas/list',
            headers=headers(auth(auth_token), vohdr(vo), accept(content_type)),
            json=data
        )
        assert response.status_code == 200

        replicas_response = response.get_data(as_text=True)
        assert replicas_response

        get_geoip_db_mock.assert_called()
