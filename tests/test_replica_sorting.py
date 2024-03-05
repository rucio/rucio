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

import copy
import json
import os
from unittest import mock
from urllib.parse import urlparse
from tempfile import mkstemp

import geoip2.database
import pytest

from rucio.common.utils import parse_replicas_from_string
from rucio.common.config import config_get
from rucio.core import rse_expression_parser, replica_sorter
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, del_rse, add_rse_attribute, add_protocol, del_rse_attribute
from rucio.tests.common import rse_name_generator, headers, auth, vohdr, Mime, accept
from .inputs import GEOIP_LITE2_CITY_TEST_DB

LOCATION_TO_IP = {
    'Switzerland': '2a02:d000::1',
    'Romania': '2a02:e940::1',
    'Austria': '2a02:da80::1',
    'United Kingdom': '81.2.69.142',
    'China': '175.16.199.0',
    'United States': '216.160.83.56',
    'Japan': '2001:258::1',
    'Taiwan': '2001:288::1',
    'Israel': '2a02:cf80::1',
    'Finland': '2a02:d200::1',
    'United Arab Emirates': '2a02:f400::1',
    'Libya': '2a02:e700::1',
}

CLIENT_SITE = 'CLIENTSITE'
CLIENT_SITE_CACHE = '10.0.0.1:443'

base_rse_info = [
    {'site': 'APERTURE', 'address': 'aperture.com', 'ip': LOCATION_TO_IP['Austria']},
    {'site': 'BLACKMESA', 'address': 'blackmesa.com', 'ip': LOCATION_TO_IP['Japan']},
]
schemes = ['root', 'gsiftp', 'davs']


@pytest.fixture
def mock_geoip_db():
    temp_fd, temp_db_path = mkstemp()
    os.close(temp_fd)
    try:
        with open(GEOIP_LITE2_CITY_TEST_DB, 'rb') as archive_file:
            replica_sorter.extract_file_from_tar_gz(archive_file_obj=archive_file,
                                                    file_name='GeoLite2-City-Test.mmdb',
                                                    destination=temp_db_path)
        with mock.patch('rucio.core.replica_sorter.__geoip_db', side_effect=lambda: geoip2.database.Reader(temp_db_path)):
            yield geoip2.database.Reader(temp_db_path)
    finally:
        os.unlink(temp_db_path)


@pytest.fixture
def mock_get_multi_cache_prefix():
    with mock.patch('rucio.core.replica.get_multi_cache_prefix', side_effect=lambda _x, _y: CLIENT_SITE_CACHE):
        yield


@pytest.fixture
def mock_get_lat_long():
    def _get_lat_long_mock(se, gi):
        ip = None
        if se in LOCATION_TO_IP.values():
            ip = se
        else:
            # Try to map the hostname to one of the test RSES fake ip
            for rse_info in base_rse_info:
                if rse_info['address'] in se:
                    ip = rse_info['ip']
                    break
        if ip:
            response = gi.city(ip)
            return response.location.latitude, response.location.longitude

        raise Exception("Unknown ip provided, fail the test")

    with mock.patch('rucio.core.replica_sorter.__get_lat_long', side_effect=_get_lat_long_mock):
        yield


@pytest.fixture
def protocols_setup(vo, root_account, mock_scope):
    rse_info = copy.deepcopy(base_rse_info)

    files = [{'scope': mock_scope, 'name': 'element_0', 'bytes': 1234, 'adler32': 'deadbeef'}]

    for idx in range(len(rse_info)):
        rse_info[idx]['name'] = '%s_%s' % (rse_info[idx]['site'], rse_name_generator())
        rse_info[idx]['id'] = add_rse(rse_info[idx]['name'], vo=vo)
        add_rse_attribute(rse_id=rse_info[idx]['id'], key='site', value=base_rse_info[idx]['site'])
        add_replicas(rse_id=rse_info[idx]['id'], files=files, account=root_account)

    # invalidate cache for parse_expression('site=…')
    rse_expression_parser.REGION.invalidate()

    # check sites
    for idx in range(len(rse_info)):
        site_rses = rse_expression_parser.parse_expression('site=' + base_rse_info[idx]['site'])
        assert len(site_rses) > 0
        assert rse_info[idx]['id'] in [rse['id'] for rse in site_rses]

    add_protocol(rse_info[0]['id'], {'scheme': 'root',
                                     'hostname': ('root.%s' % base_rse_info[0]['address']),
                                     'port': 1409,
                                     'prefix': '//test/chamber/',
                                     'impl': 'rucio.rse.protocols.xrootd.Default',
                                     'domains': {
                                         'lan': {'read': 1, 'write': 1, 'delete': 1},
                                         'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_info[0]['id'], {'scheme': 'davs',
                                     'hostname': ('davs.%s' % base_rse_info[0]['address']),
                                     'port': 443,
                                     'prefix': '/test/chamber/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': 2, 'write': 2, 'delete': 2},
                                         'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    add_protocol(rse_info[0]['id'], {'scheme': 'gsiftp',
                                     'hostname': ('gsiftp.%s' % base_rse_info[0]['address']),
                                     'port': 8446,
                                     'prefix': '/test/chamber/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': None, 'write': None, 'delete': None},
                                         'wan': {'read': 3, 'write': 3, 'delete': 3}}})

    add_protocol(rse_info[1]['id'], {'scheme': 'gsiftp',
                                     'hostname': ('gsiftp.%s' % base_rse_info[1]['address']),
                                     'port': 8446,
                                     'prefix': '/lambda/complex/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': 2, 'write': 2, 'delete': 2},
                                         'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_info[1]['id'], {'scheme': 'davs',
                                     'hostname': ('davs.%s' % base_rse_info[1]['address']),
                                     'port': 443,
                                     'prefix': '/lambda/complex/',
                                     'impl': 'rucio.rse.protocols.gfal.Default',
                                     'domains': {
                                         'lan': {'read': None, 'write': None, 'delete': None},
                                         'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    add_protocol(rse_info[1]['id'], {'scheme': 'root',
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
@pytest.mark.parametrize("content_type", [Mime.METALINK, Mime.JSON_STREAM])
@pytest.mark.parametrize("file_config_mock", [
    # Run test twice: with root proxy and without
    {"overrides": []},
    {"overrides": [('clientcachemap', CLIENT_SITE, 'ANYTHING')]},
], indirect=True)
def test_sort_geoip_wan_client_location(vo, rest_client, auth_token, protocols_setup, content_type,
                                        mock_geoip_db, mock_get_lat_long, mock_get_multi_cache_prefix, file_config_mock):
    """Replicas: test sorting a few WANs via geoip."""

    data = {
        'dids': [{'scope': f['scope'].external, 'name': f['name'], 'type': 'FILE'} for f in protocols_setup['files']],
        'schemes': schemes,
        'sort': 'geoip',
    }
    test_with_cache = False
    if config_get('clientcachemap', CLIENT_SITE, raise_exception=False) is not None:
        test_with_cache = True
        data['client_location'] = {'site': CLIENT_SITE}

    first_aut_then_jpn = ['root.aperture.com', 'davs.aperture.com', 'gsiftp.aperture.com', 'gsiftp.blackmesa.com', 'davs.blackmesa.com', 'root.blackmesa.com']
    first_jpn_then_aut = ['gsiftp.blackmesa.com', 'davs.blackmesa.com', 'root.blackmesa.com', 'root.aperture.com', 'davs.aperture.com', 'gsiftp.aperture.com']
    for client_location, expected_order in (
            ('Switzerland', first_aut_then_jpn),
            ('Romania', first_aut_then_jpn),
            ('Austria', first_aut_then_jpn),
            ('United Kingdom', first_aut_then_jpn),
            ('Libya', first_aut_then_jpn),
            ('China', first_jpn_then_aut),
            ('United States', first_jpn_then_aut),
            ('Japan', first_jpn_then_aut),
            ('Taiwan', first_jpn_then_aut),
            ('Israel', first_aut_then_jpn),
            ('Finland', first_aut_then_jpn),
            ('United Arab Emirates', first_aut_then_jpn),
    ):
        response = rest_client.post(
            '/replicas/list',
            headers=headers(auth(auth_token), vohdr(vo), accept(content_type), [('X-Forwarded-For', LOCATION_TO_IP[client_location])]),
            json=data
        )
        assert response.status_code == 200
        replicas_response = response.get_data(as_text=True)
        assert replicas_response

        replicas = []
        pfns = []
        if content_type == Mime.METALINK:
            replicas = parse_replicas_from_string(replicas_response)
            pfns = [s['pfn'] for s in replicas[0]['sources']]
        elif content_type == Mime.JSON_STREAM:
            replicas = list(map(json.loads, filter(bool, map(str.strip, replicas_response.splitlines(keepends=False)))))
            pfns = list(replicas[0]['pfns'])

        print(client_location, pfns)
        assert len(replicas) == 1
        if test_with_cache:
            cache_prefix = f'root://{CLIENT_SITE_CACHE}//'
            for i, pfn in enumerate(pfns):
                if pfn.startswith('root'):
                    assert pfn.startswith(cache_prefix)
                    pfn = pfn[len(cache_prefix):]
                assert urlparse(pfn).hostname == expected_order[i]
        else:
            assert [urlparse(pfn).hostname for pfn in pfns] == expected_order


@pytest.mark.noparallel(reason='fails when run in parallel, lists replicas and checks for length of returned list')
@pytest.mark.parametrize("content_type", [Mime.METALINK, Mime.JSON_STREAM])
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
        (Mime.JSON_STREAM, 0),
        (Mime.JSON_STREAM, 1),
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
@pytest.mark.parametrize("content_type", [Mime.METALINK, Mime.JSON_STREAM])
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

    with mock.patch('rucio.core.replica_sorter.__geoip_db', side_effect=fake_get_geoip_db) as get_geoip_db_mock:
        response = rest_client.post(
            '/replicas/list',
            headers=headers(auth(auth_token), vohdr(vo), accept(content_type)),
            json=data
        )
        assert response.status_code == 200

        replicas_response = response.get_data(as_text=True)
        assert replicas_response

        get_geoip_db_mock.assert_called()


@pytest.mark.noparallel(reason='fails when run in parallel, replicas should not be changed')
def test_get_sorted_list_replicas_no_metalink(vo, rest_client, auth_token, protocols_setup, mock_scope):
    """Replicas: gets the json list replicas and checks if its sorted"""

    global replica_singleton
    replica_singleton = None

    def _reverse_geoip(dictreplica, client_location, ignore_error=False):
        global replica_singleton
        if replica_singleton is None:
            replica_singleton = list(dictreplica.keys())
            return replica_singleton
        replica_singleton.reverse()
        return replica_singleton

    def _extract_priorities(data):
        return {k: v['priority'] for k, v in data['pfns'].items()}

    def get_replicas():
        return parse_replicas_from_string(rest_client.get(
            '/replicas/%s/%s?select=geoip' % (mock_scope.external, protocols_setup['files'][0]['name']),
            headers=headers(auth(auth_token), vohdr(vo), accept(Mime.JSON_STREAM))
        ).get_data(as_text=True))

    with mock.patch('rucio.core.replica_sorter.sort_geoip', side_effect=_reverse_geoip):
        initial_priorities = _extract_priorities(get_replicas())
        updated_priorities = _extract_priorities(get_replicas())
        assert initial_priorities != updated_priorities, "The replica list is not sorted according to the priorities."
