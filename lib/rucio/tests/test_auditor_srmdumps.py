# Copyright 2015-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Fernando Lopez <fernando.e.lopez@gmail.com>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Vincent Garonne <vgaronne@gmail.com>, 2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K

import mock

try:
    # PY2
    from ConfigParser import ConfigParser
except ImportError:
    # PY3
    from configparser import ConfigParser
from datetime import datetime
from nose.tools import eq_
from nose.tools import raises
from rucio.daemons.auditor import srmdumps


def test_patterns_on_file_names():
    """ test_get_newest_matches_the_patterns_on_file_names """
    links = [
        '/test/filename-with-2015-weird-01-date-30'
    ]
    base_url = '/test'
    pattern = 'filename-with-%Y-weird-%m-date-%d'
    newest, date = srmdumps.get_newest(base_url, pattern, links)
    eq_(newest, links[0])
    eq_(date, datetime(2015, 1, 30))


def test_the_newest_path():
    """ test_get_newest_returns_actually_the_newest_path """
    links = [
        '/test/filename-with-2014-weird-01-date-10',
        '/test/filename-with-2015-weird-01-date-30',
        '/test/filename-with-2015-weird-01-date-10',
    ]
    base_url = '/test'
    pattern = 'filename-with-%Y-weird-%m-date-%d'
    newest, date = srmdumps.get_newest(base_url, pattern, links)
    eq_(newest, '/test/filename-with-2015-weird-01-date-30')
    eq_(date, datetime(2015, 1, 30))


def test_be_on_directory():
    """ test_get_newest_pattern_can_be_on_directory """
    links = [
        '/test/dir-with-2015-weird-01-date-30'
    ]
    base_url = '/test'
    pattern = 'dir-with-%Y-weird-%m-date-%d/dump'
    newest, date = srmdumps.get_newest(base_url, pattern, links)
    eq_(newest, links[0] + '/dump')
    eq_(date, datetime(2015, 1, 30))


@raises(Exception)
def test_no_matching_links():
    """ test_get_newest_exception_raise_when_no_matching_links """
    links = [
        '/test/dir-with'
    ]
    base_url = '/test'
    pattern = 'dir-with-%Y-weird-%m-date-%d/dump'
    srmdumps.get_newest(base_url, pattern, links)


def test_returns_a_list_of_links():
    """ test__link_collector_returns_a_list_of_links """
    collector = srmdumps._LinkCollector()
    collector.feed('''
    <html>
    <body>
    <a href='x'></a>
    <a href='y'></a>
    </body>
    </html>
    ''')

    eq_(collector.links, ['x', 'y'])


def test_identifies_known_protocols():
    """ test_protocol_identifies_known_protocols """
    eq_(srmdumps.protocol('davs://some/example'), 'davs')
    eq_(srmdumps.protocol('gsiftp://some/example'), 'gsiftp')
    eq_(srmdumps.protocol('http://some/example'), 'http')
    eq_(srmdumps.protocol('https://some/example'), 'https')
    eq_(srmdumps.protocol('root://some/example'), 'root')
    eq_(srmdumps.protocol('srm://some/example'), 'srm')


@raises(Exception)
def test_fails_on_unknown_protocol():
    """ test_protocol_fails_on_unknown_protocol """
    srmdumps.protocol('fake://some/example')


@mock.patch('rucio.daemons.auditor.srmdumps.ddmendpoint_url')
def test_sites_no_configuration_file(mock_ddmendpoint):
    """ test_generate_url_returns_standard_url_for_sites_with_no_configuration_file"""
    config = ConfigParser()
    mock_ddmendpoint.return_value = 'srm://example.com/atlasdatadisk/'
    base_url, pattern = srmdumps.generate_url('SITE_DATADISK', config)
    eq_(base_url, 'srm://example.com/atlasdatadisk/dumps')
    eq_(pattern, 'dump_%Y%m%d')


def test_with_configuration_file():
    """ test_generate_url_returns_custom_url_for_sites_with_configuration_file"""
    config = ConfigParser()
    config.add_section('SITE')
    config.set('SITE', 'SITE_DATADISK', 'http://example.com/pattern-%%Y-%%m-%%d/dumps')
    base_url, pattern = srmdumps.generate_url('SITE_DATADISK', config)
    eq_(base_url, 'http://example.com')
    eq_(pattern, 'pattern-%Y-%m-%d/dumps')
