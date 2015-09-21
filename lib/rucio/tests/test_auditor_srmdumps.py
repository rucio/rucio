from ConfigParser import ConfigParser
from datetime import datetime
from nose.tools import eq_
from nose.tools import raises
from rucio.daemons.auditor import srmdumps
from rucio.tests.common import stubbed


def test_get_newest_matches_the_patterns_on_file_names():
    links = [
        '/test/filename-with-2015-weird-01-date-30'
    ]
    base_url = '/test'
    pattern = 'filename-with-%Y-weird-%m-date-%d'
    newest, date = srmdumps.get_newest(base_url, pattern, links)
    eq_(newest, links[0])
    eq_(date, datetime(2015, 01, 30))


def test_get_newest_returns_actually_the_newest_path():
    links = [
        '/test/filename-with-2014-weird-01-date-10',
        '/test/filename-with-2015-weird-01-date-30',
        '/test/filename-with-2015-weird-01-date-10',
    ]
    base_url = '/test'
    pattern = 'filename-with-%Y-weird-%m-date-%d'
    newest, date = srmdumps.get_newest(base_url, pattern, links)
    eq_(newest, '/test/filename-with-2015-weird-01-date-30')
    eq_(date, datetime(2015, 01, 30))


def test_get_newest_pattern_can_be_on_directory():
    links = [
        '/test/dir-with-2015-weird-01-date-30'
    ]
    base_url = '/test'
    pattern = 'dir-with-%Y-weird-%m-date-%d/dump'
    newest, date = srmdumps.get_newest(base_url, pattern, links)
    eq_(newest, links[0] + '/dump')
    eq_(date, datetime(2015, 01, 30))


@raises(Exception)
def test_get_newest_exception_raise_when_no_matching_links():
    links = [
        '/test/dir-with'
    ]
    base_url = '/test'
    pattern = 'dir-with-%Y-weird-%m-date-%d/dump'
    newest, date = srmdumps.get_newest(base_url, pattern, links)


def test__link_collector_returns_a_list_of_links():
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


def test_protocol_identifies_http_and_srm():
    eq_(srmdumps.protocol('http://some/example'), 'http')
    eq_(srmdumps.protocol('srm://some/example'), 'srm')


@raises(Exception)
def test_protocol_fails_on_unknown_protocol():
    srmdumps.protocol('fake://some/example')


def test_generate_url_returns_standard_url_for_sites_with_no_configuration_file():
    config = ConfigParser()
    with stubbed(srmdumps.ddmendpoint_url, lambda _: 'srm://example.com/atlasdatadisk/'):
        base_url, pattern = srmdumps.generate_url('SITE_DATADISK', config)
    eq_(base_url, 'srm://example.com/atlasdatadisk/dumps')
    eq_(pattern, 'dump_%Y%m%d')


def test_generate_url_returns_custom_url_for_sites_with_configuration_file():
    config = ConfigParser()
    config.add_section('SITE')
    config.set('SITE', 'SITE_DATADISK', 'http://example.com/pattern-%Y-%m-%d/dumps')
    base_url, pattern = srmdumps.generate_url('SITE_DATADISK', config)
    eq_(base_url, 'http://example.com')
    eq_(pattern, 'pattern-%Y-%m-%d/dumps')
