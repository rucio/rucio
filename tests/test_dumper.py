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

import json
from io import StringIO
from unittest import mock

import pytest
import requests

from rucio.common import dumper
from rucio.tests.common import mock_open

from .mocks import gfal2


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.text = json.dumps(json_data)

    def json(self):
        return self.json_data


@mock.patch('requests.get')
def test_http_download_to_file_without_session_uses_requests_get(mock_get):
    response = requests.Response()
    response.status_code = 200
    response.iter_content = lambda _: ['content']
    mock_get.return_value = response
    stringio = StringIO()

    dumper.http_download_to_file('http://example.com', stringio)

    stringio.seek(0)
    assert stringio.read() == 'content'


def test_http_download_to_file_with_session():
    response = requests.Response()
    response.status_code = 200
    response.iter_content = lambda _: ['content']

    stringio = StringIO()
    session = requests.Session()
    session.get = lambda _: response

    dumper.http_download_to_file('http://example.com', stringio, session)
    stringio.seek(0)
    assert stringio.read() == 'content'


def test_http_download_to_file_throws_exception_on_error():
    response = requests.Response()
    response.status_code = 404
    response.iter_content = lambda _: ['content']

    stringio = StringIO()
    session = requests.Session()
    session.get = lambda _: response

    with pytest.raises(dumper.HTTPDownloadFailed):
        dumper.http_download_to_file('http://example.com', stringio, session)


@mock.patch('requests.get')
def test_http_download_creates_file_with_content(mock_get):
    response = requests.Response()
    response.status_code = 200
    response.iter_content = lambda _: ['abc']
    stringio = StringIO()
    mock_get.return_value = response

    with mock_open(dumper, stringio):
        dumper.http_download('http://example.com', 'filename')

    stringio.seek(0)
    assert stringio.read() == 'abc'


def test_gfal_download_to_file():
    gfal_file = StringIO()
    local_file = StringIO()
    gfal_file.write('content')
    gfal_file.seek(0)

    with gfal2.mocked_gfal2(dumper, files={'srm://example.com/file': gfal_file}):
        dumper.gfal_download_to_file('srm://example.com/file', local_file)

    local_file.seek(0)
    assert local_file.read() == 'content'


def test_gfal_download_creates_file_with_content():
    gfal_file = StringIO()
    local_file = StringIO()
    gfal_file.write('content')
    gfal_file.seek(0)

    with gfal2.mocked_gfal2(dumper, files={'srm://example.com/file': gfal_file}):
        with mock_open(dumper, local_file):
            dumper.gfal_download('srm://example.com/file', 'filename')

    local_file.seek(0)
    assert local_file.read() == 'content'
