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

from io import StringIO

from rucio.common import dumper
from rucio.tests.common import mock_open

from .mocks import gfal2


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
