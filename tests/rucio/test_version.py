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

from rucio.vcsversion import VERSION_INFO
from rucio.version import canonical_version_string, vcs_version_string, version_string, version_string_with_vcs


class TestVersion:
    def test_canonical_version_string(self):
        assert canonical_version_string() == VERSION_INFO['version']

    def test_version_string(self):
        assert version_string() == VERSION_INFO['version']

    def test_vcs_version_string(self):
        assert vcs_version_string() == "%s:%s" % (VERSION_INFO['branch_nick'], VERSION_INFO['revision_id'])

    def test_version_string_with_vcs(self):
        assert version_string_with_vcs() == "%s-%s" % (VERSION_INFO['version'], "%s:%s" % (VERSION_INFO['branch_nick'], VERSION_INFO['revision_id']))
