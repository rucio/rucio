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

from rucio.vcsversion import BRANCH_NICK, REVISION_ID, VERSION

RUCIO_VERSION = VERSION

def version_string() -> str:
    """ Get the version string """
    return VERSION


def vcs_version_string() -> str:
    """ Get the VCS version string """
    return "%s:%s" % (BRANCH_NICK, REVISION_ID)


def version_string_with_vcs() -> str:
    """ Get the version string with VCS """

    return "%s-%s" % (version_string(), vcs_version_string())


def current_version() -> str:
    """ Get the current version """
    components = 2 if version_string().startswith("1.") else 1
    return ".".join(version_string().split(".")[:components])
