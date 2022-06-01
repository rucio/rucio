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

try:
    from rucio.vcsversion import VERSION_INFO
except ImportError:
    VERSION_INFO = {'branch_nick': u'LOCALBRANCH',     # NOQA
                    'revision_id': u'LOCALREVISION',
                    'version': u'VERSION',
                    'final': False,
                    'revno': 0}

RUCIO_VERSION = [VERSION_INFO['version'], ]
FINAL = VERSION_INFO['final']   # This becomes true at Release Candidate time


def canonical_version_string():
    """ Get the canonical string """
    return '.'.join(filter(None, RUCIO_VERSION))


def version_string():
    """ Get the version string """
    return canonical_version_string()


def vcs_version_string():
    """ Get the VCS version string """
    return "%s:%s" % (VERSION_INFO['branch_nick'], VERSION_INFO['revision_id'])


def version_string_with_vcs():
    """ Get the version string with VCS """
    return "%s-%s" % (canonical_version_string(), vcs_version_string())
