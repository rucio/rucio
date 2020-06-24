# Copyright 2016-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2016
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Tomas Javurek <tomasjavurek09@gmail.com>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
#
# PY3K COMPATIBLE

# !!! DEPRECATION WARNING !!!
#
# This module will go away.
#
# Use instead: impl=rucio.rse.protocols.gfal.NoRename
#
# !!! DEPRECATION WARNING !!!

try:
    # PY2
    from exceptions import NotImplementedError
except ImportError:
    # PY3
    pass

from rucio.rse.protocols import gfal


class Default(gfal.Default):

    """ Implementing access to RSEs using the ngarc protocol."""

    def __init__(self, protocol_attr, rse_settings, logger=None):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.renaming = False
        self.attributes.pop('determinism_type', None)
        self.files = []

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        raise NotImplementedError
