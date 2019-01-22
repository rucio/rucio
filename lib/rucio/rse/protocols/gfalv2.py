# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

try:
    # PY2
    from exceptions import NotImplementedError
except ImportError:
    # PY3
    pass

from rucio.rse.protocols import gfal


class Default(gfal.Default):

    """ Implementing access to RSEs using the ngarc protocol."""

    def __init__(self, protocol_attr, rse_settings):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings)
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
