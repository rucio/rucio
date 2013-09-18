# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

from os.path import normpath
from urlparse import SplitResult, urlunsplit

from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the srm protocol."""

    def __init__(self, props):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        self.rse = props
        self.scheme = 'srm'
        self.hostname = self.rse['hostname']
        self.port = self.rse['port']
        self.prefix = self.rse['prefix']
        self.web_service_path = self.rse['extended_attributes']['web_service_path']
        self.space_token = self.rse['extended_attributes']['space_token']

    def pfn2uri(self, pfn):
        netloc = '{0}:{1}'.format(self.hostname, self.port)
        path = self.web_service_path + normpath(self.prefix + '/' + pfn)
        return urlunsplit(SplitResult(scheme='srm', netloc=netloc, path=path, query='', fragment=''))
