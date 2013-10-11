# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import os

from os.path import dirname
from urlparse import urlparse

from rucio.common.utils import execute
from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):

    def connect(self, credentials):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
        """
        extended_attributes = self.rse['protocol']['extended_attributes']
        if 'STAGE_SVCCLASS' in extended_attributes:
            os.environ['STAGE_SVCCLASS'] = extended_attributes['STAGE_SVCCLASS']

    def path2pfn(self, path):
        """
            Retruns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        return ''.join([self.rse['scheme'], '://', path])

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        cmd = 'rfstat %(path)s' % locals()
        status, out, err = execute(cmd)
        return status == 0

    def close(self):
        """ Closes the connection to RSE."""
        if 'STAGE_SVCCLASS' in os.environ:
            del os.environ['STAGE_SVCCLASS']

    def put(self, source, target, source_dir):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        if not self.exists(dirname(target)):
            self.mkdir(dirname(target))

        cmd = 'rfcp %(source)s %(path)s' % locals()
        status, out, err = execute(cmd)
        return status == 0

    def mkdir(self, directory):
        cmd = 'rfmkdir -p %(path)s' % locals()
        status, out, err = execute(cmd)
        return status == 0

    def split_pfn(self, pfn):
        """
            Splits the given PFN into the parts known by the protocol. During parsing the PFN is also checked for
            validity on the given RSE with the given protocol.

            :param pfn: a fully qualified PFN

            :returns: a dict containing all known parts of the PFN for the protocol e.g. scheme, hostname, port, prefix, path, filename

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        parsed = urlparse(pfn)
        ret = dict()
        ret['scheme'] = parsed.scheme
        ret['hostname'] = parsed.netloc.partition(':')[0]
        ret['port'] = int(parsed.netloc.partition(':')[2]) if parsed.netloc.partition(':')[2] != '' else 0
        ret['path'] = parsed.path

        # Protect against 'lazy' defined prefixes for RSEs in the repository
        self.rse['prefix'] = '' if self.rse['prefix'] is None else self.rse['prefix']
        if not self.rse['prefix'].startswith('/'):
            self.rse['prefix'] = '/' + self.rse['prefix']
        if not self.rse['prefix'].endswith('/'):
            self.rse['prefix'] += '/'

        if self.rse['hostname'] != ret['hostname']:
            raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (ret['hostname'], self.rse['hostname']))

        if not ret['path'].startswith(self.rse['prefix']):
            raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(ret['path'].split('/')[0:len(self.rse['prefix'].split('/')) - 1]),
                                                                                                          self.rse['prefix']))  # len(...)-1 due to the leading '/
        # Spliting parsed.path into prefix, path, filename
        ret['prefix'] = self.rse['prefix']
        ret['path'] = ret['path'].partition(self.rse['prefix'])[2]
        ret['name'] = ret['path'].split('/')[-1]
        ret['path'] = ret['path'].partition(ret['name'])[0]

        return ret
