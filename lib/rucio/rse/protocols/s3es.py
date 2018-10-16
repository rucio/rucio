# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016
#
# PY3K COMPATIBLE

from rucio.common import exception
from rucio.common import objectstore
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the S3 protocol."""

    def __init__(self, protocol_attr, rse_settings):
        super(Default, self).__init__(protocol_attr, rse_settings)

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        if path.startswith("s3:") or path.startswith("http"):
            return path

        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        return ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, path])

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
        """
        url = self.path2pfn('')
        objectstore.connect(self.rse['rse'], url)

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def delete(self, pfn_dir):
        """
            Deletes a directory from the connected RSE.

            :param pfn_dir: path to the to be deleted directory
            :raises ServiceUnavailable: if some generic error occured in the library.
        """
        try:
            status, output = objectstore.delete_dir(pfn_dir, rse=self.rse['rse'])
            if status != 0:
                raise exception.RucioException("Failed to delete directory %s on RSE %s: %s" % (pfn_dir, self.rse['rse'], output))
        except NotImplementedError:
            raise NotImplementedError
        except Exception as e:
            raise exception.ServiceUnavailable(e)
