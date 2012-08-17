# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import json

from rucio.common import exception


class RSEWrapper(object):
    """ This class is a  wrapper for all registered RSEs. Its intention is to provide generic access to
        whatever RSE is referred during the instantiation. It further provides the basic methods
        GET (Download), PUT (Upload), Delete, and Rename files for RSEs.
    """

    def __init__(self, rse_id, credentials={}, protocol=None):
        """ This methode instantiates a new RSE using the provided credetnials and the reffered protocol.

            :param rse_id       The identifier of the requested RSE
            :param credentials  RSE and protocol specific information to authenticate the user
            :param protocol     The identifier of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost, ...

            :raises SwitchProtocol          If the referred protocol is not supported by the referred RSE
            :raises RSENotFound             If the referred RSE is not found insode the RSERepository
            :raises RSERepositoryNotFound   If the RSERepository can be accessed
        """

        self.__protocol = protocol
        self.__id = rse_id
        self.__props = None
        self.__connected = False
        self.__credentials = credentials
        self.__path_to_repo = 'etc/rse.repository'  # path_to_repo: path to the RSE repository used to look-up a specific RSE

        # Loading repository data
        try:
            repdata = json.load(open(self.__path_to_repo))
        except Exception:
            raise exception.RSERepositoryNotFound({'RSERepository': self.__path_to_repo})

        try:
            self.__props = repdata[self.__id]
        except Exception:
            raise exception.RSENotFound({'ID': rse_id})

        # Check if protocol is provided and supported or otherwise assign default protocol
        if self.__protocol is None:
            self.__protocol = self.__props['static']['protocols']['default']
        else:
            if not self.__protocol in self.__props['static']['protocols']['supported']:
                raise exception.SwitchProtocol({'protocols': json.dumps(self.__props['static']['protocols'])})

        # Instantiating the actual protocol class
        parts = ('rucio.rse.protocols.' + self.__protocol).split('.')
        module = ".".join(parts[:-1])
        m = __import__(module)
        for comp in parts[1:]:
            m = getattr(m, comp)
        self.__protocol = m(self.__props)

    def lfn2uri(self, lfns):
        """ Transforms the logical file name (LFN) into the RSE specific URI of the file on the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns A single LFN as string or a list object with LFNs

            :returns: URI of the physical file or a dict object with LFN (key) and the URI (value) in bulk mode
        """
        ret = {}
        lfns = [lfns] if not type(lfns) is list else lfns
        for lfn in lfns:
            pfn = lfn  # Do some magic, e.g. MD5 lfn
            ret[lfn] = self.__protocol.pfn2uri(pfn)
        if len(ret) == 1:
            return ret[lfns[0]]
        return ret

    def exists(self, lfns):
        """ Checks if the provided LFN is known by the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns A single LFN as string or a list object with LFNs

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected         If the connection to the RSE has not yet been established
        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                exists = self.__protocol.exists(lfn)
                ret[lfn] = exists
                if not exists:
                    gs = False
        else:
            raise exception.RSENotConnected()
        if len(ret) == 1:
            return ret[lfns[0]]
        return [gs, ret]

    def connect(self, credentials):
        """ Establishes the connection to the referred storage system.

            :param  credentials         User credentials to use when connecting to the referred storage system. Note that the content of this object depends on the referred protocol to use.

            :raises RSEAccessDenied     If access to the RSE is denied
        """
        if not self.__connected:
            self.__protocol.connect(credentials)
            self.__connected = True

    def close(self):
        """ Closes the connection to the storage system """
        if self.__connected:
            self.__protocol.close()

    def get(self, lfns, dest_dir='.'):
        """ Copy a file (LFN) from the connected RSE to the local file system.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns         A single LFN as string or a list object with LFNs
            :param dest_dir     Path where the downloaded file(s) will be stored

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected         If the connection to the RSE has not yet been established
            :raises DestinationAccessDenied If access to the local destination directory is denied
        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                try:
                    self.__protocol.get(lfn, dest_dir + '/' + lfn)
                    ret[lfn] = True
                except Exception as e:
                    gs = False
                    ret[lfn] = e
        else:
            raise exception.RSENotConnected()
        if len(ret) == 1:
            for x in ret:
                if isinstance(ret[x], Exception):
                    raise ret[x]
                else:
                    return ret[x]
        return [gs, ret]

    def put(self, lfns, source_dir=None):
        """ Uploads a file (LFN) to the connected RSE
            Providing a list of LFNs indicates the bulk mode.

            :param lfns        A single LFN as string or a list object with LFNs
            :param source_dir  Path to the local directory including the source files

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected    If the connection to the RSE has not yet been established
            :raises SourceAccessDenied If access to the local destination directory is denied
            :raises SourceNotFound     If access to the local destination directory is not found
        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                try:
                    self.__protocol.put(lfn, source_dir)
                    ret[lfn] = True
                except Exception as e:
                    gs = False
                    ret[lfn] = e
        else:
            raise exception.RSENotConnected()
        if len(ret) == 1:
            for x in ret:
                if isinstance(ret[x], Exception):
                    raise ret[x]
                else:
                    return ret[x]
        return [gs, ret]

    def delete(self, lfns):
        """ Delete a file (LFN) from the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns        A single LFN as string or a list object with LFNs
            :param source_dir  Path to the local directory including the source files

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected    If the connection to the RSE has not yet been established
            :raises SourceAccessDenied If access to the local destination directory is denied
            :raises SourceNotFound     If access to the local destination directory is not found
        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                try:
                    self.__protocol.delete(lfn)
                    ret[lfn] = True
                except Exception as e:
                    ret[lfn] = e
                    gs = False
        else:
            raise exception .RSENotConnected()
        if len(ret) == 1:
            for x in ret:
                if isinstance(ret[x], Exception):
                    raise ret[x]
                else:
                    return ret[x]
        return [gs, ret]

    def rename(self, lfns):
        """ Rename files store d on the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns        A single LFN as string or a list object with LFNs

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected    If the connection to the RSE has not yet been established
            :raises SourceAccessDenied If access to the local destination directory is denied
            :raises SourceNotFound     If access to the local destination directory is not found
            :raises FileAlreadyExists  If the new name is already present on the RSE
        """
        ret = {}
        gs = True
        if self.__connected:
            for lfn in lfns:
                # Check if source is on storage
                if not self.exists(lfn):
                    ret[lfn] = exception.SourceNotFound('File %s is not found on storage' % lfn)
                    gs = False
                # Check if target is not on storage
                elif self.exists(lfns[lfn]):
                    ret[lfn] = exception.FileAlreadyExists('File %s already exists on storage' % lfn)
                    gs = False
                else:
                    try:
                        self.__protocol.rename(lfn, lfns[lfn])
                        ret[lfn] = True
                    except Exception as e:
                        ret[lfn] = e
                        gs = False
        else:
            raise exception.RSENotConnected()
        if len(ret) == 1:
            for x in ret:
                if isinstance(ret[x], Exception):
                    raise ret[x]
                else:
                    return ret[x]
        return [gs, ret]
