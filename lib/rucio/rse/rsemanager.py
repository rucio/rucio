# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import json
import os
import hashlib

from rucio.common import exception


class RSEMgr(object):

    def __init__(self, path_to_credentials_file=None):
        """ Instantiates the RSEMgr.

            :param path_to_credentials_file: Relative path from RUCIO_HOME to the JSON file where the user credentials are stored in. If not given the default path is assumed.
        """
        self.__credentials = None

        if not path_to_credentials_file:
            if 'RUCIO_HOME' in os.environ:
                self.path_to_credentials_file = '%s/etc/rse-accounts.cfg' % os.environ['RUCIO_HOME']
            else:
                self.path_to_credentials_file = '/opt/rucio/etc/rse-accounts.cfg'
        else:
            self.path_to_credentials_file = path_to_credentials_file

        try:
            # Load all user credentials
            self.__credentials = json.load(open(self.path_to_credentials_file))
        except Exception as e:
            raise exception.ErrorLoadingCredentials(e)

    def __create_rse(self, rse_id, protocol=None):
        """ Create the according RSE object.

            :param rse_id       The identifier of the requested RSE
            :param protocol     The identifier of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost, ...

            :returns: an instance of the according RSE object
        """
        # If we go for connection pooling, this would be the place to do so
        rse = RSE(rse_id, protocol)
        rse.connect(self.__credentials[rse_id])
        return rse

    def upload(self, rse_id, lfns, source_dir='.', protocol=None):
        """ Uploads a file to the connected RSE
            Providing a list indicates the bulk mode.

            :param rse_id       The identifier of the requested RSE
            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes
            :param source_dir  Path to the local directory including the source files
            :param protocol     The name of the protocol to use. If this is not given the defined default protocol of the RSE will be used.

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises FileReplicaAlreadyExists, DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSENotFound, RSEAccessDenied, RSERepositoryNotFound, ErrorLoadingCredentials
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.put(lfns, source_dir)
        rse.close()
        return res

    def download(self, rse_id, files, dest_dir='.', protocol=None):
        """ Downloads files from the connected RSE to the local file system.

            :param rse_id       The identifier of the requested RSE
            :param files        A dict with the following structure: {'lfns': [{'scope': '', 'filename': ''}], 'pfns': []}
            :param dest_dir     Path where the downloaded file(s) will be stored
            :param protocol     The name of the protocol to use. If this is not given the defined default protocol of the RSE will be used.

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSENotFound, RSEAccessDenied, RSERepositoryNotFound, ErrorLoadingCredentials
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.get(files, dest_dir)
        rse.close()
        return res

    def delete(self, rse_id, lfns, protocol=None):
        """ Deletes a file from the connected RSE.
            Providing a list indicates the bulk mode.

            :param rse_id       The identifier of the requested RSE
            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes
            :param protocol     The name of the protocol to use. If this is not given the defined default protocol of the RSE will be used.

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises ServiceUnavailable,  RSENotFound, RSEAccessDenied, RSERepositoryNotFound, ErrorLoadingCredentials
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.delete(lfns)
        rse.close()
        return res

    def rename(self, rse_id, lfns, protocol=None):
        """ Rename files stored on the connected RSE.
            Providing a list indicates the bulk mode.

            :param rse_id       The identifier of the requested RSE
            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes
            :param protocol     The name of the protocol to use. If this is not given the defined default protocol of the RSE will be used.

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises SourceNotFound, FileReplicaAlreadyExists, DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSENotFound, RSEAccessDenied, RSERepositoryNotFound, ErrorLoadingCredentials
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.rename(lfns)
        rse.close()
        return res

    def exists(self, rse_id, lfns, protocol=None):
        """ Checks if the referred file is known by the connected RSE.
            Providing a list of indicates the bulk mode.

            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises DestinationNotAccessible, ServiceUnavailable, RSENotFound, RSEAccessDenied, RSERepositoryNotFound, ErrorLoadingCredentials
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.exists(lfns)
        rse.close()
        return res


class RSE(object):
    """ This class is a  wrapper for all registered RSEs. Its intention is to provide generic access to
        whatever RSE is referred during the instantiation. It further provides the basic methods
        GET (Download), PUT (Upload), Delete, and Rename files for RSEs.
    """

    def __init__(self, rse_id, protocol=None, path_to_repo=None):
        """  This method instantiates a new RSE using the provided credetnials and the reffered protocol.

            :param rse_id       The identifier of the requested RSE
            :param protocol     The name of the protocol to use. If this is not given the defined default protocol of the RSE will be used.

            :raises SwitchProtocol          If the referred protocol is not supported by the referred RSE
            :raises RSENotFound             If the referred RSE is not found insode the RSERepository
            :raises RSERepositoryNotFound   If the RSERepository can be accessed
        """

        self.__protocol = None
        self.__id = rse_id
        self.__props = None
        self.__connected = False
        if not path_to_repo:
            if 'RUCIO_HOME' in os.environ:
                self.__path_to_repo = '%s/etc/rse_repository.json' % os.environ['RUCIO_HOME']  # path_to_repo: path to the RSE repository used to look-up a specific RSE
            else:
                self.__path_to_repo = '/opt/rucio/etc/rse_repository.json'
        else:
            self.__path_to_repo = path_to_repo

        # Loading repository data
        try:
            f = open(self.__path_to_repo)
            repdata = json.load(f)
            f.close()
        except Exception as e:
            raise exception.RSERepositoryNotFound({'RSERepository': self.__path_to_repo, 'Exception': e})

        try:
            self.__props = repdata[self.__id]
        except Exception:
            raise exception.RSENotFound({'ID': rse_id})

        self.__props['protocol'] = {}
        # Check if user requested a specific protocol?
        self.__props['protocol']['id'] = protocol
        if self.__props['protocol']['id'] is None:
            self.__props['protocol']['id'] = self.__props['protocols']['default']
        # Check if selected protocol is supported
        if self.__props['protocol']['id'] not in self.__props['protocols']['supported']:
            raise exception.SwitchProtocol(self.__props['protocols']['supported'].keys())

        # Copy selected protocol attributes into new dict
        for i in self.__props['protocols']['supported'][self.__props['protocol']['id']]:
            self.__props['protocol'][i] = self.__props['protocols']['supported'][self.__props['protocol']['id']][i]

        # If protcol doesn't define a prefix get the default one for all protocols at this storage
        if 'prefix' not in self.__props['protocol']:
            self.__props['protocol']['prefix'] = self.__props['protocols']['prefix']

        # Instantiating the actual protocol class
        parts = self.__props['protocol']['impl'].split('.')
        module = ".".join(parts[:-1])
        m = __import__(module)
        for comp in parts[1:]:
            m = getattr(m, comp)
        self.__protocol = m(self.__props)

    def lfn2uri(self, lfns):
        """ Transforms the logical file name (LFN) into the RSE specific URI of the file on the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes

            :returns: URI of the physical file or a dict object with LFN (key) and the URI (value) in bulk mode
        """
        ret = {}
        lfns = [lfns] if not type(lfns) is list else lfns
        for lfn in lfns:
            pfn = self.__lfn2pfn(lfn['filename'], lfn['scope'])
            ret[lfn['scope'] + ':' + lfn['filename']] = self.__protocol.pfn2uri(pfn)
        if len(ret) == 1:
            return ret[lfns[0]['scope'] + ':' + lfns[0]['filename']]
        return ret

    def __lfn2pfn(self, lfn, scope):
        """ Transforms the logical file name into the physical file name.

            :param lfn The logical file name
            :param scope The selected user scope

            :returns: The physical filen name (including scope)
        """
        # Agreed naming convention: [scope1]/[scope2]/[first_two_hash]/[second_two_hash]/[lfn]
        # e.g. user/jdoe/fb/6a/4_rse_remote_get.raw
        hstr = hashlib.md5('%s:%s' % (scope, lfn)).hexdigest()
        correctedscope = "/".join(scope.split('.'))
        return '%s/%s/%s/%s' % (correctedscope, hstr[0:2], hstr[2:4], lfn)

    def exists(self, files):
        """ Checks if the provided LFN is known by the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes
            :param new         Checkes if the properties filename/scope are used (False) or new_filename/new_scope (True)

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected         If the connection to the RSE has not yet been established
        """
        ret = {}
        gs = True
        if self.__connected:
            files = [files] if not type(files) is list else files
            for f in files:
                exists = None
                if type(f) is str:
                    exists = self.__protocol.exists(f)
                    ret[f] = exists
                elif 'scope' in f:  # a LFN is provided
                    exists = self.__protocol.exists(self.__lfn2pfn(f['filename'], f['scope']))
                    ret[f['scope'] + ':' + f['filename']] = exists
                else:
                    exists = self.__protocol.exists(f['filename'])
                    ret[f['filename']] = exists
                if not exists:
                    gs = False
        else:
            raise exception.RSENotConnected()
        if len(ret) == 1:
            for x in ret:
                return ret[x]
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

    def get(self, files, dest_dir='.'):
        """ Copy a file (LFN) from the connected RSE to the local file system.

            :param files       A dict with the following structure: {'lfns': [{'scope': '', 'filename': ''}], 'pfns': []}
            :param dest_dir     Path where the downloaded file(s) will be stored

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected, SourceNotFound, DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        ret = {}
        gs = True
        if self.__connected:
            files = [files] if not type(files) is list else files
            for f in files:
                pfn = f['pfn'] if 'pfn' in f else self.__lfn2pfn(f['filename'], f['scope'])
                try:
                    if not os.path.exists('%s/%s' % (dest_dir, f['scope'])):
                        os.makedirs('%s/%s' % (dest_dir, f['scope']))
                    # Each scope is stored into a separate folder
                    self.__protocol.get(pfn, '%s/%s/%s' % (dest_dir, f['scope'], f['filename']))
                    ret['%s:%s' % (f['scope'], f['filename'])] = True
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (f['scope'], f['filename'])] = e
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

            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes
            :param source_dir  Path to the local directory including the source files

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises FileReplicaAlreadyExists, RSENotConnected, SourceNotFound, DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                filename = lfn['filename']
                scope = lfn['scope']
                # Check if file replica is already on the storage system
                pfn = self.__lfn2pfn(filename, scope)
                if self.exists(lfn):
                    ret['%s:%s' % (scope, filename)] = exception.FileReplicaAlreadyExists('File %s already exists on storage' % lfn['filename'])
                    gs = False
                else:
                    try:
                        self.__protocol.put(lfn['filename'], pfn, source_dir)
                        ret['%s:%s' % (scope, filename)] = True
                    except Exception as e:
                        gs = False
                        ret['%s:%s' % (scope, filename)] = e
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

            :param lfns        A single LFN as dict or a list object with dicts. Each dict has 'scope' and 'filename' as attributes

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected, SourceNotFound
        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                pfn = self.__lfn2pfn(lfn['filename'], lfn['scope'])
                try:
                    self.__protocol.delete(pfn)
                    ret['%s:%s' % (lfn['scope'], lfn['filename'])] = True
                except Exception as e:
                    ret['%s:%s' % (lfn['scope'], lfn['filename'])] = e
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

    def rename(self, files):
        """ Rename files stored on the connected RSE.
            Providing a list of LFNs indicates the bulk mode.

            :param lfns       A list of dict object with the current filename (filename), the current scope (scope) in a dict and the new filename (new_filename) and optional the new scope (new_scope)

            :returns: True/False for a the file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises FileReplicaAlreadyExists, RSENotConnected, SourceNotFound
        """
        ret = {}
        gs = True
        files = [files] if not type(files) is list else files
        if self.__connected:
            for f in files:
                pfn = None
                new_pfn = None
                key = None
                if 'scope' in f:  # LFN is provided
                    key = '%s:%s' % (f['scope'], f['filename'])
                    # Check if new filename is provided
                    if not 'new_filename' in f:
                        f['new_filename'] = f['filename']
                    # Check if new scope is provided
                    if not 'new_scope' in f:
                        f['new_scope'] = f['scope']
                    pfn = self.__lfn2pfn(f['filename'], f['scope'])
                    new_pfn = self.__lfn2pfn(f['new_filename'], f['new_scope'])
                else:
                    pfn = f['filename']
                    new_pfn = f['new_filename']
                    key = f['filename']
                # Check if source is on storage
                if not self.exists(pfn):
                    ret[key] = exception.SourceNotFound('File %s not found on storage' % (pfn))
                    gs = False
                # Check if target is not on storage
                elif self.exists(new_pfn):
                    ret[key] = exception.FileReplicaAlreadyExists('File %s already exists on storage' % (new_pfn))
                    gs = False
                else:
                    try:
                        self.__protocol.rename(pfn, new_pfn)
                        ret[key] = True
                    except Exception as e:
                        ret[key] = e
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
