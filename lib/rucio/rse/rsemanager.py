# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import json
import os
import hashlib

from rucio.common import exception


class RSEMgr(object):
    def __init__(self, path_to_credentials_file=None):
        """
            Instantiates the RSEMgr.

            :param path_to_credentials_file:    relative path from RUCIO_HOME to the JSON file where the user credentials are stored in. If not given the default path is assumed

            :raises ErrorLoadingCredentials:    user credentials could not be loaded

        """
        self.__credentials_file = path_to_credentials_file

    def __create_rse(self, rse_id, protocol=None, auto_connect=True):
        """
            Create the according RSE object.

            :param rse_id:      identifier of the requested storage
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used
            :param auto_connect: indicates if the connection to the RSE should be established automatically (True) or not (False)

            :returns:           an instance of the according RSE object

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)
            :raises RSEAccessDenied: storage refuses to establish a connection
        """
        # If we go for connection pooling, this would be the place to do so
        rse = RSE(rse_id, protocol)
        if auto_connect:
            rse.connect(self.__credentials_file)
        return rse

    def upload(self, rse_id, lfns, source_dir='.', protocol=None):
        """
            Uploads files to the connected storage.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. [{'filename': '1_rse_local_put.raw', 'scope': 'user.jdoe'}, {'filename': '2_rse_local_put.raw', 'scope': 'user.jdoe'}]
            :param source_dir:  path to the local directory including the source files. Default is the current working directory
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: local source file can not be found
            :raises DestinationNotAccessible: remote destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.put(lfns, source_dir)
        rse.close()
        return res

    def download(self, rse_id, files, dest_dir='.', protocol=None):
        """
            Downloads files from the connected storage to the local file system.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param files:       a single dict or a list with dicts containing 'scope' and 'filename'
                                if LFNs are provided and additional 'pfn' if PFNs are provided.
                                E.g.  [{'filename': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'filename':'3_rse_remote_get.raw', 'scope': 'user.jdoe', 'pfn': 'user/jdoe/5a/98/3_rse_remote_get.raw'}]
            :param dest_dir:    path where the downloaded file(s) will be stored. Default is the current working directory
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used

            :returns: True/False for a single file or a dict object with 'scope:filename' for LFNs or 'filename' for PFNs as keys and True or the exception as value for each file in bulk mode

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: local destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.get(files, dest_dir)
        rse.close()
        return res

    def delete(self, rse_id, lfns, protocol=None):
        """
            Deletes a file from the connected storage.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. [{'filename': '1_rse_remote_delete.raw', 'scope': 'user.jdoe'}, {'filename': '2_rse_remote_delete.raw', 'scope': 'user.jdoe'}]
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises ServiceUnavailable: for any other reason
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.delete(lfns)
        rse.close()
        return res

    def rename(self, rse_id, files, protocol=None):
        """
            Rename files stored on the connected storage.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param files: a single dict or a list with dicts containing 'scope', 'filename', 'new_scope' and 'new_filename'
                          if LFNs are used or only 'filename' and 'new_filename' if PFNs are used. If 'new_scope' or 'new_filename' are not provided, the current one is used.
                          E.g. [{'filename': '3_rse_remote_rename.raw', 'scope': 'user.jdoe', 'new_filename': '3_rse_new.raw', 'new_scope': 'user.jdoe'},
                                {'filename': 'user/jdoe/d9/cb/9_rse_remote_rename.raw', 'new_filename': 'user/jdoe/c6/4a/9_rse_new.raw'}
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used

            :returns: True/False for a single file or a dict object with 'scope:filename' for LFNs or 'filename' for PFNs as keys and True or the exception as value for each file in bulk mode

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: remote destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.rename(files)
        rse.close()
        return res

    def exists(self, rse_id, files, protocol=None):
        """
            Checks if the referred file is known by the connected storage.
            Providing a list of indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param files:       a single dict or a list with dicts containing 'scope' and 'filename'
                                if LFNs are used and only 'filename' if PFNs are used.
                                E.g. {'filename': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'filename': 'user/jdoe/5a/98/3_rse_remote_get.raw'}
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)
            :raises RSEAccessDenied: storage refuses to establish a connection
        """
        rse = self.__create_rse(rse_id, protocol)
        res = rse.exists(files)
        rse.close()
        return res

    def lfn2pfn(self, rse_id, lfn, scope, protocol):
        """
            Convert the lfn to a pfn

            :param rse_id:   identifier of the requested storage
            :param lfn:      logical file name
            :param scope:    scope
            :param protocol: protocol

            :returns: A list of supported protocols.

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
        """
        rse = self.__create_rse(rse_id, protocol=protocol, auto_connect=False)
        return rse.lfn2pfn(lfns=[{'scope': scope, 'filename': lfn}, ])

    def list_protocols(self, rse_id):
        """
            List the supported protocols by the RSE.

            :param rse_id:      identifier of the requested storage

            :returns: A list of supported protocols.

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
        """
        rse = self.__create_rse(rse_id, auto_connect=False)
        return rse.list_protocols()


class RSE(object):
    """
        This class is a  wrapper for all registered storage. Its intention is to provide generic access to
        whatever RSE is referred during the instantiation. It further provides the basic methods
        GET (Download), PUT (Upload), Delete, and Rename files for RSEs.
    """

    def __init__(self, rse_id, protocol=None, path_to_repo=None):
        """
            This method instantiates a new RSE using the provided credetnials and the reffered protocol.

            :param rse_id:      identifier of the requested storage
            :param protocol:    identifier (class name) of the preferred protocol e.g. S3.Default, S3.Swift, SFTP.Localhost. If not given the default for the storage will be used
            :param path_to_repo: path to the RSE-repository file. If not given the file '/opt/rucio/etc/rse_repository.json' will be used

            :raises RSERepositoryNotFound: if RSE-repository file is not found (path_to_repo)
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises SwitchProtocol: if the specified protocol is not supported by the provided storage (protocol)

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
            print self.__path_to_repo
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

    def list_protocols(self):
        """
            List the supported protocols by the RSE.

            :returns: A list of supported protocols.
        """
        protocols = list()
        if 'default' in self.__props['protocols']:
            protocols.append(self.__props['protocols']['default'])
        if 'supported' in self.__props['protocols']:
            for protocol in self.__props['protocols']['supported']:
                if protocol not in protocols:
                    protocols.append(protocol)
        return protocols

    def lfn2pfn(self, lfns):
        """
            Transforms the logical file name (LFN) into the storage specific URI of the file on the connected storage.
            Providing a list indicates the bulk mode.

            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. {'filename': '1_rse_remote.raw', 'scope': 'user.jdoe'}

            :returns: URI for a single file or a dict object with scope:filename as keys and the URI for each file in bulk mode

        """
        ret = {}
        lfns = [lfns] if not type(lfns) is list else lfns
        for lfn in lfns:
            pfn = self.__deterministic_lfn(lfn['filename'], lfn['scope'])
            ret[lfn['scope'] + ':' + lfn['filename']] = self.__protocol.pfn2uri(pfn)
        if len(ret) == 1:
            return ret[lfns[0]['scope'] + ':' + lfns[0]['filename']]
        return ret

    def __deterministic_lfn(self, lfn, scope):
        """
            Transforms the logical file name into the physical file name.

            :param lfn:     logical file name
            :param scope:   scope

            :returns: physical file name (PFN)
        """
        # Agreed naming convention: [scope1]/[scope2]/[first_two_hash]/[second_two_hash]/[lfn]
        # e.g. user/jdoe/fb/6a/4_rse_remote_get.raw
        hstr = hashlib.md5('%s:%s' % (scope, lfn)).hexdigest()
        correctedscope = "/".join(scope.split('.'))
        return '%s/%s/%s/%s' % (correctedscope, hstr[0:2], hstr[2:4], lfn)

    def exists(self, files):
        """
            Checks if a file is present at the connected storage.
            Providing a list indicates the bulk mode.

            :param files: a single dict or a list with dicts containing 'scope' and 'filename'
                          if LFNs are used and only 'filename' if PFNs are used.
                          E.g. {'filename': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'filename': 'user/jdoe/5a/98/3_rse_remote_get.raw'}

            :returns: True/False for a single file or a dict object with 'scope:filename' for LFNs or 'filename' for PFNs as keys and True or the exception as value for each file in bulk mode

            :raises RSENotConnected: no connection to a specific storage has been established

        """
        ret = {}
        gs = True
        if self.__connected:
            files = [files] if not type(files) is list else files
            for f in files:
                exists = None
                if type(f) is str or (type(f) is unicode):
                    exists = self.__protocol.exists(f)
                    ret[f] = exists
                elif 'scope' in f:  # a LFN is provided
                    exists = self.__protocol.exists(self.__deterministic_lfn(f['filename'], f['scope']))
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

    def connect(self, path_to_credentials_file=None):
        """
            Establishes the connection to the referred storage system.

            :param path_to_credentials_file:    relative path from RUCIO_HOME to the JSON file where the user credentials are stored in. If not given the default path is assumed
            :param credentials:   Credentials

            :raises RSEAccessDenied: storage refuses to establish a connection

        """
        if self.__connected:
            return
        self.__credentials = None
        path = ''
        if path_to_credentials_file:  # Use specific file for this connect
            path = path_to_credentials_file
        else:  # Use file defined in th RSEMgr
            if 'RUCIO_HOME' in os.environ:
                path = '%s/etc/rse-accounts.cfg' % os.environ['RUCIO_HOME']
            else:
                path = '/opt/rucio/etc/rse-accounts.cfg'
        try:
            # Load all user credentials
            with open(path) as f:
                self.__credentials = json.load(f)
        except Exception as e:
            raise exception.ErrorLoadingCredentials(e)

        if not self.__id in self.__credentials:
            self.__credentials[self.__id] = dict()
        if not self.__connected:
            self.__protocol.connect(self.__credentials[self.__id])
            self.__connected = True

    def close(self):
        """
            Closes the connection to the storage system
        """
        if self.__connected:
            self.__protocol.close()

    def get(self, files, dest_dir='.'):
        """
            Copy a file from the connected storage to the local file system.
            Providing a list indicates the bulk mode.


            :param files:       a single dict or a list with dicts containing 'scope' and 'filename'
                                if LFNs are provided and additional 'pfn' if PFNs are provided.
                                E.g.  [{'filename': '2_rse_remote_get.raw', 'scope': 'user.jdoe'},
                                       {'filename':'3_rse_remote_get.raw', 'scope': 'user.jdoe', 'pfn': 'user/jdoe/5a/98/3_rse_remote_get.raw'}]
            :param dest_dir:    path to the directory where the downloaded files will be stored. For each scope a seperate subdirectory is created

            :returns: True/False for a single file or a dict object with 'scope:filename' for LFNs or 'filename' for PFNs as keys and True or the exception as value for each file in bulk mode

            :raises RSENotConnected: no connection to a specific storage has been established
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: local destination directory is not accessible
            :raises ServiceUnavailable: for any other reason

        """
        ret = {}
        gs = True
        if self.__connected:
            files = [files] if not type(files) is list else files
            for f in files:
                pfn = f['pfn'] if 'pfn' in f else self.__deterministic_lfn(f['filename'], f['scope'])
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
        """
            Uploads a file to the connected storage.
            Providing a list indicates the bulk mode.

            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. [{'filename': '1_rse_local_put.raw', 'scope': 'user.jdoe'}, {'filename': '2_rse_local_put.raw', 'scope': 'user.jdoe'}]
            :param source_dir:  path to the local directory including the source files

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSENotConnected: no connection to a specific storage has been established
            :raises SourceNotFound: local source file can not be found
            :raises DestinationNotAccessible: remote destination directory is not accessible
            :raises ServiceUnavailable: for any other reason

        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                filename = lfn['filename']
                scope = lfn['scope']
                # Check if file replica is already on the storage system
                pfn = self.__deterministic_lfn(filename, scope)
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
        """
            Delete a file from the connected storage.
            Providing a list indicates the bulk mode.

            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. [{'filename': '1_rse_remote_delete.raw', 'scope': 'user.jdoe'}, {'filename': '2_rse_remote_delete.raw', 'scope': 'user.jdoe'}]

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSENotConnected: no connection to a specific storage has been established
            :raises SourceNotFound: remote source file can not be found on storage
            :raises ServiceUnavailable: for any other reason

        """
        ret = {}
        gs = True
        if self.__connected:
            lfns = [lfns] if not type(lfns) is list else lfns
            for lfn in lfns:
                pfn = self.__deterministic_lfn(lfn['filename'], lfn['scope'])
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
        """
            Rename files stored on the connected storage.
            Providing a list indicates the bulk mode.

            :param files: a single dict or a list with dicts containing 'scope', 'filename', 'new_scope' and 'new_filename'
                          if LFNs are used or only 'filename' and 'new_filename' if PFNs are used.
                          If 'new_scope' or 'new_filename' are not provided, the current one is used.
                          E.g. [{'filename': '3_rse_remote_rename.raw', 'scope': 'user.jdoe', 'new_filename': '3_rse_new.raw', 'new_scope': 'user.jdoe'},
                                {'filename': 'user/jdoe/d9/cb/9_rse_remote_rename.raw', 'new_filename': 'user/jdoe/c6/4a/9_rse_new.raw'}

            :returns: True/False for a single file or a dict object with LFN (key) and True/False (value) in bulk mode

            :raises RSENotConnected: no connection to a specific storage has been established
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: remote destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
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
                    pfn = self.__deterministic_lfn(f['filename'], f['scope'])
                    new_pfn = self. __deterministic_lfn(f['new_filename'], f['new_scope'])
                else:
                    pfn = f['filename']
                    new_pfn = f['new_filename']
                    key = f['filename']
                # Check if target is not on storage
                if self.exists(new_pfn):
                    ret[key] = exception.FileReplicaAlreadyExists('File %s already exists on storage' % (new_pfn))
                    gs = False
                # Check if source is on storage
                elif not self.exists(pfn):
                    ret[key] = exception.SourceNotFound('File %s not found on storage' % (pfn))
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
