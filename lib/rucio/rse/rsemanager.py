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

import os

from rucio.common import exception, utils, config


class RSEMgr(object):
    def __init__(self, path_to_credentials_file=None, server_mode=False, server_mode_with_credentials=False):
        """
            Instantiates the RSEMgr.

            :param path_to_credentials_file:    relative path from RUCIO_HOME to the JSON file where the user credentials are stored in. If not given the default path is assumed
            :param server_mode: indicates if the RSEMgr is executed in a server environment or in a client environment.
            :param server_mode_with_credentials: indicates if the RSEMgr executed in a server environment must load the RSE credentials.


            :raises ErrorLoadingCredentials:    user credentials could not be loaded
        """
        self.__rse_client = None
        self.__rses = dict()
        self.__credentials = None
        self.__server_mode = server_mode

        # Loading credentials into manager - only if not executed by the server
        if not server_mode or (server_mode and server_mode_with_credentials):
            self.__credentials = config.get_rse_credentials(path_to_credentials_file)

        if server_mode:
            from rucio.core import rse
            self.__rse_client = rse
        else:
            from rucio.client.rseclient import RSEClient
            self.__rse_client = RSEClient()

    def __select_protocol(self, rse_id, protocol_domain='ALL', operation=None, default=False, scheme=None, properties=None):
        """
            This method checks which protocol should be used depending on the operation and additional constraints like protocol domain,
            marked as default protocol, protocol scheme. If properties is given it checks if the referred protocol (scheme, hostname, and port)
            support the requested operation for the RSE. If the matching protocol for the given RSE has not been instaciated so far, a new instance will be created.

            :param rse_id: Identifier of the RSE.
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param operation: For which operation should be checked for support. Values are read, write, delete
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: an instance of a protocol supporting the requested operation and applying to the provided constraints

            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
            :raises RSENotFound: if the provided RSE coud not be found in the database.
        """
        if rse_id not in self.__rses:  # Site is accessed for the first time or no matching protocol was instanciated so far
            self.__rses[rse_id] = self.__rse_client.get_rse(rse_id)
            self.__rses[rse_id]['protocols'] = dict()
            self.__rses[rse_id]['client'] = self.__rse_client

        # A specific protocol implementation is requested
        if properties is not None:
            try:
                pid = '_'.join([properties['scheme'], properties['hostname'], str(properties['port'])])
            except KeyError:
                raise exception.InvalidObject('Properties object not including all mandatory keys i.e. scheme, hostname, port.')
            if pid in self.__rses[rse_id]['protocols']:  # Protocol already instanciated, check if requested operation is supported by it
                if operation is None:  # only lfn2pfn conversion is requested
                    return self.__rses[rse_id]['protocols'][pid]
                domains = [protocol_domain] if protocol_domain != 'ALL' else utils.rse_supported_protocol_domains()
                for domain in domains:
                    if not self.__rses[rse_id]['protocols'][pid]['domains'][domain][operation]:
                        raise exception.RSEOperationNotSupported('Protocol %s doesn\'t support %s in domain %s' % (pid, operation, domain))
                return self.__rses[rse_id]['protocols'][pid]
            else:  # Protocol not instanciated so far, check if it is known by the database
                candidates = self.__rse_client.get_protocols(rse_id, protocol_domain=protocol_domain, scheme=properties['scheme'], operation=operation)
                for protocol in candidates:
                    if (protocol['hostname'] == properties['hostname']) and (protocol['port'] == properties['port']):
                        self.__rses[rse_id]['protocols'][pid] = RSEProtocolWrapper(rse_id, protocol, self.__rses[rse_id])
                        if not self.__rses[rse_id]['deterministic']:
                            if self.__server_mode:
                                self.__rses[rse_id]['protocols'][pid].get_path = self.__rses[rse_id]['protocols'][pid].get_path_nd_server
                            else:
                                self.__rses[rse_id]['protocols'][pid].get_path = self.__rses[rse_id]['protocols'][pid].get_path_nd_client
                        return self.__rses[rse_id]['protocols'][pid]
                raise exception.RSEOperationNotSupported('Protocol %s doesn\'t support %s in domain %s' % (pid, operation, protocol_domain))

        # Check if one of the instanciated protocols supports the requested operation
        best_choice_priority = -1
        best_choice = None
        for protocol in self.__rses[rse_id]['protocols'].values():  # Potentially more then one protocol exists for this operation
            if protocol.check_protocol(protocol_domain=protocol_domain, operation=operation, default=default, scheme=scheme):
                if operation is None:  # only lfn2pfn conversion is requested
                    return protocol
                if (best_choice_priority == -1) or (best_choice_priority > protocol.get_priority(protocol_domain, operation)):
                    best_choice = protocol
        if best_choice is not None:
            return best_choice

        # So far, no protocol supported the operation -> check database for more protocols of this RSE
        candidates = self.__rse_client.get_protocols(rse=rse_id, protocol_domain=protocol_domain, default=default, operation=operation, scheme=scheme)
        for protocol in candidates:
            pid = '_'.join([protocol['scheme'], protocol['hostname'], str(protocol['port'])])
            self.__rses[rse_id]['protocols'][pid] = RSEProtocolWrapper(rse_id, protocol, self.__rses[rse_id])
            if not self.__rses[rse_id]['deterministic']:
                if self.__server_mode:
                    self.__rses[rse_id]['protocols'][pid].get_path = self.__rses[rse_id]['protocols'][pid].get_path_nd_server
                else:
                    self.__rses[rse_id]['protocols'][pid].get_path = self.__rses[rse_id]['protocols'][pid].get_path_nd_client
            return self.__rses[rse_id]['protocols'][pid]
        raise exception.RSEOperationNotSupported('No protocol matching the constraints could be found for the RSE.')

    def upload(self, rse_id, lfns, source_dir='.', protocol_domain='ALL', default=False, scheme=None, properties=None):
        """
            Uploads files to the connected storage.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. [{'filename': '1_rse_local_put.raw', 'scope': 'user.jdoe'}, {'filename': '2_rse_local_put.raw', 'scope': 'user.jdoe'}]
            :param source_dir:  path to the local directory including the source files. Default is the current working directory
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: local destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
            :raises ErrorLoadingCredentials: if no credentials for the requested RSE could be found
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        protocol = self.__select_protocol(rse_id, protocol_domain=protocol_domain, operation='write', default=default, scheme=scheme, properties=properties)
        if not protocol.is_connected():
            protocol.connect(self.__credentials.get(rse_id, {}))
        return protocol.put(lfns, source_dir)

    def download(self, rse_id, files, dest_dir='.', protocol_domain='ALL', default=False, scheme=None, properties=None):
        """
            Downloads files from the connected storage to the local file system.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param files:       a single dict or a list with dicts containing 'scope' and 'filename'
                                if LFNs are provided and additional 'pfn' if PFNs are provided.
                                E.g.  [{'filename': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'filename':'3_rse_remote_get.raw', 'scope': 'user.jdoe', 'pfn': 'file:///rucio_file/user/jdoe/5a/98/3_rse_remote_get.raw'}]
            :param dest_dir:    path where the downloaded file(s) will be stored. Default is the current working directory
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: True/False for a single file or a dict object with 'scope:filename' for LFNs or 'filename' for PFNs as keys and True or the exception as value for each file in bulk mode

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: local destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
            :raises ErrorLoadingCredentials: if no credentials for the requested RSE could be found
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        protocol = self.__select_protocol(rse_id, protocol_domain=protocol_domain, operation='read', default=default, scheme=scheme, properties=properties)
        if not protocol.is_connected():
            protocol.connect(self.__credentials.get(rse_id, {}))
        return protocol.get(files, dest_dir)

    def delete(self, rse_id, lfns, protocol_domain='ALL', default=False, scheme=None, properties=None):
        """
            Deletes a file from the connected storage.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. [{'filename': '1_rse_remote_delete.raw', 'scope': 'user.jdoe'}, {'filename': '2_rse_remote_delete.raw', 'scope': 'user.jdoe'}]
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises ServiceUnavailable: for any other reason
            :raises ErrorLoadingCredentials: if no credentials for the requested RSE could be found
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        protocol = self.__select_protocol(rse_id, protocol_domain=protocol_domain, operation='delete', default=default, scheme=scheme, properties=properties)
        if not protocol.is_connected():
            protocol.connect(self.__credentials.get(rse_id, {}))
        return protocol.delete(lfns)

    def rename(self, rse_id, files, protocol_domain='ALL', default=False, scheme=None, properties=None):
        """
            Rename files stored on the connected storage.
            Providing a list indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param files: a single dict or a list with dicts containing 'scope', 'filename', 'new_scope' and 'new_filename'
                          if LFNs are used or only 'filename' and 'new_filename' if PFNs are used. If 'new_scope' or 'new_filename' are not provided, the current one is used.
                          E.g. [{'filename': '3_rse_remote_rename.raw', 'scope': 'user.jdoe', 'new_filename': '3_rse_new.raw', 'new_scope': 'user.jdoe'},
                                {'filename': 'user/jdoe/d9/cb/9_rse_remote_rename.raw', 'new_filename': 'user/jdoe/c6/4a/9_rse_new.raw'}
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: True/False for a single file or a dict object with 'scope:filename' for LFNs or 'filename' for PFNs as keys and True or the exception as value for each file in bulk mode

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises SourceNotFound: remote source file can not be found on storage
            :raises DestinationNotAccessible: remote destination directory is not accessible
            :raises ServiceUnavailable: for any other reason
            :raises ErrorLoadingCredentials: if no credentials for the requested RSE could be found
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        protocol = self.__select_protocol(rse_id, protocol_domain=protocol_domain, operation='write', default=default, scheme=scheme, properties=properties)
        if not protocol.is_connected():
            protocol.connect(self.__credentials.get(rse_id, {}))
        return protocol.rename(files)

    def exists(self, rse_id, files, protocol_domain='ALL', default=False, scheme=None, properties=None):
        """
            Checks if the referred file is known by the connected storage.
            Providing a list of indicates the bulk mode.

            :param rse_id:      identifier of the requested storage
            :param files:       a single dict or a list with dicts containing 'scope' and 'filename'
                                if LFNs are used and only 'filename' if PFNs are used.
                                E.g. {'filename': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'filename': 'file://rucio_files/user/jdoe/5a/98/3_rse_remote_get.raw'}
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: True/False for a single file or a dict object with 'scope:filename' as keys and True or the exception as value for each file in bulk mode

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises RSEAccessDenied: storage refuses to establish a connection
            :raises ErrorLoadingCredentials: if no credentials for the requested RSE could be found
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        protocol = self.__select_protocol(rse_id, protocol_domain=protocol_domain, operation='read', default=default, scheme=scheme, properties=properties)
        if not protocol.is_connected():
            protocol.connect(self.__credentials.get(rse_id, {}))
        return protocol.exists(files)

    def lfn2pfn(self, rse_id, lfns, protocol_domain='ALL', default=False, scheme=None, properties=None):
        """
            Convert the lfn to a pfn

            :param rse_id:   identifier of the requested storage
            :param lfn:      logical file names as a dict containing 'scope' and 'filename' as keys. For bulk a list of dicts can be provided
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: URI/PFN for a single file or a dict object with scope:filename as keys and the URI for each file in bulk mode, e.g. sftp://mock.cern.ch:22/some/prefix/user/17/18/some_file.raw

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
        """
        return self.__select_protocol(rse_id, protocol_domain=protocol_domain, operation=None, default=default, scheme=scheme, properties=properties).lfn2pfn(lfns)

    def list_protocols(self, rse_id, protocol_domain='ALL', default=False, operation=None, scheme=None, properties=None):
        """
            List the supported protocols by the RSE.

            :param rse_id:      identifier of the requested storage
            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param operation: For which operation should be checked for support. Values are read, write, delete
            :param scheme: Indicating the protocol scheme to use
            :param properties: Defining the protocol to use. A protocol is identifed by scheme, hostname, and port. If this parameter is provided
                               only operation and protocol domain are considered for validation.

            :returns: A list of supported protocols.

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        return self.__rse_client.get_protocols(rse=rse_id, protocol_domain=protocol_domain, default=default, operation=operation, scheme=scheme)

    def parse_pfn(self, rse_id, pfn, protocol=None):
        """
            Checks if a PFN is feasible for a given RSE. If so it splits the pfn in its various components.

            :param rse_id: Name of the RSE
            :param pfn: PFN of the file
            :param protocol: A protocol descrciption as returned by list_protocols identifying a specific protocol supoorted be the referred RSE

            :returns: A dict with the parts known by the selected protocol e.g. scheme, hostname, prefix, path, filename

            :raises RSEFileNameNotSupported: if provided PFN is not supported by the RSE/protocol
            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
            :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
            :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
        """
        return self.__select_protocol(rse_id, scheme=pfn.split('://')[0], properties=protocol).split_pfn(pfn)


class RSEProtocolWrapper(object):
    """
        This class is a  wrapper for all registered storage. Its intention is to provide generic access to
        whatever RSE is referred during the instantiation. It further provides the basic methods
        GET (Download), PUT (Upload), Delete, and Rename files for RSEs.
    """

    def __init__(self, rse_id, protocol_properties, rse_properties):
        """
            This method instantiates a new RSE using the provided credetnials and the reffered protocol.

            :param rse_id:      identifier of the requested storage
            :param protocol_properties: a dict with all properties of the requested protocol defined in the database
            :param rse_properties: properties of the RSE for which the protocol is instanciated for

            :raises RSENotFound: if the referred storage is not found i the repository (rse_id)

        """
        self.__properties = protocol_properties
        self.__instance = None
        self.__rse_id = rse_id
        self.__rse_properties = rse_properties
        self.__didclient = None

        # Instantiating the actual protocol class
        parts = self.__properties['impl'].split('.')
        module = ".".join(parts[:-1])
        m = __import__(module)
        for comp in parts[1:]:
            m = getattr(m, comp)
        self.__instance = m(protocol_properties)

        self.__connected = False

    def split_pfn(self, pfn):
        """
            Splits the given PFN into the parts known by the protocol. During parsing the PFN is also checked for
            validity on the given RSE with the given protocol.

            As this method is strongly connected to the protocol itself it is very likely that it will be overwritten
            in the specific protocol classes.

            The default implementation parses a PFN for: scheme, hostname, port, prefix, path, filename and checks if the
            derived data matches with data provided in the RSE repository for this RSE/protocol.

            :param pfn: a fully qualified PFN

            :returns: a dict containing all known parts of the PFN for the protocol e.g. scheme, hostname, port, prefix, path, filename

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        return self.__instance.split_pfn(pfn)

    def get_properties(self):
        """ Returns the properties of the protocol instance as dict. """
        return self.__properties

    def check_protocol(self, protocol_domain, operation, default, scheme):
        """
            Checks if this protocol instance matches the provided contraints.

            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param operation: For which operation should be checked for support. Values are read, write, delete
            :param default: Inidcates if the operation must be marked as default for the protocol domain
            :param scheme: Indicating the protocol scheme to use

            :returns: True if the protocol matches, False otherwise

        """
        if ((scheme is not None) and (self.__properties['scheme'] != scheme)):  # If scheme is not matching, the protocol is not matching
            return False
        if operation is None:  # only if lfn2pfn is executed
            return True
        domains = [protocol_domain] if protocol_domain != 'ALL' else utils.rse_supported_protocol_domains()
        for domain in domains:  # Check per domain
            priority = self.__properties['domains'][domain][operation]
            if (not priority) or (default and priority != 1):  # Check support of the operation and, if reuqtested, if it is default
                return False
        return True

    def is_connected(self):
        """
            Provides the values of the connection state of the protocol instance.

            :returns: True if the protocol has established an connection, False otherwise
        """
        return self.__connected

    def get_priority(self, protocol_domain, operation):
        """
            Returns the priority this protocol inctance has for the provided operation on this RSE.

            :param protocol_domain: ID of the requested protocol domain e.g. LAN, WAN, ALL
            :param operation: For which operation should be checked for support. Values are read, write, delete

            :returns: An integer (0 = unsupported, > 0 supported, the lower the number the higher the priority, 1 = default protocol for this operation)
        """
        try:
            return self.__properties['domains'][protocol_domain][operation]
        except KeyError:
            return 0

    def lfn2pfn(self, lfns):
        """
            Transforms the logical file name (LFN) into the storage specific URI of the file on the connected storage.
            Providing a list indicates the bulk mode.

            :param lfns:        a single dict or a list with dicts containing 'scope' and 'filename'. E.g. {'filename': '1_rse_remote.raw', 'scope': 'user.jdoe'}

            :returns: PFN for a single file or a dict object with scope:filename as keys and the URI for each file in bulk mode, e.g. sftp://mock.cern.ch:22/some/prefix/user/17/18/some_file.raw

        """
        ret = {}
        lfns = [lfns] if not type(lfns) is list else lfns
        for lfn in lfns:
            path = self.get_path(lfn['filename'], lfn['scope'])
            ret[lfn['scope'] + ':' + lfn['filename']] = self.__instance.path2pfn(path)
        if len(ret) == 1:
            return ret[lfns[0]['scope'] + ':' + lfns[0]['filename']]
        return ret

    def get_path(self, lfn, scope):
        """
            Transforms the logical file name into the physical file name according to the detemernistic naming scheme defined in the protocol.

            :param lfn:     logical file name
            :param scope:   scope

            :returns: physical file name (PFN)
        """
        return self.__instance.get_path(lfn, scope)

    def get_path_nd_server(self, lfn, scope):
        """
            Transforms the logical file name into the physical file name by querying the database. This method is therefore only used for non-detemernistic RSEs.
            Due to different APIs provided at the server and at the client, two methods exist for this purpose. This one is the one to be used in server environments.

            :param lfn:     logical file name
            :param scope:   scope

            :returns: path of the requested file on the storage (protocol independent)

            :raises SourceNotFound: if the requested file was not found on the storage.
        """
        return self.__rse_properties['client'].list_replicas(self.__rse_id, filters={'scope': scope, 'name': lfn}).next()['path']  # There should not be more than one for this return

    def get_path_nd_client(self, lfn, scope):
        """
            Transforms the logical file name into the physical file name by querying the database. This method is therefore only used for non-detemernistic RSEs.
            Due to different APIs provided at the server and at the client, two methods exist for this purpose. This one is the one to be used in client environments.

            :param lfn:     logical file name
            :param scope:   scope

            :returns: path of the requested file on the storage (protocol independent)

            :raises SourceNotFound: if the requested file was not found on the storage.
        """
        # TODO: if the rse_client supports listing replicas on a specific rse (with the same signature as the core method) this method will become obsolete.
        if self.__didclient is None:
            from rucio.client.didclient import DIDClient
            self.__didclient = DIDClient()

        for replica in self.__didclient.list_replicas(scope=scope, name=lfn, schemes=[self.__properties['scheme']]):
            if replica['rse'] == self.__rse_id:
                tmp = self.split_pfn(replica['pfns'][0])
                path = ''.join([tmp['prefix'], tmp['path'], tmp['filename']]) if ('prefix' in tmp.keys()) and (tmp['prefix'] is not None) else ''.join([tmp['path'], tmp['filename']])
                return path
        raise exception.SourceNotFound('Replica %s:%s not found on RSE %s with scheme %s' % (scope, lfn, self.__rse_id, self.__properties['scheme']))

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
                    exists = self.__instance.exists(f)
                    ret[f] = exists
                elif 'scope' in f:  # a LFN is provided
                    exists = self.__instance.exists(self.get_path(f['filename'], f['scope']))
                    ret[f['scope'] + ':' + f['filename']] = exists
                else:
                    tmp = self.split_pfn(f['filename'])
                    pfn = ''.join([tmp['prefix'], tmp['path'], tmp['filename']]) if ('prefix' in tmp.keys()) and (tmp['prefix'] is not None) else ''.join([tmp['path'], tmp['filename']])
                    exists = self.__instance.exists(pfn)
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
        """
            Establishes the connection to the referred storage system.

            :param credentials: Credentials to use for authentication on the storage

            :raises RSEAccessDenied: storage refuses to establish a connection
        """
        self.__instance.connect(credentials)
        self.__connected = True

    def close(self):
        """
            Closes the connection to the storage system.
        """
        if self.__connected:
            self.__instance.close()

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
                if 'pfn' in f:
                    tmp = self.split_pfn(f['pfn'])
                    pfn = ''.join([tmp['prefix'], tmp['path'], tmp['filename']]) if ('prefix' in tmp.keys()) and (tmp['prefix'] is not None) else ''.join([tmp['path'], tmp['filename']])
                else:
                    pfn = self.get_path(f['filename'], f['scope'])
                try:
                    if not os.path.exists('%s/%s' % (dest_dir, f['scope'])):
                        os.makedirs('%s/%s' % (dest_dir, f['scope']))
                    # Each scope is stored into a separate folder
                    self.__instance.get(pfn, '%s/%s/%s' % (dest_dir, f['scope'], f['filename']))
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
        if not self.__connected:
            raise exception.RSENotConnected()
        lfns = [lfns] if not type(lfns) is list else lfns
        for lfn in lfns:
            filename = lfn['filename']
            scope = lfn['scope']
            pfn = self.get_path(filename, scope)
            # Check if file replica is already on the storage system
            if self.exists(lfn):
                ret['%s:%s' % (scope, filename)] = exception.FileReplicaAlreadyExists('File %s in scope %s already exists on storage' % (filename, scope))
                gs = False
            else:
                try:
                    self.__instance.put(filename, pfn, source_dir)
                    ret['%s:%s' % (scope, filename)] = True
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, filename)] = e
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
                pfn = self.get_path(lfn['filename'], lfn['scope'])
                try:
                    self.__instance.delete(pfn)
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
                    pfn = self.get_path(f['filename'], f['scope'])
                    new_pfn = self.get_path(f['new_filename'], f['new_scope'])
                else:
                    tmp = self.split_pfn(f['filename'])
                    pfn = ''.join([tmp['prefix'], tmp['path'], tmp['filename']]) if ('prefix' in tmp.keys()) and (tmp['prefix'] is not None) else ''.join([tmp['path'], tmp['filename']])
                    tmp = self.split_pfn(f['new_filename'])
                    new_pfn = ''.join([tmp['prefix'], tmp['path'], tmp['filename']]) if ('prefix' in tmp.keys()) and (tmp['prefix'] is not None) else ''.join([tmp['path'], tmp['filename']])
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
                        self.__instance.rename(pfn, new_pfn)
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
