# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015

import copy
import os

from urlparse import urlparse

from rucio.common import exception, utils

DEFAULT_PROTOCOL = 1


def get_rse_info(rse, session=None):
    """ Returns all protocol related RSE attributes.

        :param rse: Name of the reqeusted RSE
        :param session: The eventual database session.


        :returns: a dict object with the following attributes:
                    id              ...     an internal identifier
                    rse             ...     the name of the RSE as string
                    type            ...     the storage type odf the RSE e.g. DISK
                    volatile        ...     boolean indictaing if the RSE is volatile
                    deteministic    ...     boolean indicating of the nameing of the files follows the defined determinism
                    domain          ...     indictaing the domain that should bes assumed for transfers. Values are 'ALL', 'LAN', or 'WAN'
                    delete_protocol ...     the protocol to be used for deletion, if rsemanager.DEFAULT_PROTOCOL, the default of the site will be selected automatically
                    write_protocol  ...     the protocol to be used for deletion, if rsemanager.DEFAULT_PROTOCOL, the default of the site will be selected automatically
                    read_protocol   ...     the protocol to be used for deletion, if rsemanager.DEFAULT_PROTOCOL, the default of the site will be selected automatically
                    protocols       ...     all supported protocol in form of alist of dict objects with the followig structure
                        scheme              ...     protocol scheme e.g. http, srm, ...
                        hostname            ...     hostname of the site
                        prefix              ...     path to the folder where the files are stored
                        port                ...     port used for this protocol
                        impl                ...     naming the python class of the protocol implementation
                        extended_attributes ...     additional information for the protocol
                        domains             ...     a dict naming each domain and the priority of the protocol for each operation (lower is better, zero is not upported)

        :raises RSENotFound: if the provided RSE coud not be found in the database.
    """
    # __request_rse_info will be assigned when the module is loaded as it depends on the rucio environment (server or client)
    # __request_rse_info, rse_region are defined in /rucio/rse/__init__.py
    rse_info = rse_region.get(str(rse))   # NOQA
    if not rse_info:  # no cached entry found
        rse_info = __request_rse_info(str(rse), session=session)  # NOQA
        rse_region.set(str(rse), rse_info)  # NOQA
    return rse_info


def select_protocol(rse_settings, operation, scheme=None):
    operation = operation.lower()
    candidates = copy.copy(rse_settings['protocols'])
    if type(rse_settings['domain']) is not list:
        raise exception.RSEProtocolDomainNotSupported('Domain setting must be list.')

    for d in rse_settings['domain']:
        if d not in utils.rse_supported_protocol_domains():
            raise exception.RSEProtocolDomainNotSupported('Domain %s is not supported by Rucio.' % d)

    tbr = list()
    for protocol in candidates:
        # Check if scheme given and filter if so
        if scheme:
            if not isinstance(scheme, list):
                scheme = scheme.split(',')
            if protocol['scheme'] not in scheme:
                tbr.append(protocol)
                continue
        # Check if operation in domain is supported
        for d in rse_settings['domain']:
            if protocol['domains'][d][operation] == 0:
                tbr.append(protocol)
                break
    for r in tbr:
        candidates.remove(r)

    if not len(candidates):
        raise exception.RSEProtocolNotSupported('No protocol for provided settings found : %s.' % str(rse_settings))

    # Select the one with the highest priority
    candidates = sorted(candidates, key=lambda k: k['scheme'])
    best_choice = candidates[0]
    candidates.remove(best_choice)
    domain = rse_settings['domain'][0]
    for p in candidates:
        if p['domains'][domain][operation] < best_choice['domains'][domain][operation]:
            best_choice = p
    return best_choice


def create_protocol(rse_settings, operation, scheme=None):
    """ Instanciates the protocol defined for the given operation.

        :param rse_attr: RSE attributes
        :param operation: the intended operation for this protocol
        :param scheme: optional filter if no specific protocol is defined in rse_setting for the provided operation

        :returns: an instance of the requested protocol
    """

    # Verify feasibility of Protocol
    operation = operation.lower()
    if operation not in utils.rse_supported_protocol_operations():
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)
    rse_settings['domain'] = [rse_settings['domain']] if type(rse_settings['domain']) is not list else rse_settings['domain']
    for domain in rse_settings['domain']:
        if domain.lower() not in utils.rse_supported_protocol_domains():
            raise exception.RSEOperationNotSupported('Domain %s not supported' % rse_settings['domain'])

    if rse_settings['%s_protocol' % operation] == DEFAULT_PROTOCOL:
        protocol_attr = select_protocol(rse_settings, operation, scheme)
    else:
        protocol_attr = rse_settings['%s_protocol' % operation]
        for d in rse_settings['domain']:
            if protocol_attr['domains'][d][operation] == 0:
                raise exception.RSEOperationNotSupported('Operation %s for domain %s not supported by %s' % (operation, rse_settings['domain'], protocol_attr['scheme']))

    # Instanciate protocol
    comp = protocol_attr['impl'].split('.')
    mod = __import__('.'.join(comp[:-1]))
    for n in comp[1:]:
        try:
            mod = getattr(mod, n)
        except AttributeError:
            print 'Protocol implementation not found'
            raise  # TODO: provide proper rucio exception
    protocol = mod(protocol_attr, rse_settings)
    return protocol


def lfns2pfns(rse_settings, lfns, operation='write', scheme=None):
    """
        Convert the lfn to a pfn

        :param lfns:        logical file names as a dict containing 'scope' and 'name' as keys. For bulk a list of dicts can be provided
        :param protocol:    instance of the protocol to be used to create the PFN

        :returns: a dict with scope:name as key and the PFN as value

    """
    return create_protocol(rse_settings, operation, scheme).lfns2pfns(lfns)


def parse_pfns(rse_settings, pfns, operation='read'):
    """
        Checks if a PFN is feasible for a given RSE. If so it splits the pfn in its various components.

        :param pfns:        list of PFNs
        :param protocol:    instance of the protocol to be used to create the PFN

        :returns: A dict with the parts known by the selected protocol e.g. scheme, hostname, prefix, path, name

        :raises RSEFileNameNotSupported: if provided PFN is not supported by the RSE/protocol
        :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
        :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
        :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
    """
    if len(set([urlparse(pfn).scheme for pfn in pfns])) != 1:
        raise ValueError('All PFNs must provide the same protocol scheme')
    return create_protocol(rse_settings, operation, urlparse(pfns[0]).scheme).parse_pfns(pfns)


def download(rse_settings, files, dest_dir=None, printstatements=False):
    """
        Copy a file from the connected storage to the local file system.
        Providing a list indicates the bulk mode.


        :param rse_settings:    RSE to use
        :param files:           a single dict or a list with dicts containing 'scope' and 'name'
                                if LFNs are provided and additional 'pfn' if PFNs are provided.
                                E.g.  [{'name': '2_rse_remote_get.raw', 'scope': 'user.jdoe'},
                                       {'name':'3_rse_remote_get.raw', 'scope': 'user.jdoe', 'pfn': 'user/jdoe/5a/98/3_rse_remote_get.raw'}]
        :param dest_dir:        path to the directory where the downloaded files will be stored. If not given, each scope is represented by its own directory.

        :returns: True/False for a single file or a dict object with 'scope:name' for LFNs or 'name' for PFNs as keys and True or the exception as value for each file in bulk mode

        :raises SourceNotFound: remote source file can not be found on storage
        :raises DestinationNotAccessible: local destination directory is not accessible
        :raises FileConsistencyMismatch: the checksum of the downloaded file does not match the provided one
        :raises ServiceUnavailable: for any other reason

    """
    ret = {}
    gs = True  # gs represents the global status which inidcates if every operation workd in bulk mode
    protocol = create_protocol(rse_settings, 'read')
    protocol.connect()

    files = [files] if not type(files) is list else files
    for f in files:
        pfn = f['pfn'] if 'pfn' in f else protocol.lfns2pfns(f).values()[0]
        target_dir = "./%s" % f['scope'] if dest_dir is None else dest_dir
        try:
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            # Each scope is stored into a separate folder
            finalfile = '%s/%s' % (target_dir, f['name'])
            # Check if the file already exists, if not download and validate it
            if not os.path.isfile(finalfile):
                if 'adler32' in f:
                    tempfile = '%s/%s.part' % (target_dir, f['name'])
                    if os.path.isfile(tempfile):
                        if printstatements:
                            print '%s already exists, probably from a failed attempt. Will remove it' % (tempfile)
                        os.unlink(tempfile)
                    protocol.get(pfn, tempfile)
                    if printstatements:
                        print 'File downloaded. Will be validated'
                    localchecksum = utils.adler32(tempfile)
                    if localchecksum == f['adler32']:
                        if printstatements:
                            print 'File validated'
                        os.rename(tempfile, finalfile)
                    else:
                        os.unlink(tempfile)
                        raise exception.FileConsistencyMismatch('Checksum mismatch : local %s vs recorded %s' % (str(localchecksum), str(f['adler32'])))
                else:
                    protocol.get(pfn, '%s/%s' % (target_dir, f['name']))
                ret['%s:%s' % (f['scope'], f['name'])] = True
            else:
                ret['%s:%s' % (f['scope'], f['name'])] = True
        except Exception as e:
            gs = False
            ret['%s:%s' % (f['scope'], f['name'])] = e

    protocol.close()
    if len(ret) == 1:
        for x in ret:
            if isinstance(ret[x], Exception):
                raise ret[x]
            else:
                return ret[x]
    return [gs, ret]


def exists(rse_settings, files):
    """
        Checks if a file is present at the connected storage.
        Providing a list indicates the bulk mode.

        :param files: a single dict or a list with dicts containing 'scope' and 'name'
                      if LFNs are used and only 'name' if PFNs are used.
                      E.g. {'name': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'name': 'user/jdoe/5a/98/3_rse_remote_get.raw'}

        :returns: True/False for a single file or a dict object with 'scope:name' for LFNs or 'name' for PFNs as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
    """
    ret = {}
    gs = True  # gs represents the global status which inidcates if every operation workd in bulk mode

    protocol = create_protocol(rse_settings, 'read')
    protocol.connect()

    files = [files] if not type(files) is list else files
    for f in files:
        exists = None
        if (type(f) is str) or (type(f) is unicode):
            exists = protocol.exists(f)
            ret[f] = exists
        elif 'scope' in f:  # a LFN is provided
            exists = protocol.exists(protocol.lfns2pfns(f).values()[0])
            ret[f['scope'] + ':' + f['name']] = exists
        else:
            exists = protocol.exists(f['name'])
            ret[f['name']] = exists
        if not exists:
            gs = False

    protocol.close()
    if len(ret) == 1:
        for x in ret:
            return ret[x]
    return [gs, ret]


def upload(rse_settings, lfns, source_dir=None):
    """
        Uploads a file to the connected storage.
        Providing a list indicates the bulk mode.

        :param lfns:        a single dict or a list with dicts containing 'scope' and 'name'. E.g. [{'name': '1_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 42, 'adler32': '87HS3J968JSNWID'},
                                                                                                    {'name': '2_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 4711, 'adler32': 'RSSMICETHMISBA837464F'}]
        :param source_dir:  path to the local directory including the source files

        :returns: True/False for a single file or a dict object with 'scope:name' as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: local source file can not be found
        :raises DestinationNotAccessible: remote destination directory is not accessible
        :raises ServiceUnavailable: for any other reason
    """
    ret = {}
    gs = True  # gs represents the global status which inidcates if every operation workd in bulk mode

    protocol = create_protocol(rse_settings, 'write')
    protocol.connect()
    protocol_delete = create_protocol(rse_settings, 'delete')
    protocol_delete.connect()

    lfns = [lfns] if not type(lfns) is list else lfns
    for lfn in lfns:
        name = lfn['name']
        scope = lfn['scope']
        if 'adler32' not in lfn:
            gs = False
            ret['%s:%s' % (scope, name)] = exception.RucioException('Missing checksum for file %s:%s' % (lfn['scope'], lfn['name']))
            continue
        if 'filesize' not in lfn:
            gs = False
            ret['%s:%s' % (scope, name)] = exception.RucioException('Missing filesize for file %s:%s' % (lfn['scope'], lfn['name']))
            continue

        pfn = protocol.lfns2pfns(lfn).values()[0]
        # Check if file replica is already on the storage system
        if protocol.exists(pfn):
            ret['%s:%s' % (scope, name)] = exception.FileReplicaAlreadyExists('File %s in scope %s already exists on storage' % (name, scope))
            gs = False
        else:
            if protocol.exists('%s.rucio.upload' % pfn):  # Check for left over of previous unsuccessful attempts
                try:
                    protocol_delete.delete('%s.rucio.upload', protocol_delete.lfns2pfns(lfn).values()[0])
                except Exception as e:
                    ret['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('Unable to remove temporary file %s.rucio.upload: %s' % (pfn, str(e)))
            try:  # Try uploading file
                protocol.put(name, '%s.rucio.upload' % pfn, source_dir)
            except Exception as e:
                gs = False
                ret['%s:%s' % (scope, name)] = e
                continue

            valid = None
            try:  # Get metadata of file to verify if upload was successful
                stats = protocol.stat('%s.rucio.upload' % pfn)
                if ('adler32' in stats) and ('adler32' in lfn):
                    valid = stats['adler32'] == lfn['adler32']
                if (valid is None) and ('filesize' in stats) and ('filesize' in lfn):
                    valid = stats['filesize'] == lfn['filesize']
            except NotImplementedError:
                valid = True  # If the protocol doesn't support stat of a file, we agreed on assuming that the file was uploaded without error
            except Exception as e:
                gs = False
                ret['%s:%s' % (scope, name)] = e
                continue

            if valid:  # The upload finished successful and the file can be renamed
                try:
                    protocol.rename('%s.rucio.upload' % pfn, pfn)
                    ret['%s:%s' % (scope, name)] = True
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, name)] = e
            else:
                gs = False
                ret['%s:%s' % (scope, name)] = exception.RucioException('Replica %s is corrupted.' % pfn)

    protocol.close()
    protocol_delete.close()
    if len(ret) == 1:
        for x in ret:
            if isinstance(ret[x], Exception):
                raise ret[x]
            else:
                return ret[x]
    return [gs, ret]


def delete(rse_settings, lfns):
    """
        Delete a file from the connected storage.
        Providing a list indicates the bulk mode.

        :param lfns:        a single dict or a list with dicts containing 'scope' and 'name'. E.g. [{'name': '1_rse_remote_delete.raw', 'scope': 'user.jdoe'}, {'name': '2_rse_remote_delete.raw', 'scope': 'user.jdoe'}]

        :returns: True/False for a single file or a dict object with 'scope:name' as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: remote source file can not be found on storage
        :raises ServiceUnavailable: for any other reason

    """
    ret = {}
    gs = True  # gs represents the global status which inidcates if every operation workd in bulk mode

    protocol = create_protocol(rse_settings, 'delete')
    protocol.connect()

    lfns = [lfns] if not type(lfns) is list else lfns
    for lfn in lfns:
        pfn = protocol.lfns2pfns(lfn).values()[0]
        try:
            protocol.delete(pfn)
            ret['%s:%s' % (lfn['scope'], lfn['name'])] = True
        except Exception as e:
            ret['%s:%s' % (lfn['scope'], lfn['name'])] = e
            gs = False

    protocol.close()
    if len(ret) == 1:
        for x in ret:
            if isinstance(ret[x], Exception):
                raise ret[x]
            else:
                return ret[x]
    return [gs, ret]


def rename(rse_settings, files):
    """
        Rename files stored on the connected storage.
        Providing a list indicates the bulk mode.

        :param files: a single dict or a list with dicts containing 'scope', 'name', 'new_scope' and 'new_name'
                      if LFNs are used or only 'name' and 'new_name' if PFNs are used.
                      If 'new_scope' or 'new_name' are not provided, the current one is used.
                      E.g. [{'name': '3_rse_remote_rename.raw', 'scope': 'user.jdoe', 'new_name': '3_rse_new.raw', 'new_scope': 'user.jdoe'},
                            {'name': 'user/jdoe/d9/cb/9_rse_remote_rename.raw', 'new_name': 'user/jdoe/c6/4a/9_rse_new.raw'}

        :returns: True/False for a single file or a dict object with LFN (key) and True/False (value) in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: remote source file can not be found on storage
        :raises DestinationNotAccessible: remote destination directory is not accessible
        :raises ServiceUnavailable: for any other reason
    """
    ret = {}
    gs = True  # gs represents the global status which inidcates if every operation workd in bulk mode

    protocol = create_protocol(rse_settings, 'write')
    protocol.connect()

    files = [files] if not type(files) is list else files
    for f in files:
        pfn = None
        new_pfn = None
        key = None
        if 'scope' in f:  # LFN is provided
            key = '%s:%s' % (f['scope'], f['name'])
            # Check if new name is provided
            if 'new_name' not in f:
                f['new_name'] = f['name']
            # Check if new scope is provided
            if 'new_scope' not in f:
                f['new_scope'] = f['scope']
            pfn = protocol.lfns2pfns({'name': f['name'], 'scope': f['scope']}).values()[0]
            new_pfn = protocol.lfns2pfns({'name': f['new_name'], 'scope': f['new_scope']}).values()[0]
        else:
            pfn = f['name']
            new_pfn = f['new_name']
            key = pfn
        # Check if target is not on storage
        if protocol.exists(new_pfn):
            ret[key] = exception.FileReplicaAlreadyExists('File %s already exists on storage' % (new_pfn))
            gs = False
        # Check if source is on storage
        elif not protocol.exists(pfn):
            ret[key] = exception.SourceNotFound('File %s not found on storage' % (pfn))
            gs = False
        else:
            try:
                protocol.rename(pfn, new_pfn)
                ret[key] = True
            except Exception as e:
                ret[key] = e
                gs = False

    protocol.close()
    if len(ret) == 1:
        for x in ret:
            if isinstance(ret[x], Exception):
                raise ret[x]
            else:
                return ret[x]
    return [gs, ret]


def get_space_usage(rse_settings, scheme=None):
    """
        Get RSE space usage information.

        :param scheme: optional filter to select which protocol to be used.

        :returns: a list with dict containing 'totalsize' and 'unusedsize'

        :raises ServiceUnavailable: if some generic error occured in the library.
    """
    gs = True
    ret = {}

    protocol = create_protocol(rse_settings, 'read', scheme)
    protocol.connect()

    try:
        totalsize, unusedsize = protocol.get_space_usage()
        ret["totalsize"] = totalsize
        ret["unusedsize"] = unusedsize
    except Exception as e:
        ret = e
        gs = False

    protocol.close()
    return [gs, ret]
