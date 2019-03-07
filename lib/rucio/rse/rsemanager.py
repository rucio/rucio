# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Ralph Vigne <ralph.vigne@cern.ch>, 2012-2015
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2012-2017
# - Yun-Pin Sun <winter0128@gmail.com>, 2013
# - Wen Guan <wguan.icedew@gmail.com>, 2014-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2018
# - Tobias Wegner <twegner@cern.ch>, 2017-2018
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Frank Berghaus <frank.berghaus@cern.ch>, 2018-2019
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Nicolo Magini <nicolo.magini@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function

import copy
import os
import random
from time import sleep

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from rucio.common import exception, utils, constants
from rucio.common.config import config_get
from rucio.common.constraints import STRING_TYPES
from rucio.common.utils import make_valid_did


def get_rse_info(rse, session=None):
    """
        Returns all protocol related RSE attributes.

        :param rse: Name of the requested RSE
        :param session: The eventual database session.

        :returns: a dict object with the following attributes:
                    id                ...     an internal identifier
                    rse               ...     the name of the RSE as string
                    type              ...     the storage type odf the RSE e.g. DISK
                    volatile          ...     boolean indictaing if the RSE is volatile
                    verify_checksum   ...     boolean indicating whether RSE supports requests for checksums
                    deteministic      ...     boolean indicating of the nameing of the files follows the defined determinism
                    domain            ...     indictaing the domain that should be assumed for transfers. Values are 'ALL', 'LAN', or 'WAN'
                    protocols         ...     all supported protocol in form of a list of dict objects with the followig structure
                    - scheme              ...     protocol scheme e.g. http, srm, ...
                    - hostname            ...     hostname of the site
                    - prefix              ...     path to the folder where the files are stored
                    - port                ...     port used for this protocol
                    - impl                ...     naming the python class of the protocol implementation
                    - extended_attributes ...     additional information for the protocol
                    - domains             ...     a dict naming each domain and the priority of the protocol for each operation (lower is better, zero is not upported)

        :raises RSENotFound: if the provided RSE coud not be found in the database.
    """
    # __request_rse_info will be assigned when the module is loaded as it depends on the rucio environment (server or client)
    # __request_rse_info, rse_region are defined in /rucio/rse/__init__.py
    rse_info = RSE_REGION.get(str(rse))   # NOQA pylint: disable=undefined-variable
    if not rse_info:  # no cached entry found
        rse_info = __request_rse_info(str(rse), session=session)  # NOQA pylint: disable=undefined-variable
        RSE_REGION.set(str(rse), rse_info)  # NOQA pylint: disable=undefined-variable
    return rse_info


def _get_possible_protocols(rse_settings, operation, scheme=None, domain=None):
    """
    Filter the list of available protocols or provided by the supported ones.

    :param rse_settings: The rse settings.
    :param operation:    The operation (write, read).
    :param scheme:       Optional filter if no specific protocol is defined in
                         rse_setting for the provided operation.
    :param domain:       Optional domain (lan/wan), if not specified, both will be returned
    :returns:            The list of possible protocols.
    """
    operation = operation.lower()
    candidates = rse_settings['protocols']

    # convert scheme to list, if given as string
    if scheme and not isinstance(scheme, list):
        scheme = scheme.split(',')

    tbr = []
    for protocol in candidates:
        # Check if scheme given and filter if so
        if scheme and protocol['scheme'] not in scheme:
            tbr.append(protocol)
            continue

        filtered = True

        if not domain:
            for d in list(protocol['domains'].keys()):
                if protocol['domains'][d][operation] != 0:
                    filtered = False
        else:
            if protocol['domains'].get(domain, {operation: 0}).get(operation) != 0:
                filtered = False

        if filtered:
            tbr.append(protocol)

    if len(candidates) <= len(tbr):
        raise exception.RSEProtocolNotSupported('No protocol for provided settings'
                                                ' found : %s.' % str(rse_settings))

    return [c for c in candidates if c not in tbr]


def get_protocols_ordered(rse_settings, operation, scheme=None, domain='wan'):
    if operation not in utils.rse_supported_protocol_operations():
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)

    if domain and domain not in utils.rse_supported_protocol_domains():
        raise exception.RSEProtocolDomainNotSupported('Domain %s not supported' % domain)

    candidates = _get_possible_protocols(rse_settings, operation, scheme, domain)
    candidates.sort(key=lambda k: k['domains'][domain][operation])
    return candidates


def select_protocol(rse_settings, operation, scheme=None, domain='wan'):
    if operation not in utils.rse_supported_protocol_operations():
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)

    if domain and domain not in utils.rse_supported_protocol_domains():
        raise exception.RSEProtocolDomainNotSupported('Domain %s not supported' % domain)

    candidates = _get_possible_protocols(rse_settings, operation, scheme, domain)
    # Shuffle candidates to load-balance over equal sources
    random.shuffle(candidates)
    return min(candidates, key=lambda k: k['domains'][domain][operation])


def create_protocol(rse_settings, operation, scheme=None, domain='wan'):
    """
    Instanciates the protocol defined for the given operation.

    :param rse_attr:  RSE attributes
    :param operation: Intended operation for this protocol
    :param scheme:    Optional filter if no specific protocol is defined in rse_setting for the provided operation
    :param domain:    Optional specification of the domain
    :returns:         An instance of the requested protocol
    """

    # Verify feasibility of Protocol
    operation = operation.lower()
    if operation not in utils.rse_supported_protocol_operations():
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)

    if domain and domain not in utils.rse_supported_protocol_domains():
        raise exception.RSEProtocolDomainNotSupported('Domain %s not supported' % domain)

    protocol_attr = select_protocol(rse_settings, operation, scheme, domain)

    # Instantiate protocol
    comp = protocol_attr['impl'].split('.')
    mod = __import__('.'.join(comp[:-1]))
    for n in comp[1:]:
        try:
            mod = getattr(mod, n)
        except AttributeError:
            print('Protocol implementation not found')
            raise  # TODO: provide proper rucio exception
    protocol = mod(protocol_attr, rse_settings)
    return protocol


def lfns2pfns(rse_settings, lfns, operation='write', scheme=None, domain='wan'):
    """
        Convert the lfn to a pfn

        :param lfns:        logical file names as a dict containing 'scope' and 'name' as keys. For bulk a list of dicts can be provided
        :param protocol:    instance of the protocol to be used to create the PFN

        :returns: a dict with scope:name as key and the PFN as value

    """
    return create_protocol(rse_settings, operation, scheme, domain).lfns2pfns(lfns)


def parse_pfns(rse_settings, pfns, operation='read', domain='wan'):
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
    return create_protocol(rse_settings, operation, urlparse(pfns[0]).scheme, domain).parse_pfns(pfns)


def download(rse_settings, files, dest_dir=None, force_scheme=None, ignore_checksum=False, printstatements=False, domain='wan', transfer_timeout=None):
    """
        Copy a file from the connected storage to the local file system.
        Providing a list indicates the bulk mode.


        :param rse_settings:    RSE to use
        :param files:           a single dict or a list with dicts containing 'scope' and 'name'
                                if LFNs are provided and additional 'pfn' if PFNs are provided.
                                Examples:
                                [
                                {'name': '2_rse_remote_get.raw', 'scope': 'user.jdoe'},
                                {'name':'3_rse_remote_get.raw', 'scope': 'user.jdoe', 'pfn': 'user/jdoe/5a/98/3_rse_remote_get.raw'}
                                ]
        :param dest_dir:        path to the directory where the downloaded files will be stored. If not given, each scope is represented by its own directory.
        :param force_scheme:    normally the scheme is dictated by the RSE object, when specifying the PFN it must be forced to the one specified in the PFN, overruling the RSE description.
        :param ignore_checksum: do not verify the checksum - caution: should only be used for rucio download --pfn
        :param transfer_timeout: set this timeout (in seconds) for the transfers, for protocols that support it

        :returns: True/False for a single file or a dict object with 'scope:name' for LFNs or 'name' for PFNs as keys and True or the exception as value for each file in bulk mode

        :raises SourceNotFound: remote source file can not be found on storage
        :raises DestinationNotAccessible: local destination directory is not accessible
        :raises FileConsistencyMismatch: the checksum of the downloaded file does not match the provided one
        :raises ServiceUnavailable: for any other reason

    """
    ret = {}
    gs = True  # gs represents the global status which inidcates if every operation workd in bulk mode

    protocol = create_protocol(rse_settings, 'read', scheme=force_scheme, domain=domain)
    protocol.connect()

    files = [files] if not type(files) is list else files
    for f in files:
        pfn = f['pfn'] if 'pfn' in f else list(protocol.lfns2pfns(f).values())[0]
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
                            print('%s already exists, probably from a failed attempt. Will remove it' % (tempfile))
                        os.unlink(tempfile)
                    protocol.get(pfn, tempfile, transfer_timeout=transfer_timeout)
                    if printstatements:
                        print('File downloaded. Will be validated')

                    if ignore_checksum:
                        if printstatements:
                            print('Skipping checksum validation')
                    else:
                        ruciochecksum = f['adler32'] if f['adler32'] else f['md5']
                        localchecksum = utils.adler32(tempfile) if f['adler32'] else utils.md5(tempfile)
                        if localchecksum == ruciochecksum:
                            if printstatements:
                                print('File validated')
                        else:
                            os.unlink(tempfile)
                            raise exception.FileConsistencyMismatch('Checksum mismatch : local %s vs recorded %s' % (str(localchecksum), str(ruciochecksum)))
                    os.rename(tempfile, finalfile)
                else:
                    protocol.get(pfn, '%s/%s' % (target_dir, f['name']), transfer_timeout=transfer_timeout)
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
        if isinstance(f, STRING_TYPES):
            exists = protocol.exists(f)
            ret[f] = exists
        elif 'scope' in f:  # a LFN is provided
            pfn = list(protocol.lfns2pfns(f).values())[0]
            if isinstance(pfn, exception.RucioException):
                raise pfn
            exists = protocol.exists(list(protocol.lfns2pfns(f).values())[0])
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


def upload(rse_settings, lfns, source_dir=None, force_pfn=None, force_scheme=None, transfer_timeout=None, delete_existing=False):
    """
        Uploads a file to the connected storage.
        Providing a list indicates the bulk mode.

        :param lfns:        a single dict or a list with dicts containing 'scope' and 'name'.
                            Examples:
                            [
                            {'name': '1_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 42, 'adler32': '87HS3J968JSNWID'},
                            {'name': '2_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 4711, 'adler32': 'RSSMICETHMISBA837464F'}
                            ]
                            If the 'filename' key is present, it will be used by Rucio as the actual name of the file on disk (separate from the Rucio 'name').
        :param source_dir:  path to the local directory including the source files
        :param force_pfn: use the given PFN -- can lead to dark data, use sparingly
        :param force_scheme: use the given protocol scheme, overriding the protocol priority in the RSE description
        :param transfer_timeout: set this timeout (in seconds) for the transfers, for protocols that support it

        :returns: True/False for a single file or a dict object with 'scope:name' as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: local source file can not be found
        :raises DestinationNotAccessible: remote destination directory is not accessible
        :raises ServiceUnavailable: for any other reason
    """
    ret = {}
    gs = True  # gs represents the global status which indicates if every operation worked in bulk mode

    protocol = create_protocol(rse_settings, 'write', scheme=force_scheme)
    protocol.connect()
    protocol_delete = create_protocol(rse_settings, 'delete')
    protocol_delete.connect()

    lfns = [lfns] if not type(lfns) is list else lfns
    for lfn in lfns:
        base_name = lfn.get('filename', lfn['name'])
        name = lfn.get('name', base_name)
        scope = lfn['scope']
        if 'adler32' not in lfn:
            gs = False
            ret['%s:%s' % (scope, name)] = exception.RucioException('Missing checksum for file %s:%s' % (lfn['scope'], name))
            continue
        if 'filesize' not in lfn:
            gs = False
            ret['%s:%s' % (scope, name)] = exception.RucioException('Missing filesize for file %s:%s' % (lfn['scope'], name))
            continue

        if force_pfn:
            pfn = force_pfn
        else:
            pfn = list(protocol.lfns2pfns(make_valid_did(lfn)).values())[0]
            if isinstance(pfn, exception.RucioException):
                raise pfn

        # First check if renaming operation is supported
        if protocol.renaming:

            # Check if file replica is already on the storage system
            if protocol.overwrite is False and delete_existing is False and protocol.exists(pfn):
                ret['%s:%s' % (scope, name)] = exception.FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))
                gs = False
            else:
                if protocol.exists('%s.rucio.upload' % pfn):  # Check for left over of previous unsuccessful attempts
                    try:
                        protocol_delete.delete('%s.rucio.upload' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0])
                    except Exception as e:
                        ret['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('Unable to remove temporary file %s.rucio.upload: %s' % (pfn, str(e)))
                        gs = False
                        continue

                if delete_existing:
                    if protocol.exists('%s' % pfn):  # Check for previous completed uploads that have to be removed before upload
                        try:
                            protocol_delete.delete('%s' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0])
                        except Exception as e:
                            ret['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('Unable to remove file %s: %s' % (pfn, str(e)))
                            gs = False
                            continue

                try:  # Try uploading file
                    protocol.put(base_name, '%s.rucio.upload' % pfn, source_dir, transfer_timeout=transfer_timeout)
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, name)] = e
                    continue

                valid = None
                try:  # Get metadata of file to verify if upload was successful
                    try:
                        stats = _retry_protocol_stat(protocol, '%s.rucio.upload' % pfn)
                        if ('adler32' in stats) and ('adler32' in lfn):
                            valid = stats['adler32'] == lfn['adler32']
                        if (valid is None) and ('filesize' in stats) and ('filesize' in lfn):
                            valid = stats['filesize'] == lfn['filesize']
                    except exception.RSEChecksumUnavailable as e:
                        if rse_settings['verify_checksum'] is False:
                            valid = True
                        else:
                            raise exception.RucioException('Checksum not validated')
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
        else:

            # Check if file replica is already on the storage system
            if protocol.overwrite is False and delete_existing is False and protocol.exists(pfn):
                ret['%s:%s' % (scope, name)] = exception.FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))
                gs = False
            else:
                try:  # Try uploading file
                    protocol.put(base_name, pfn, source_dir, transfer_timeout=transfer_timeout)
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, name)] = e
                    continue

                valid = None
                try:  # Get metadata of file to verify if upload was successful
                    try:
                        stats = _retry_protocol_stat(protocol, pfn)
                        if ('adler32' in stats) and ('adler32' in lfn):
                            valid = stats['adler32'] == lfn['adler32']
                        if (valid is None) and ('filesize' in stats) and ('filesize' in lfn):
                            valid = stats['filesize'] == lfn['filesize']
                    except exception.RSEChecksumUnavailable as e:
                        if rse_settings['verify_checksum'] is False:
                            valid = True
                        else:
                            raise exception.RucioException('Checksum not validated')
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, name)] = e
                    continue

                if not valid:
                    gs = False
                    ret['%s:%s' % (scope, name)] = exception.RucioException('Replica %s is corrupted.' % pfn)

    protocol.close()
    protocol_delete.close()
    if len(ret) == 1:
        for x in ret:
            if isinstance(ret[x], Exception):
                raise ret[x]
            else:
                return {'success': ret[x],
                        'pfn': pfn}
    return {0: gs, 1: ret, 'success': gs, 'pfn': pfn}


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
        pfn = list(protocol.lfns2pfns(lfn).values())[0]
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
                      Examples:
                      [
                      {'name': '3_rse_remote_rename.raw', 'scope': 'user.jdoe', 'new_name': '3_rse_new.raw', 'new_scope': 'user.jdoe'},
                      {'name': 'user/jdoe/d9/cb/9_rse_remote_rename.raw', 'new_name': 'user/jdoe/c6/4a/9_rse_new.raw'}
                      ]

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
            pfn = list(protocol.lfns2pfns({'name': f['name'], 'scope': f['scope']}).values())[0]
            new_pfn = list(protocol.lfns2pfns({'name': f['new_name'], 'scope': f['new_scope']}).values())[0]
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


def find_matching_scheme(rse_settings_dest, rse_settings_src, operation_src, operation_dest, domain='wan', scheme=None):
    """
    Find the best matching scheme between two RSEs

    :param rse_settings_dest:    RSE settings for the destination RSE.
    :param rse_settings_src:     RSE settings for the src RSE.
    :param operation_src:        Source Operation such as read, write.
    :param operation_dest:       Dest Operation such as read, write.
    :param domain:               Domain such as lan, wan.
    :param scheme:               List of supported schemes.
    :returns:                    Tuple of matching schemes (dest_scheme, src_scheme).
    """
    operation_src = operation_src.lower()
    operation_dest = operation_dest.lower()

    src_candidates = copy.copy(rse_settings_src['protocols'])
    dest_candidates = copy.copy(rse_settings_dest['protocols'])

    # Clean up src_candidates
    tbr = list()
    for protocol in src_candidates:
        # Check if scheme given and filter if so
        if scheme:
            if not isinstance(scheme, list):
                scheme = scheme.split(',')
            if protocol['scheme'] not in scheme:
                tbr.append(protocol)
                continue
        if protocol['domains'].get(domain, {}).get(operation_src, 1) == 0:
            tbr.append(protocol)
    for r in tbr:
        src_candidates.remove(r)

    # Clean up dest_candidates
    tbr = list()
    for protocol in dest_candidates:
        # Check if scheme given and filter if so
        if scheme:
            if not isinstance(scheme, list):
                scheme = scheme.split(',')
            if protocol['scheme'] not in scheme:
                tbr.append(protocol)
                continue
        if protocol['domains'].get(domain, {}).get(operation_dest, 1) == 0:
            tbr.append(protocol)
    for r in tbr:
        dest_candidates.remove(r)

    if not len(src_candidates) or not len(dest_candidates):
        raise exception.RSEProtocolNotSupported('No protocol for provided settings found : %s.' % str(rse_settings_dest))

    # Shuffle the candidates to load-balance across equal weights.
    random.shuffle(dest_candidates)
    random.shuffle(src_candidates)

    # Select the one with the highest priority
    dest_candidates = sorted(dest_candidates, key=lambda k: k['domains'][domain][operation_dest])
    src_candidates = sorted(src_candidates, key=lambda k: k['domains'][domain][operation_src])

    for dest_protocol in dest_candidates:
        for src_protocol in src_candidates:
            if __check_compatible_scheme(dest_protocol['scheme'], src_protocol['scheme']):
                return (dest_protocol['scheme'], src_protocol['scheme'])

    raise exception.RSEProtocolNotSupported('No protocol for provided settings found : %s.' % str(rse_settings_dest))


def _retry_protocol_stat(protocol, pfn):
    """
    try to stat file, on fail try again 1s, 2s, 4s, 8s, 16s, 32s later. Fail is all fail

    :param protocol     The protocol to use to reach this file
    :param pfn          Physical file name of the target for the protocol stat
    """
    retries = config_get('client', 'protocol_stat_retries', raise_exception=False, default=6)

    for attempt in range(retries):
        try:
            stats = protocol.stat(pfn)
            return stats
        except exception.RSEChecksumUnavailable as e:
            # The stat succeeded here, but the checksum failed
            raise e
        except Exception as e:
            sleep(2**attempt)
    return protocol.stat(pfn)


def __check_compatible_scheme(dest_scheme, src_scheme):
    """
    Check if two schemes are compatible, such as srm and gsiftp

    :param dest_scheme:    Destination scheme
    :param src_scheme:     Source scheme
    :param scheme:         List of supported schemes
    :returns:              True if schemes are compatible, False otherwise.
    """

    if dest_scheme == src_scheme:
        return True
    if src_scheme in constants.SCHEME_MAP.get(dest_scheme, []):
        return True

    return False
