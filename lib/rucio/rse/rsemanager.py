# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import copy
import logging
import random
from time import sleep
from typing import TYPE_CHECKING, Any, Literal, Optional, Union, cast
from urllib.parse import urlparse

from rucio.common import constants, exception, types, utils
from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS
from rucio.common.config import config_get_int
from rucio.common.constants import DEFAULT_VO
from rucio.common.constraints import STRING_TYPES
from rucio.common.logging import formatted_logger
from rucio.common.utils import get_transfer_schemas, make_valid_did

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.orm import Session

    from rucio.rse.protocols.protocol import RSEProtocol


def get_scope_protocol(vo: str = DEFAULT_VO) -> 'Callable':
    """
        Returns the callable protocol to translate the pfn to a name/scope pair

    :returns:
        Callable: Scope Parser function
    """
    from rucio.rse.translation import RSEDeterministicScopeTranslation
    translation = RSEDeterministicScopeTranslation(vo=vo)
    return translation.parser


def get_rse_info(
        rse: Optional[str] = None,
        vo: str = DEFAULT_VO,
        rse_id: Optional[str] = None,
        session: Optional["Session"] = None
) -> types.RSESettingsDict:
    """
        Returns all protocol related RSE attributes.
        Call with either rse and vo, or (in server mode) rse_id

        :param rse: Name of the requested RSE
        :param vo: The VO for the RSE.
        :param rse_id: The id of the rse (use in server mode to avoid db calls)
        :param session: The eventual database session.

        :returns: a dict object with the following attributes:
                    id                ...     an internal identifier
                    rse               ...     the name of the RSE as string
                    type              ...     the storage type odf the RSE e.g. DISK
                    volatile          ...     boolean indicating if the RSE is volatile
                    verify_checksum   ...     boolean indicating whether RSE supports requests for checksums
                    deterministic      ...     boolean indicating of the naming of the files follows the defined determinism
                    domain            ...     indicating the domain that should be assumed for transfers. Values are 'ALL', 'LAN', or 'WAN'
                    protocols         ...     all supported protocol in form of a list of dict objects with the following structure
                    - scheme              ...     protocol scheme e.g. http, srm, ...
                    - hostname            ...     hostname of the site
                    - prefix              ...     path to the folder where the files are stored
                    - port                ...     port used for this protocol
                    - impl                ...     naming the python class of the protocol implementation
                    - extended_attributes ...     additional information for the protocol
                    - domains             ...     a dict naming each domain and the priority of the protocol for each operation (lower is better, zero is not supported)

        :raises RSENotFound: if the provided RSE could not be found in the database.
    """
    # __request_rse_info will be assigned when the module is loaded as it depends on the rucio environment (server or client)
    # __request_rse_info, rse_region are defined in /rucio/rse/__init__.py
    key = '{}:{}'.format(rse, vo) if rse_id is None else str(rse_id)
    key = 'rse_info_%s' % (key)
    rse_info = RSE_REGION.get(key)   # NOQA pylint: disable=undefined-variable
    if not rse_info:  # no cached entry found
        rse_info = __request_rse_info(str(rse), vo=vo, rse_id=rse_id, session=session)  # NOQA pylint: disable=undefined-variable
        RSE_REGION.set(key, rse_info)  # NOQA pylint: disable=undefined-variable
    return rse_info


def _get_possible_protocols(
        rse_settings: types.RSESettingsDict,
        operation: str,
        scheme: Optional[Union[list[str], str]] = None,
        domain: Optional[str] = None,
        impl: Optional[str] = None
) -> list[types.RSEProtocolDict]:
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
        # Check if impl given and filter if so
        if impl and protocol['impl'] != impl:
            tbr.append(protocol)
            continue

        # Check if scheme given and filter if so
        if scheme and protocol['scheme'] not in scheme:
            tbr.append(protocol)
            continue

        filtered = True

        if not domain:
            for d in list(protocol['domains'].keys()):
                if protocol['domains'][d][operation]:
                    filtered = False
        else:
            if protocol['domains'].get(domain, {operation: None}).get(operation):
                filtered = False

        if filtered:
            tbr.append(protocol)

    if len(candidates) <= len(tbr):
        raise exception.RSEProtocolNotSupported('No protocol for provided settings'
                                                ' found : %s.' % str(rse_settings))

    return [c for c in candidates if c not in tbr]


def get_protocols_ordered(
        rse_settings: types.RSESettingsDict,
        operation: constants.RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL,
        scheme: Optional[Union[list[str], str]] = None,
        domain: str = 'wan',
        impl: Optional[str] = None
) -> list[types.RSEProtocolDict]:
    if operation not in constants.RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS:
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)

    if domain and domain not in utils.rse_supported_protocol_domains():
        raise exception.RSEProtocolDomainNotSupported('Domain %s not supported' % domain)

    candidates = _get_possible_protocols(rse_settings, operation, scheme, domain, impl)
    candidates.sort(key=lambda k: k['domains'][domain][operation])
    return candidates


def select_protocol(
        rse_settings: types.RSESettingsDict,
        operation: constants.RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL,
        scheme: Optional[str] = None,
        domain: str = 'wan'
) -> types.RSEProtocolDict:
    if operation not in constants.RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS:
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)

    if domain and domain not in utils.rse_supported_protocol_domains():
        raise exception.RSEProtocolDomainNotSupported('Domain %s not supported' % domain)

    candidates = _get_possible_protocols(rse_settings, operation, scheme, domain)
    # Shuffle candidates to load-balance over equal sources
    random.shuffle(candidates)
    return min(candidates, key=lambda k: k['domains'][domain][operation])


def create_protocol(
        rse_settings: types.RSESettingsDict,
        operation: str,
        scheme: Optional[str] = None,
        domain: str = 'wan',
        auth_token: Optional[str] = None,
        protocol_attr: Optional[types.RSEProtocolDict] = None,
        logger: types.LoggerFunction = logging.log,
        impl: Optional[str] = None
) -> "RSEProtocol":
    """
    Instantiates the protocol defined for the given operation.

    :param rse_settings:  RSE attributes
    :param operation:     Intended operation for this protocol
    :param scheme:        Optional filter if no specific protocol is defined in rse_setting for the provided operation
    :param domain:        Optional specification of the domain
    :param auth_token:    Optionally passing JSON Web Token (OIDC) string for authentication
    :param protocol_attr: Optionally passing the full protocol availability information to correctly select WAN/LAN
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:             An instance of the requested protocol
    """

    # Verify feasibility of Protocol
    operation = operation.lower()
    if operation not in constants.RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS:
        raise exception.RSEOperationNotSupported('Operation %s is not supported' % operation)

    operation = cast("constants.RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL", operation)

    if domain and domain not in utils.rse_supported_protocol_domains():
        raise exception.RSEProtocolDomainNotSupported('Domain %s not supported' % domain)

    if impl:
        candidate = _get_possible_protocols(rse_settings, operation, scheme, domain, impl=impl)
        if len(candidate) == 0:
            raise exception.RSEProtocolNotSupported('Protocol implementation %s operation %s on domain %s not supported' % (impl, operation, domain))
        protocol_attr = candidate[0]
    elif not protocol_attr:
        protocol_attr = select_protocol(rse_settings, operation, scheme, domain)
    else:
        candidates = _get_possible_protocols(rse_settings, operation, scheme, domain)
        if protocol_attr not in candidates:
            raise exception.RSEProtocolNotSupported('Protocol %s operation %s on domain %s not supported' % (protocol_attr, operation, domain))

    # Instantiate protocol
    comp = protocol_attr['impl'].split('.')
    prefix = '.'.join(comp[-2:]) + ': '
    logger = formatted_logger(logger, prefix + "%s")
    mod = __import__('.'.join(comp[:-1]))
    for n in comp[1:]:
        try:
            mod = getattr(mod, n)
        except AttributeError as e:
            logger(logging.DEBUG, 'Protocol implementations not supported.')
            raise exception.RucioException(str(e))  # TODO: provide proper rucio exception
    protocol_attr['auth_token'] = auth_token
    protocol = mod(protocol_attr, rse_settings, logger=logger)
    return protocol


def lfns2pfns(
        rse_settings: types.RSESettingsDict,
        lfns: Union[list[types.LFNDict], types.LFNDict],
        operation: str = 'write',
        scheme: Optional[str] = None,
        domain: str = 'wan',
        auth_token: Optional[str] = None,
        logger: types.LoggerFunction = logging.log,
        impl: Optional[str] = None
) -> dict[str, str]:
    """
        Convert the lfn to a pfn

        :param rse_settings:      RSE attributes
        :param lfns:        logical file names as a dict containing 'scope' and 'name' as keys. For bulk a list of dicts can be provided
        :param operation:   Intended operation for this protocol
        :param scheme:      Optional filter if no specific protocol is defined in rse_setting for the provided operation
        :param domain:      Optional specification of the domain
        :param auth_token:  Optionally passing JSON Web Token (OIDC) string for authentication
        :param logger:      Optional decorated logger that can be passed from the calling daemons or servers.

        :returns:           a dict with scope:name as key and the PFN as value

    """
    return create_protocol(rse_settings, operation, scheme, domain, auth_token=auth_token, logger=logger, impl=impl).lfns2pfns(lfns)


def parse_pfns(
        rse_settings: types.RSESettingsDict,
        pfns: list[str],
        operation: str = 'read',
        domain: str = 'wan',
        auth_token: Optional[str] = None
) -> dict[str, dict[str, str]]:
    """
        Checks if a PFN is feasible for a given RSE. If so it splits the pfn in its various components.

        :param rse_settings:   RSE attributes
        :param pfns:        list of PFNs
        :param operation: Intended operation for this protocol
        :param domain:    Optional specification of the domain
        :param auth_token: Optionally passing JSON Web Token (OIDC) string for authentication

        :returns: A dict with the parts known by the selected protocol e.g. scheme, hostname, prefix, path, name

        :raises RSEFileNameNotSupported: if provided PFN is not supported by the RSE/protocol
        :raises RSENotFound: if the referred storage is not found i the repository (rse_id)
        :raises InvalidObject: If the properties parameter doesn't include scheme, hostname, and port as keys
        :raises RSEOperationNotSupported: If no matching protocol was found for the requested operation
    """
    if len(set([urlparse(pfn).scheme for pfn in pfns])) != 1:
        raise ValueError('All PFNs must provide the same protocol scheme')
    return create_protocol(rse_settings, operation, urlparse(pfns[0]).scheme, domain, auth_token=auth_token).parse_pfns(pfns)


def exists(
        rse_settings: types.RSESettingsDict,
        files: Union[list[dict[str, str]], dict[str, str]],
        domain: str = 'wan',
        scheme: Optional[str] = None,
        impl: Optional[str] = None,
        auth_token: Optional[str] = None,
        vo: str = DEFAULT_VO,
        logger: types.LoggerFunction = logging.log
) -> Union[bool, list[Union[bool, dict[dict[str, str], bool]]]]:
    """
        Checks if a file is present at the connected storage.
        Providing a list indicates the bulk mode.

        :param rse_settings:      RSE attributes
        :param files:       a single dict or a list with dicts containing 'scope' and 'name'
                            if LFNs are used and only 'name' if PFNs are used.
                            E.g. {'name': '2_rse_remote_get.raw', 'scope': 'user.jdoe'}, {'name': 'user/jdoe/5a/98/3_rse_remote_get.raw'}
        :param domain:      The network domain, either 'wan' (default) or 'lan'
        :param auth_token:  Optionally passing JSON Web Token (OIDC) string for authentication
        :param vo:          The VO for the RSE
        :param logger:      Optional decorated logger that can be passed from the calling daemons or servers.

        :returns:           True/False for a single file or a dict object with 'scope:name' for LFNs or 'name' for PFNs as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
    """

    protocol = create_protocol(rse_settings, 'read', scheme=scheme, impl=impl, domain=domain, auth_token=auth_token, logger=logger)
    protocol.connect()

    from rucio.rse.protocols.protocol import RSEProtocol  # Placed it here to avoid possible circular imports
    # Check if 'exists' is truly overridden on the read protocol
    if not utils.is_method_overridden(protocol, RSEProtocol, 'exists'):
        # If not overridden, optionally fall back to a write protocol
        protocol = create_protocol(rse_settings, 'write', scheme=scheme, domain=domain, auth_token=auth_token, logger=logger)
        protocol.connect()

    ret = {}
    gs = True  # gs represents the global status which indicates if every operation worked in bulk mode

    if not isinstance(files, list):
        files = [files]
    for f in files:
        exists = None
        if isinstance(f, STRING_TYPES):
            exists = protocol.exists(f)
            ret[f] = exists
        elif 'scope' in f:  # a LFN is provided
            f = cast("types.LFNDict", f)
            pfn = list(protocol.lfns2pfns(f).values())[0]
            if isinstance(pfn, exception.RucioException):
                raise pfn
            logger(logging.DEBUG, 'Checking if %s exists', pfn)
            # deal with URL signing if required
            if rse_settings['sign_url'] is not None and pfn[:5] == 'https':
                pfn = __get_signed_url(rse_settings['rse'], rse_settings['sign_url'], 'read', pfn, vo)    # NOQA pylint: disable=undefined-variable
            exists = protocol.exists(pfn)
            ret[f['scope'] + ':' + f['name']] = exists
        else:
            exists = protocol.exists(f['name'])
            ret[f['name']] = exists
        if not exists:
            gs = False

    protocol.close()
    if len(ret) == 1:
        return next(iter(ret.values()))
    return [gs, ret]


def upload(
        rse_settings: types.RSESettingsDict,
        lfns: Union[list[types.LFNDict], types.LFNDict],
        domain: str = 'wan',
        source_dir: Optional[str] = None,
        force_pfn: Optional[str] = None,
        force_scheme: Optional[str] = None,
        transfer_timeout: Optional[int] = None,
        delete_existing: bool = False,
        sign_service: Optional[str] = None,
        auth_token: Optional[str] = None,
        vo: str = DEFAULT_VO,
        logger: types.LoggerFunction = logging.log,
        impl: Optional[str] = None
) -> dict[Union[int, str], Union[bool, str, dict[str, Union[Literal[True], Exception]]]]:
    """
        Uploads a file to the connected storage.
        Providing a list indicates the bulk mode.

        :param rse_settings:            RSE attributes
        :param lfns:              a single dict or a list with dicts containing 'scope' and 'name'.
                                  Examples:
                                  [
                                  {'name': '1_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 42, 'adler32': '87HS3J968JSNWID'},
                                  {'name': '2_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 4711, 'adler32': 'RSSMICETHMISBA837464F'}
                                  ]
                                  If the 'filename' key is present, it will be used by Rucio as the actual name of the file on disk (separate from the Rucio 'name').
        :param domain:            The network domain, either 'wan' (default) or 'lan'
        :param source_dir:        path to the local directory including the source files
        :param force_pfn:         use the given PFN -- can lead to dark data, use sparingly
        :param force_scheme:      use the given protocol scheme, overriding the protocol priority in the RSE description
        :param transfer_timeout:  set this timeout (in seconds) for the transfers, for protocols that support it
        :param sign_service:      use the given service (e.g. gcs, s3, swift) to sign the URL
        :param auth_token:        Optionally passing JSON Web Token (OIDC) string for authentication
        :param vo:                The VO for the RSE
        :param logger:            Optional decorated logger that can be passed from the calling daemons or servers.

        :returns:                 True/False for a single file or a dict object with 'scope:name' as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: local source file can not be found
        :raises DestinationNotAccessible: remote destination directory is not accessible
        :raises ServiceUnavailable: for any other reason
    """

    ret = {}
    gs = True  # gs represents the global status which indicates if every operation worked in bulk mode

    protocol = create_protocol(rse_settings, 'write', scheme=force_scheme, domain=domain, auth_token=auth_token, logger=logger, impl=impl)
    protocol.connect()
    protocol_delete = create_protocol(rse_settings, 'delete', domain=domain, auth_token=auth_token, logger=logger, impl=impl)
    protocol_delete.connect()

    if not isinstance(lfns, list):
        lfns = [lfns]
    for lfn in lfns:
        base_name = lfn.get('filename', lfn['name'])
        name = lfn.get('name', base_name)
        scope = lfn['scope']
        if 'adler32' not in lfn and 'md5' not in lfn:
            gs = False
            ret['%s:%s' % (scope, name)] = exception.RucioException('Missing checksum for file %s:%s' % (lfn['scope'], name))
            continue
        if 'filesize' not in lfn:
            gs = False
            ret['%s:%s' % (scope, name)] = exception.RucioException('Missing filesize for file %s:%s' % (lfn['scope'], name))
            continue
        if force_pfn:
            pfn = force_pfn
            readpfn = force_pfn
        else:
            pfn = list(protocol.lfns2pfns(make_valid_did(lfn)).values())[0]
            if isinstance(pfn, exception.RucioException):
                raise pfn
            readpfn = pfn
            if sign_service is not None:
                # need a separate signed URL for read operations (exists and stat)
                readpfn = __get_signed_url(rse_settings['rse'], sign_service, 'read', pfn, vo)    # NOQA pylint: disable=undefined-variable
                pfn = __get_signed_url(rse_settings['rse'], sign_service, 'write', pfn, vo)       # NOQA pylint: disable=undefined-variable

        # First check if renaming operation is supported
        if protocol.renaming:

            # Check if file replica is already on the storage system
            if protocol.overwrite is False and delete_existing is False and protocol.exists(pfn):
                ret['%s:%s' % (scope, name)] = exception.FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))
                gs = False
            else:
                if protocol.exists('%s.rucio.upload' % pfn):  # Check for left over of previous unsuccessful attempts
                    try:
                        logger(logging.DEBUG, 'Deleting %s.rucio.upload', pfn)
                        protocol_delete.delete('%s.rucio.upload' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0])
                    except Exception as e:
                        ret['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('Unable to remove temporary file %s.rucio.upload: %s' % (pfn, str(e)))
                        gs = False
                        continue

                if delete_existing:
                    if protocol.exists('%s' % pfn):  # Check for previous completed uploads that have to be removed before upload
                        try:
                            logger(logging.DEBUG, 'Deleting %s', pfn)
                            protocol_delete.delete('%s' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0])
                        except Exception as e:
                            ret['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('Unable to remove file %s: %s' % (pfn, str(e)))
                            gs = False
                            continue

                try:  # Try uploading file
                    logger(logging.DEBUG, 'Uploading to %s.rucio.upload', pfn)
                    protocol.put(base_name, '%s.rucio.upload' % pfn, source_dir, transfer_timeout=transfer_timeout)  # type: ignore (source_dir could be None)
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, name)] = e
                    continue

                valid = None

                try:  # Get metadata of file to verify if upload was successful
                    try:
                        stats = _retry_protocol_stat(protocol, '%s.rucio.upload' % pfn)
                        # Verify all supported checksums and keep rack of the verified ones
                        verified_checksums = []
                        for checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS:
                            if (checksum_name in stats) and (checksum_name in lfn):
                                verified_checksums.append(stats[checksum_name] == lfn[checksum_name])
                        # Upload is successful if at least one checksum was found
                        valid = any(verified_checksums)
                        if not valid and ('filesize' in stats) and ('filesize' in lfn):
                            valid = stats['filesize'] == lfn['filesize']
                    except NotImplementedError:
                        if rse_settings['verify_checksum'] is False:
                            valid = True
                        else:
                            raise exception.RucioException('Checksum not validated')
                    except exception.RSEChecksumUnavailable:
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
                        logger(logging.DEBUG, 'Renaming %s.rucio.upload to %s', pfn, pfn)
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
            if protocol.overwrite is False and delete_existing is False and protocol.exists(readpfn):
                ret['%s:%s' % (scope, name)] = exception.FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))
                gs = False
            else:
                try:  # Try uploading file
                    logger(logging.DEBUG, 'Uploading to %s', pfn)
                    protocol.put(base_name, pfn, source_dir, transfer_timeout=transfer_timeout)
                except Exception as e:
                    gs = False
                    ret['%s:%s' % (scope, name)] = e
                    continue

                valid = None
                try:  # Get metadata of file to verify if upload was successful
                    try:
                        stats = _retry_protocol_stat(protocol, pfn)

                        # Verify all supported checksums and keep rack of the verified ones
                        verified_checksums = []
                        for checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS:
                            if (checksum_name in stats) and (checksum_name in lfn):
                                verified_checksums.append(stats[checksum_name] == lfn[checksum_name])

                        # Upload is successful if at least one checksum was found
                        valid = any(verified_checksums)
                        if not valid and ('filesize' in stats) and ('filesize' in lfn):
                            valid = stats['filesize'] == lfn['filesize']
                    except NotImplementedError:
                        if rse_settings['verify_checksum'] is False:
                            valid = True
                        else:
                            raise exception.RucioException('Checksum not validated')
                    except exception.RSEChecksumUnavailable:
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
        ret_value = next(iter(ret.values()))
        if isinstance(ret_value, Exception):
            raise ret_value
        else:
            return {0: ret_value, 1: ret, 'success': ret_value, 'pfn': pfn}
    return {0: gs, 1: ret, 'success': gs, 'pfn': pfn}


def delete(
        rse_settings: types.RSESettingsDict,
        lfns: Union[list[types.LFNDict], types.LFNDict],
        domain: str = 'wan',
        auth_token: Optional[str] = None,
        logger: types.LoggerFunction = logging.log,
        impl: Optional[str] = None
) -> Union[bool, list[Union[bool, dict[str, Union[Literal[True], Exception]]]]]:
    """
        Delete a file from the connected storage.
        Providing a list indicates the bulk mode.

        :param rse_settings:     RSE attributes
        :param lfns:       a single dict or a list with dicts containing 'scope' and 'name'. E.g. [{'name': '1_rse_remote_delete.raw', 'scope': 'user.jdoe'}, {'name': '2_rse_remote_delete.raw', 'scope': 'user.jdoe'}]
        :param domain:     The network domain, either 'wan' (default) or 'lan'
        :param auth_token: Optionally passing JSON Web Token (OIDC) string for authentication
        :param logger:     Optional decorated logger that can be passed from the calling daemons or servers.
        :returns:          True/False for a single file or a dict object with 'scope:name' as keys and True or the exception as value for each file in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: remote source file can not be found on storage
        :raises ServiceUnavailable: for any other reason

    """
    ret = {}
    gs = True  # gs represents the global status which indicates if every operation worked in bulk mode

    protocol = create_protocol(rse_settings, 'delete', domain=domain, auth_token=auth_token, logger=logger, impl=impl)
    protocol.connect()

    if not isinstance(lfns, list):
        lfns = [lfns]
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
        ret_value = next(iter(ret.values()))
        if isinstance(ret_value, Exception):
            raise ret_value
        else:
            return ret_value
    return [gs, ret]


def rename(
        rse_settings: types.RSESettingsDict,
        files: Union[list[dict[str, str]], dict[str, str]],
        domain: str = 'wan',
        auth_token: Optional[str] = None,
        logger: types.LoggerFunction = logging.log,
        impl: Optional[str] = None
) -> Union[bool, list[Union[bool, dict[str, Union[Literal[True], Exception]]]]]:
    """
        Rename files stored on the connected storage.
        Providing a list indicates the bulk mode.

        :param rse_settings:     RSE attributes
        :param files:      a single dict or a list with dicts containing 'scope', 'name', 'new_scope' and 'new_name'
                           if LFNs are used or only 'name' and 'new_name' if PFNs are used.
                           If 'new_scope' or 'new_name' are not provided, the current one is used.
                           Examples:
                           [
                           {'name': '3_rse_remote_rename.raw', 'scope': 'user.jdoe', 'new_name': '3_rse_new.raw', 'new_scope': 'user.jdoe'},
                           {'name': 'user/jdoe/d9/cb/9_rse_remote_rename.raw', 'new_name': 'user/jdoe/c6/4a/9_rse_new.raw'}
                           ]
        :param domain:     The network domain, either 'wan' (default) or 'lan'
        :param auth_token: Optionally passing JSON Web Token (OIDC) string for authentication
        :param logger:     Optional decorated logger that can be passed from the calling daemons or servers.

        :returns:          True/False for a single file or a dict object with LFN (key) and True/False (value) in bulk mode

        :raises RSENotConnected: no connection to a specific storage has been established
        :raises SourceNotFound: remote source file can not be found on storage
        :raises DestinationNotAccessible: remote destination directory is not accessible
        :raises ServiceUnavailable: for any other reason
    """
    ret = {}
    gs = True  # gs represents the global status which indicates if every operation worked in bulk mode

    protocol = create_protocol(rse_settings, 'write', domain=domain, auth_token=auth_token, logger=logger, impl=impl)
    protocol.connect()

    if not isinstance(files, list):
        files = [files]
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
        ret_value = next(iter(ret.values()))
        if isinstance(ret_value, Exception):
            raise ret_value
        else:
            return ret_value
    return [gs, ret]


def get_space_usage(
        rse_settings: types.RSESettingsDict,
        scheme: Optional[str] = None,
        domain: str = 'wan',
        auth_token: Optional[str] = None,
        logger: types.LoggerFunction = logging.log,
        impl: Optional[str] = None
) -> list[Union[bool, Union[dict[str, int], Exception]]]:
    """
        Get RSE space usage information.

        :param rse_settings:     RSE attributes
        :param scheme:     optional filter to select which protocol to be used.
        :param domain:     The network domain, either 'wan' (default) or 'lan'
        :param auth_token: Optionally passing JSON Web Token (OIDC) string for authentication
        :param logger:     Optional decorated logger that can be passed from the calling daemons or servers.

        :returns:          a list with dict containing 'totalsize' and 'unusedsize'

        :raises ServiceUnavailable: if some generic error occurred in the library.
    """
    gs = True
    ret = {}

    protocol = create_protocol(rse_settings, 'read', scheme=scheme, domain=domain, auth_token=auth_token, logger=logger, impl=impl)
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


def find_matching_scheme(
        rse_settings_dest: types.RSESettingsDict,
        rse_settings_src: types.RSESettingsDict,
        operation_src: str,
        operation_dest: str,
        domain: str = 'wan',
        scheme: Optional[Union[str, list[str]]] = None
) -> tuple[str, str, int, int]:
    """
    Find the best matching scheme between two RSEs

    :param rse_settings_dest:    RSE settings for the destination RSE.
    :param rse_settings_src:     RSE settings for the src RSE.
    :param operation_src:        Source Operation such as read, write.
    :param operation_dest:       Dest Operation such as read, write.
    :param domain:               Domain such as lan, wan.
    :param scheme:               List of supported schemes.
    :returns:                    Tuple of matching schemes (dest_scheme, src_scheme, dest_scheme_priority, src_scheme_priority).
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
        prot = protocol['domains'].get(domain, {}).get(operation_src, 1)
        if prot is None or prot == 0:
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
        prot = protocol['domains'].get(domain, {}).get(operation_dest, 1)
        if prot is None or prot == 0:
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
                return (dest_protocol['scheme'], src_protocol['scheme'], dest_protocol['domains'][domain][operation_dest], src_protocol['domains'][domain][operation_src])

    raise exception.RSEProtocolNotSupported('No protocol for provided settings found : %s.' % str(rse_settings_dest))


def _retry_protocol_stat(
        protocol: "RSEProtocol",
        pfn: str
) -> dict[str, Any]:
    """
    try to stat file, on fail try again 1s, 2s, 4s, 8s, 16s, 32s later. Fail is all fail

    :param protocol:     The protocol to use to reach this file
    :param pfn:          Physical file name of the target for the protocol stat
    """
    retries = config_get_int('client', 'protocol_stat_retries', raise_exception=False, default=6)
    for attempt in range(retries):
        try:
            stats = protocol.stat(pfn)
            return stats
        except exception.RSEChecksumUnavailable as e:
            # The stat succeeded here, but the checksum failed
            raise e
        except NotImplementedError:
            break
        except Exception:
            sleep(2**attempt)
    return protocol.stat(pfn)


def __check_compatible_scheme(
        dest_scheme: str,
        src_scheme: str
) -> bool:
    """
    Check if two schemes are compatible, such as srm and gsiftp

    :param dest_scheme:    Destination scheme
    :param src_scheme:     Source scheme
    :param scheme:         List of supported schemes
    :returns:              True if schemes are compatible, False otherwise.
    """

    if dest_scheme == src_scheme:
        return True
    if src_scheme in get_transfer_schemas().get(dest_scheme, []):
        return True

    return False
