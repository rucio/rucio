# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013

from rucio.api import permission
from rucio.common import exception
from rucio.common.schema import validate_schema
from rucio.core import rse as rse_module


def add_rse(rse, issuer, prefix=None, deterministic=True, volatile=False):
    """
    Creates a new Rucio Location (RSE).

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param prefix: the base path of the rse.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    """
    validate_schema(name='rse', obj=rse)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='add_rse', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add RSE' % (issuer))
    return rse_module.add_rse(rse, prefix=prefix, deterministic=deterministic, volatile=volatile)


def get_rse(rse):
    """
    Provides details about the specified RSE.

    :param rse: The RSE name.
    :param issuer: The issuer account.

    :returns: a dict with details about the RSE

    :raises RSENotFound: if the referred RSE was ot found in the database
    """
    return rse_module.get_rse(rse)


def del_rse(rse, issuer):
    """
    Disables a RSE with the provided RSE name.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    """

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='del_rse', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete RSE' % (issuer))

    return rse_module.del_rse(rse)


def list_rses(filters=None):
    """
    Lists all the rses.

    :param filters: dictionary of attributes by which the results should be filtered.

    :returns: List of all RSEs.
    """

    return rse_module.list_rses()


def del_rse_attribute(rse, key, issuer):
    """
    Delete a RSE attribute.

    :param rse: the name of the rse_module.
    :param key: the attribute key.

    :return: True if RSE attribute was deleted successfully, False otherwise.
    """

    kwargs = {'rse': rse, 'key': key}
    if not permission.has_permission(issuer=issuer, action='del_rse_attribute', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete RSE attributes' % (issuer))

    return rse_module.del_rse_attribute(rse=rse, key=key)


def add_rse_attribute(rse, key, value, issuer):
    """ Adds a RSE attribute.

    :param rse: the rse name.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.

    returns: True if successful, False otherwise.
    """

    kwargs = {'rse': rse, 'key': key, 'value': value}
    if not permission.has_permission(issuer=issuer, action='add_rse_attribute', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add RSE attributes' % (issuer))

    return rse_module.add_rse_attribute(rse=rse, key=key, value=value)


def list_rse_attributes(rse):
    """
    List RSE attributes for a RSE_MODULE.

    :param rse: The RSE name.

    :returns: List of all RSE attributes for a RSE_MODULE.
    """

    return rse_module.list_rse_attributes(rse=rse)


def add_file_replica(rse, scope, name, size, issuer, adler32=None, md5=None, pfn=None, dsn=None):
    """
    Add File replica.

    :param rse: The RSE name.
    :param scope: The scope name.
    :param name: The data identifier name.
    :param size: The size of the file.
    :param issuer: The issuer account.
    :param md5: The md5 checksum.
    :param adler32: The adler32 checksum.
    :param pfn: the physical file name for non deterministic rse.
    :param dsn: The dataset name.

    :returns: True is successful, False otherwise
    """

    kwargs = {'rse': rse, 'scope': scope, 'name': name, 'size': size, 'md5': md5, 'adler32': adler32, 'dsn': dsn}
    if not permission.has_permission(issuer=issuer, action='add_file_replica', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add file replica on %s' % (issuer, rse))

    rse_module.add_file_replica(rse=rse, scope=scope, name=name, size=size, md5=md5, adler32=adler32, issuer=issuer, pfn=pfn, dsn=dsn)


def add_protocol(rse, issuer, **data):
    """
    Creates a new protocol entry for an existing RSE.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param data: Parameters (protocol identifier, port, hostname, ...) provided by the request.
    """

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='add_protocol', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add protocols to RSE %s' % (issuer, rse))
    rse_module.add_protocol(rse, data['data'])


def get_protocols(rse, issuer, protocol_domain='ALL', operation=None, default=False, scheme=None):
    """
    Returns all matching protocols (including detailed information) for the given RSE.

    :param rse: The name of the rse.
    :param issuer: The issuer account.
    :param protocol_domain: The scope of the protocol. Supported are 'LAN', 'WAN', and 'ALL" (as default).
    :param operation: The name of the requested operation (read, write, or delete).
                      If None, all operations are queried.
    :param default: Indicates if all or only the default protocols should be returned.
    :param scheme: The protocol identifier.

    :returns: A dict with all supported protocols and their attibutes.
    """
    return rse_module.get_protocols(rse, protocol_domain=protocol_domain, operation=operation, scheme=scheme, default=default)


def del_protocols(rse, issuer, scheme, hostname=None, port=None):
    """
    Deletes all matching protocol entries for the given RSE..

    :param rse: The name of the rse.
    :param issuer: The issuer account.
    :param scheme: The protocol identifier.
    :param hostname: The hostname (to be used if more then one protocol using the
                     same identifier are present)
    :param port: The port (to be used if more than one protocol using the same
                 identifier and hostname are present)
    """
    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='del_protocol', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete protocols from RSE %s' % (issuer, rse))
    rse_module.del_protocols(rse, scheme=scheme, hostname=hostname, port=port)


def update_protocols(rse, issuer, scheme, data, hostname=None, port=None):
    """
    Updates all provided attributes for all matching protocol entries of the given RSE..

    :param rse: The name of the rse.
    :param issuer: The issuer account.
    :param scheme: The protocol identifier.
    :param data: A dict including the attributes of the protocol to be updated. Keys must match the column names in the database.
    :param hostname: The hostname (to be used if more then one protocol using the same identifier are present)
    :param port: The port (to be used if more than one protocol using the same identifier and hostname are present)
    """
    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='update_protocol', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update protocols from RSE %s' % (issuer, rse))
    rse_module.update_protocols(rse, scheme=scheme, hostname=hostname, port=port, data=data)
