# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import rucio.api.permission

from rucio.common.exception import FileAlreadyExists
from rucio.core import rse as rse_core


def add_rse(rse, issuer):
        """
        Creates a new Rucio Location/RSE.

        :param rse: The rse name.
        :param issuer: The issuer account.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        kwargs = {'rse': rse}
        if not rucio.api.permission.has_permission(issuer=issuer, action='add_rse', kwargs=kwargs):
            raise rucio.common.exception.AccessDenied('Account %s can not add RSE' % (issuer))
        return rse_core.add_rse(rse)


def del_rse(rse, issuer):
        """
        Disables a RSE with the provided RSE name.

        :param rse: The rse name.
        :param issuer: The issuer account.
        """
        kwargs = {'rse': rse}
        if not rucio.api.permission.has_permission(issuer=issuer, action='del_rse', kwargs=kwargs):
            raise rucio.common.exception.AccessDenied('Account %s can not delete RSE' % (issuer))

        return rse_core.del_rse(rse)


def list_rses(filters=None):
    """
    Lists all the rses.

    :param filters: dictionary of attributes by which the results should be filtered.

    :returns: List of all RSEs.
    """
    return rse_core.list_rses()


def del_rse_attribute(rse, key, issuer):
    """
    Delete a RSE attribute.

    :param rse: the name of the rse.
    :param key: the attribute key.

    :return: True if RSE attribute was deleted successfully else False.
    """
    kwargs = {'rse': rse, 'key': key}
    if not rucio.api.permission.has_permission(issuer=issuer, action='del_rse_attribute', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete RSE attributes' % (issuer))

    return rse_core.del_rse_attribute(rse=rse, key=key)


def add_rse_attribute(rse, key, value, issuer):
    """ Adds a RSE attribute.

    :param rse: the rse name.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.


    returns: True is successfull
    """
    kwargs = {'rse': rse, 'key': key, 'value': value}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_rse_attribute', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add RSE attributes' % (issuer))

    return rse_core.add_rse_attribute(rse=rse, key=key, value=value)


def list_rse_attributes(rse):
    """ List RSE attributes for a RSE.

    :param rse: the rse name.

    :returns: List of all RSE attributes for a RSE.
    """
    return rse_core.list_rse_attributes(rse=rse)


def add_file_replica(rse, scope, name, size, checksum, issuer, dsn=None):
    """ Add File replica.

    :param rse: the rse name.
    :param scope: the tag name.
    :param name: The file name.
    :param size: the size of the file.
    :param checksum: the checksum of the file.
    :param issuer: The issuer account.
    :param dsn: the dataset name.

    :returns: True is successfull.
    """
    kwargs = {'rse': rse, 'scope': scope, 'name': name, 'size': size, 'checksum': checksum, 'dsn': dsn}
    if not rucio.api.permission.has_permission(issuer=issuer, action='scope, name, size, checksum, issuer', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add file replica on %s' % (issuer, rse))

    rse_core.add_file_replica(rse=rse, scope=scope, name=name, size=size, checksum=checksum, issuer=issuer, dsn=dsn)
