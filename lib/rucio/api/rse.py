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
from rucio.core import inode as inode_core


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


def add_rse_tag(rse, tag, issuer, description=None):
    """ Tags a RSE.

    :param rse: the rse name.
    :param tag: the tag name.
    :param description: Description of the rse, e.g. cloud, site, etc.
    :param issuer: The issuer account.


    returns: True is successfull
    """
    kwargs = {'rse': rse, 'tag': tag, 'description': description}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_rse_tag', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not tag RSE' % (issuer))

    return rse_core.add_rse_tag(rse=rse, tag=tag, description=description)


def list_rse_tags(filters=None):
    """ List RSE tags.

    :param filters: dictionary of attributes by which the results should be filtered.

    :returns: List of all RSE tags.
    """
    return rse_core.list_rse_tags(filters=filters)


def add_file_replica(rse, scope, lfn, issuer):
    """ Add File replica.

    :param rse: the rse name.
    :param scope: the tag name.
    :param lfn: The file name.
    :param issuer: The issuer account.

    :returns: True is successfull.
    """
    try:
        inode_core.register_file(scope=scope, filename=lfn, account=issuer)
    except FileAlreadyExists:
        pass
    inode_core.add_file_replica(rse=rse, scope=scope, filename=lfn)
