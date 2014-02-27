# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from rucio.api import permission
from rucio.core import replica
from rucio.common import exception


def declare_bad_file_replicas(pfns, rse):
    """
    Get a list of replicas and declare them bad

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    """
    return replica.declare_bad_file_replicas(pfns=pfns, rse=rse)


def get_did_from_pfns(pfns, rse):
    """
    Get the DIDs associated to a PFN on one given RSE

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    :returns: A dictionary {pfn: {'scope': scope, 'name': name}}
    """
    return replica.get_did_from_pfns(pfns=pfns, rse=rse)


def list_replicas(dids, schemes=None, unavailable=False):
    """
    List file replicas for a list of data identifiers.

    :param dids: The list of data identifiers (DIDs).
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param unavailable: Also include unavailable replicas in the list.
    """
    return replica.list_replicas(dids=dids, schemes=schemes, unavailable=unavailable)


def add_replicas(rse, files, issuer):
    """
    Bulk add file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param account: The account owner. If None, then issuer is selected.

    :returns: True is successful, False otherwise
    """
    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='add_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add file replicas on %s' % (issuer, rse))
    replica.add_replicas(rse=rse, files=files, account=issuer)


def delete_replicas(rse, files, issuer):
    """
    Bulk delete file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param account: The account owner. If None, then issuer is selected.

    :returns: True is successful, False otherwise
    """
    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='delete_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete file replicas on %s' % (issuer, rse))
    replica.delete_replicas(rse=rse, files=files)
