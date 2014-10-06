# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from rucio.api import permission
from rucio.core import replica
from rucio.common import exception
from rucio.common.schema import validate_schema


def declare_bad_file_replicas(pfns, rse, issuer):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    :param issuer: The issuer account.
    """
    kwargs = {}
    if not permission.has_permission(issuer=issuer, action='declare_bad_file_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not declare bad replicas on %s' % (issuer, rse))
    return replica.declare_bad_file_replicas(pfns=pfns, rse=rse)


def get_did_from_pfns(pfns, rse):
    """
    Get the DIDs associated to a PFN on one given RSE

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    :returns: A dictionary {pfn: {'scope': scope, 'name': name}}
    """
    return replica.get_did_from_pfns(pfns=pfns, rse=rse)


def list_replicas(dids, schemes=None, unavailable=False, request_id=None, ignore_availability=True):
    """
    List file replicas for a list of data identifiers.

    :param dids: The list of data identifiers (DIDs).
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param unavailable: Also include unavailable replicas in the list.
    :param request_id: ID associated with the request for debugging.
    """
    validate_schema(name='r_dids', obj=dids)
    return replica.list_replicas(dids=dids, schemes=schemes, unavailable=unavailable, request_id=request_id, ignore_availability=ignore_availability)


def add_replicas(rse, files, issuer, ignore_availability=False):
    """
    Bulk add file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param ignore_availability: Ignore the RSE blacklisting.

    :returns: True is successful, False otherwise
    """
    validate_schema(name='dids', obj=files)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='add_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add file replicas on %s' % (issuer, rse))
    if not permission.has_permission(issuer=issuer, action='skip_availability_check', kwargs=kwargs):
        ignore_availability = False
    replica.add_replicas(rse=rse, files=files, account=issuer, ignore_availability=ignore_availability)


def delete_replicas(rse, files, issuer, ignore_availability=False):
    """
    Bulk delete file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param ignore_availability: Ignore the RSE blacklisting.

    :returns: True is successful, False otherwise
    """
    validate_schema(name='r_dids', obj=files)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='delete_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete file replicas on %s' % (issuer, rse))
    if not permission.has_permission(issuer=issuer, action='skip_availability_check', kwargs=kwargs):
        ignore_availability = False
    replica.delete_replicas(rse=rse, files=files, ignore_availability=ignore_availability)


def update_replicas_states(rse, files, issuer):

    """
    Update File replica information and state.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    """
    validate_schema(name='dids', obj=files)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='update_replicas_states', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update file replicas state on %s' % (issuer, rse))
    replicas = []
    for file in files:
        rep = file
        rep['rse'] = rse
        replicas.append(rep)
    replica.update_replicas_states(replicas=replicas)
