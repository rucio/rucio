# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from rucio.api import permission
from rucio.db.sqla.constants import BadFilesStatus
from rucio.core import replica
from rucio.common import exception
from rucio.common.schema import validate_schema


def get_bad_replicas_summary(rse_expression=None, from_date=None, to_date=None):
    """
    List the bad file replicas summary. Method used by the rucio-ui.
    :param rse_expression: The RSE expression.
    :param from_date: The start date.
    :param to_date: The end date.
    :param session: The database session in use.
    """
    return replica.get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date)


def list_bad_replicas_status(state=BadFilesStatus.BAD, rse=None, younger_than=None, older_than=None, limit=None, list_pfns=False):
    """
    List the bad file replicas history states. Method used by the rucio-ui.
    :param state: The state of the file (SUSPICIOUS or BAD).
    :param rse: The RSE name.
    :param younger_than: datetime object to select bad replicas younger than this date.
    :param older_than:  datetime object to select bad replicas older than this date.
    :param limit: The maximum number of replicas returned.
    """
    return replica.list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than, older_than=older_than, limit=limit, list_pfns=list_pfns)


def declare_bad_file_replicas(pfns, reason, issuer):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    """
    kwargs = {}
    if not permission.has_permission(issuer=issuer, action='declare_bad_file_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not declare bad replicas' % (issuer))
    return replica.declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=issuer, status=BadFilesStatus.BAD)


def declare_suspicious_file_replicas(pfns, reason, issuer):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    """
    kwargs = {}
    if not permission.has_permission(issuer=issuer, action='declare_bad_file_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not declare suspicious replicas' % (issuer))
    return replica.declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=issuer, status=BadFilesStatus.SUSPICIOUS)


def get_did_from_pfns(pfns, rse):
    """
    Get the DIDs associated to a PFN on one given RSE

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    :returns: A dictionary {pfn: {'scope': scope, 'name': name}}
    """
    return replica.get_did_from_pfns(pfns=pfns, rse=rse)


def list_replicas(dids, schemes=None, unavailable=False, request_id=None,
                  ignore_availability=True, all_states=False, rse_expression=None):
    """
    List file replicas for a list of data identifiers.

    :param dids: The list of data identifiers (DIDs).
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param unavailable: Also include unavailable replicas in the list.
    :param request_id: ID associated with the request for debugging.
    :param all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
    :param rse_expression: The RSE expression to restrict replicas on a set of RSEs.
    """
    validate_schema(name='r_dids', obj=dids)
    return replica.list_replicas(dids=dids, schemes=schemes, unavailable=unavailable,
                                 request_id=request_id,
                                 ignore_availability=ignore_availability,
                                 all_states=all_states, rse_expression=rse_expression)


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


def list_dataset_replicas(scope, name):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.

    :returns: A list of dict dataset replicas
    """
    return replica.list_dataset_replicas(scope=scope, name=name)


def list_datasets_per_rse(rse, filters=None, limit=None):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param limit: limit number.
    :param session: Database session to use.

    :returns: A list of dict dataset replicas
    """
    return replica.list_datasets_per_rse(rse, filters=filters, limit=limit)
