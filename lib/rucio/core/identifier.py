# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <vincent.garonne@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import exception
from rucio.db import models
from rucio.db.session import get_session

session = get_session()


def list_replicas(scope, did):
    """
    List file replicas for a data identifier.

    :param scope: The scope name.
    :param did: The data identifier.
    """

    replicas = []
    try:
        query = session.query(models.RSEFileAssociation).filter_by(scope=scope, did=did, deleted=False)
        for replica in query:
            replicas.append({'size': replica.size, 'rse': replica.rse.rse, 'checksum': replica.checksum, 'pfn': replica.pfn})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found")

    return replicas


def add_identifier(scope, did, sources, issuer):
    """
    Add data identifier.

    :param scope: The scope name.
    :param did: The data identifier.
    :param sources: The content.
    :param issuer: The issuer account.
    """

    data_type = None

    # Get the correct child data type
    #
    # TODO: Disallow putting files into containers
    #
    for source in sources:
        query = session.query(models.DataIdentifier).filter_by(scope=source['scope'], did=source['did'], deleted=False)
        try:
            tmp_did = query.one()
            if tmp_did.type == models.DataIdType.FILE:
                source['type'] = models.DataIdType.FILE
                data_type = models.DataIdType.DATASET
            elif tmp_did.type == models.DataIdType.DATASET:
                source['type'] = models.DataIdType.DATASET
                data_type = models.DataIdType.CONTAINER
            elif tmp_did.type == models.DataIdType.CONTAINER:
                source['type'] = models.DataIdType.CONTAINER
                data_type = models.DataIdType.CONTAINER

        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % source)

    # Insert new data identifier with correct type
    new_did = models.DataIdentifier(scope=scope, did=did, owner=issuer, type=data_type)
    try:
        new_did.save(session=session)
    except IntegrityError, e:
        session.rollback()
        raise e

    # Insert content with correct type
    for source in sources:
        try:
            new_child = models.DataIdentifierAssociation(scope=scope, did=did, child_scope=source['scope'], child_did=source['did'], type=data_type, child_type=source['type'])
            new_child.save(session=session)
        except IntegrityError, e:
            session.rollback()
            raise e

    session.commit()


def list_content(scope, did):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param did: The data identifier.
    """

    dids = []
    try:
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, did=did, deleted=False)
        for tmp_did in query:
            dids.append({'scope': tmp_did.child_scope, 'did': tmp_did.child_did, 'type': tmp_did.child_type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % locals())

    return dids


def list_files(scope, did):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param did: The data identifier.
    """

    # TODO: Optional traverse hierarchy
    files = []
    try:
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, did=did, child_type=models.DataIdType.FILE, deleted=False)
        for tmp_file in query:
            files.append({'scope': tmp_file.child_scope, 'did': tmp_file.child_did, 'type': tmp_file.child_type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % locals())

    return files


def scope_list(scope):
    """
    List data identifiers in a scope.

    :param scope: The scope name.
    :returns: List of data identifiers dictionaries.
    """

    query = session.query(models.DataIdentifier).filter_by(scope=scope, deleted=False)

    dids = []
    try:
        for did in query.all():
            dids.append({'scope': scope, 'did': did.did, 'type': did.type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Scope '%(scope)s' not found" % locals())

    return dids


def get_did(scope, did):
    """
    Retrieve a single data identifier.

    :param scope: The scope name.
    :param did: The data identifier.
    """

    did_r = {'scope': None, 'did': None, 'type': None}
    try:
        r = session.query(models.DataIdentifier).filter_by(scope=scope, did=did, deleted=False).one()
        if r:
            did_r = {'scope': r.scope, 'did': r.did, 'type': r.type}
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % locals())

    return did_r
