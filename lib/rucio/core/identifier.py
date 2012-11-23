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
    query = session.query(models.DataIdentifier).filter_by(scope=scope, did=did, deleted=False)
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % locals())

    if did.type == models.DataIdType.FILE:
        files = [(scope, did), ]
    else:
        files = list()
        dids = [(scope, did), ]
        while dids:
            s, n = dids.pop()
            query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, did=n, deleted=False)
            for tmp_did in query:
                if tmp_did.child_type == models.DataIdType.FILE:
                    file = (tmp_did.child_scope, tmp_did.child_name)
                    if file not in files:
                        files.append(file)
                else:
                    dids.append((tmp_did.child_scope, tmp_did.child_name))

    replicas = {}
    for s, n in files:
        query = session.query(models.RSEFileAssociation).filter_by(scope=s, did=n, deleted=False)
        rows = list()
        for replica in query:
            rows.append({'size': replica.size, 'rse': replica.rse.rse, 'checksum': replica.checksum, 'pfn': replica.pfn})
        replicas['%(s)s:%(n)s' % locals()] = rows
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

    query = session.query(models.DataIdentifier).filter_by(scope=scope, did=did, deleted=False)
    try:
        query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % locals())

    dids = list()
    query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, did=did, deleted=False)
    for tmp_did in query:
        dids.append({'name': tmp_did.child_name, 'scope': tmp_did.child_scope})
    return dids


def list_files(scope, did):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param did: The data identifier.
    """

    query = session.query(models.DataIdentifier).filter_by(scope=scope, did=did, deleted=False)
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % locals())

    files = list()
    dids = [(scope, did), ]
    while dids:
        s, n = dids.pop()
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, did=n, deleted=False)
        for tmp_did in query:
            if tmp_did.child_type == models.DataIdType.FILE:
                file = {'scope': tmp_did.child_scope, 'name': tmp_did.child_name}
                if file not in files:
                    files.append(file)
            else:
                dids.append((tmp_did.child_scope, tmp_did.child_name))

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
