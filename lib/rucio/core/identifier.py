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


def list_replicas(scope, name):
    """
    List file replicas for a did.

    :param scope: The scope name.
    :param dsn: The name.

    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    if did.type == models.DataIdType.FILE:
        files = [(scope, name), ]
    else:
        files = list()
        dids = [(scope, name), ]
        while dids:
            s, n = dids.pop()
            query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, name=n, deleted=False)
            for did in query:
                if did.child_type == models.DataIdType.FILE:
                    file = (did.child_scope, did.child_name)
                    if file not in files:
                        files.append(file)
                else:
                    dids.append((did.child_scope, did.child_name))

    replicas = {}
    for s, n in files:
        query = session.query(models.RSEFileAssociation).filter_by(scope=s, name=n, deleted=False)
        rows = list()
        for replica in query:
            rows.append({'size': replica.size, 'rse': replica.rse.rse, 'checksum': replica.checksum, 'pfn': replica.pfn})
        replicas['%(s)s:%(n)s' % locals()] = rows
    return replicas


def add_identifier(scope, did, sources, issuer):
    """
    Add dataset/container

    :param scope: The scope name.
    :param name: The name.
    :param sources: The content.
    :param issuer: The issuer account.

    """
    data_type = None
    # Check content
    for source in sources:
        query = session.query(models.DataIdentifier).filter_by(scope=source['scope'], did=source['did'], deleted=False)
        try:
            tmp_did = query.one()
            if tmp_did.type == models.DataIdType.FILE:
                tmp_data_type = models.DataIdType.DATASET
            elif tmp_did.type == models.DataIdType.DATASET or tmp_did.type == models.DataIdType.CONTAINER:
                tmp_data_type = models.DataIdType.CONTAINER

            if not data_type:
                data_type = tmp_data_type
            elif tmp_data_type != tmp_data_type:
                # To change
                raise exception.DataIdentifierNotFound("Can not mixed data identifiers" % locals())
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(did)s' not found" % source)

    # Insert dataset/container
    new_did = models.DataIdentifier(scope=scope, did=did, owner=issuer, type=data_type)
    try:
        new_did.save(session=session)
    except IntegrityError, e:
        # needs to parse the exception string
        print e
        session.rollback()

    # Insert content
    for source in sources:
        try:
            new_child = models.DataIdentifierAssociation(scope=scope, did=did, child_scope=source['scope'], child_did=source['did'], type=data_type, child_type=did.type)
            new_child.save(session=session)
        except IntegrityError, e:
           # needs to parse the exception string
            print e
            session.rollback()

    session.commit()


def list_content(scope, name):
    """
    List dataset/container contents.

    :param scope: The scope name.
    :param dsn: The name.

    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    dids = list()
    query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, deleted=False)
    for did in query:
        dids.append({'name': did.child_name, 'scope': did.child_scope})
    return dids


def list_files(scope, name):
    """
    List container/dataset file contents.

    :param scope: The scope name.
    :param dsn: The name.

    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    files = list()
    dids = [(scope, name), ]
    while dids:
        s, n = dids.pop()
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, name=n, deleted=False)
        for did in query:
            if did.child_type == models.DataIdType.FILE:
                file = {'scope': did.child_scope, 'name': did.child_name}
                if file not in files:
                    files.append(file)
            else:
                dids.append((did.child_scope, did.child_name))

    return files
