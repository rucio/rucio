# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import and_, or_

from rucio.common import exception
from rucio.core.account import account_exists
from rucio.db import models1 as models
from rucio.db.session import get_session

session = get_session()

# DATA IDENTIFIER FUNCTIONALITY


def list_replicas(scope, name):
    """
    List file replicas for a data_id.

    :param scope:   The scope name.
    :param dsn:     The name.

    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        data_id = query.one()
    except NoResultFound, error:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    if data_id.type == models.DataIdType.FILE:
        files = [(scope, name), ]
    else:
        files = list()
        data_ids = [(scope, name), ]
        while data_ids:
            s, n = data_ids.pop()
            query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, name=n, deleted=False)
            for data_id in query:
                if data_id.child_type == models.DataIdType.FILE:
                    file = (data_id.child_scope, data_id.child_name)
                    if file not in files:
                        files.append(file)
                else:
                    data_ids.append((data_id.child_scope, data_id.child_name))

    replicas = {}
    for s, n in files:
        query = session.query(models.RSEFileAssociation).filter_by(scope=s, name=n, deleted=False)
        rows = list()
        for replica in query:
            rows.append({'size': replica.size, 'rse': replica.rse.rse, 'checksum': replica.checksum, 'pfn': replica.pfn})
        replicas['%(s)s:%(n)s' % locals()] = rows
    return replicas


def add_identifier(scope, name, sources, issuer):
    """
    Add dataset/container

    :param scope:   The scope name.
    :param name:    The name.
    :param sources: The content.
    :param issuer: The issuer account.

    """
    data_type = None
    child_type = None
    # Check content
    for source in sources:
        query = session.query(models.DataIdentifier).filter_by(scope=source['scope'], name=source['name'], deleted=False)
        try:
            data_id = query.one()
            if data_id.type == models.DataIdType.FILE:
                tmp_data_type = models.DataIdType.DATASET
            elif data_id.type == models.DataIdType.DATASET or data_id.type == models.DataIdType.CONTAINER:
                tmp_data_type = models.DataIdType.CONTAINER

            if not data_type:
                data_type = tmp_data_type
                child_type = data_id.type
            elif tmp_data_type != tmp_data_type:
                # To change
                raise exception.DataIdentifierNotFound("Can not mixed data identifiers" % locals())
        except NoResultFound, error:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % source)

    # Insert dataset/container
    new_data_id = models.DataIdentifier(scope=scope, name=name, owner=issuer, type=data_type)
    try:
        new_data_id.save(session=session)
    except IntegrityError, e:
        # needs to parse the exception string
        print e
        session.rollback()

    # Insert content
    for source in sources:
        try:
            new_child = models.DataIdentifierAssociation(scope=scope, name=name, child_scope=source['scope'], child_name=source['name'], type=data_type, child_type=data_id.type)
            new_child.save(session=session)
        except IntegrityError, e:
           # needs to parse the exception string
            print e
            session.rollback()

    session.commit()


def list_content(scope, name):
    """
    List dataset/container contents.

    :param scope:   The scope name.
    :param dsn:     The name.

    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        data_id = query.one()
    except NoResultFound, error:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    data_ids = list()
    query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, deleted=False)
    for data_id in query:
        data_ids.append({'name': data_id.child_name, 'scope': data_id.child_scope})
    return data_ids


def list_files(scope, name):
    """
    List container/dataset file contents.

    :param scope:   The scope name.
    :param dsn:     The name.

    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        data_id = query.one()
    except NoResultFound, error:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    files = list()
    data_ids = [(scope, name), ]
    while data_ids:
        s, n = data_ids.pop()
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, name=n, deleted=False)
        for data_id in query:
            if data_id.child_type == models.DataIdType.FILE:
                file = {'scope': data_id.child_scope, 'name': data_id.child_name}
                if file not in files:
                    files.append(file)
            else:
                data_ids.append((data_id.child_scope, data_id.child_name))

    return files
