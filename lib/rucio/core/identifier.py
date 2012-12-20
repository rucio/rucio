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

from re import match

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import exception
from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
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
        query = session.query(models.RSEFileAssociation).filter_by(scope=scope, did=did, state='AVAILABLE', deleted=False)
        for replica in query:
            replicas.append({'scope': replica.scope, 'did': replica.did, 'size': replica.size,
                             'rse': replica.rse.rse, 'checksum': replica.checksum, 'pfn': replica.pfn})
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
        if e.args[0] == "(IntegrityError) columns scope, did are not unique":
            pass
            # Check the DI types
            #raise exception.DataIdentifierAlreadyExists('The data identifier %(scope)s:%(did)s' % locals())
        else:
            raise e

    # Insert content with correct type
    for source in sources:
        try:
            new_child = models.DataIdentifierAssociation(scope=scope, did=did, child_scope=source['scope'], child_did=source['did'], type=data_type, child_type=source['type'])
            new_child.save(session=session)
        except IntegrityError, e:
            session.rollback()
            if e.args[0] == '(IntegrityError) columns scope, did, child_scope, child_did are not unique':
                raise exception.DuplicateContent('The data identifier {0[source][scope]}:{0[source][did]} has been already added to {0[scope]}:{0[did]}.'.format(locals()))
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


def set_metadata(scope, did, key, value):
    """
    Add metadata to data identifier.

    :param scope: The scope name.
    :param did: The data identifier.
    :param key: the key.
    :param value: the value.
    """
    new_meta = models.DIDAttribute(scope=scope, did=did, key=key, value=value)
    try:
        new_meta.save(session=session)
    except IntegrityError, e:
        session.rollback()
        print e.args[0]
        if e.args[0] == "(IntegrityError) foreign key constraint failed":
            raise exception.KeyNotFound("Key '%(key)s' not found" % locals())
        if e.args[0] == "(IntegrityError) columns scope, did, key are not unique":
            raise exception.Duplicate('Metadata \'%(key)s-%(value)s\' already exists!' % locals())
        raise e

    # Check enum types
    enum = session.query(models.DIDKeyValueAssociation).filter_by(key=key, deleted=False).first()
    if enum:
        try:
            session.query(models.DIDKeyValueAssociation).filter_by(key=key, deleted=False, value=value).one()
        except NoResultFound:
            session.rollback()
            raise exception.InvalidValueForKey('The value %(value)s is invalid for the key %(key)s' % locals())

    # Check constraints
    k = session.query(models.DIDKey).filter_by(key=key).one()

    # Check value against regexp, if defined
    if k.regexp and not match(k.regexp, value):
        session.rollback()
        raise exception.InvalidValueForKey('The value %s for the key %s does not match the regular expression %s' % (value, key, k.regexp))

    # Check value type, if defined
    type_map = dict([(str(t), t) for t in AUTHORIZED_VALUE_TYPES])
    if k.type and not isinstance(value, type_map.get(k.type)):
            session.rollback()
            raise exception.InvalidValueForKey('The value %s for the key %s does not match the required type %s' % (value, key, k.type))

    session.commit()


def get_metadata(scope, did):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param did: The data identifier.
    """
    meta = {}
    query = session.query(models.DIDAttribute).filter_by(scope=scope, did=did, deleted=False)
    for row in query:
        meta[row.key] = row.value
    return meta
