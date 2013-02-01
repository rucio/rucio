# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013

from re import match

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import exception
from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
from rucio.core.rse import add_file_replica
from rucio.db import models
from rucio.db.session import get_session
from rucio.rse import rsemanager


session = get_session()


def list_replicas(scope, name, protocols=None):
    """
    List file replicas for a data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param protocols: A list of protocols to filter the replicas."
    """

    rsemgr = rsemanager.RSEMgr()
    try:
        query = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name, state='AVAILABLE', deleted=False)
        for row in query:
            try:
                pfns = list()
                for protocol in rsemgr.list_protocols(rse_id=row.rse.rse):
                    if not protocols or protocol in protocols:
                        pfns.append(rsemgr.lfn2pfn(rse_id=row.rse.rse, scope=scope, lfn=name, protocol=protocol))

                if pfns:
                    yield {'scope': row.scope, 'name': row.name, 'size': row.size,
                           'rse': row.rse.rse, 'checksum': row.checksum, 'pfns': pfns}
            except (exception.RSENotFound, exception.SwitchProtocol):
                pass
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found")


def add_identifier(scope, name, sources, issuer):
    """
    Add data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param sources: The content.
    :param issuer: The issuer account.
    """
    # session.begin(subtransactions=True)
    data_type = None

    # Get the correct child data type
    #
    # TODO: Disallow putting files into containers
    #

    data_type = None
    child_type = None
    for source in sources:
        query = session.query(models.DataIdentifier).filter_by(scope=source['scope'], name=source['name'], deleted=False)
        try:
            tmp_did = query.one()
            if tmp_did.type == models.DataIdType.FILE:
                child_type = models.DataIdType.FILE
                data_type = models.DataIdType.DATASET
            elif tmp_did.type == models.DataIdType.DATASET:
                child_type = models.DataIdType.DATASET
                data_type = models.DataIdType.CONTAINER
            elif tmp_did.type == models.DataIdType.CONTAINER:
                child_type = models.DataIdType.CONTAINER
                data_type = models.DataIdType.CONTAINER
        except NoResultFound:
            data_type = models.DataIdType.DATASET
            child_type = models.DataIdType.FILE
            if 'rse' not in source:
                raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % source)
            add_file_replica(issuer=issuer, **source)

    # Insert new data identifier with correct type
    new_did = models.DataIdentifier(scope=scope, name=name, owner=issuer, type=data_type, open=True)
    try:
        new_did.save(session=session)
    except IntegrityError, e:
        session.rollback()
        if e.args[0] == "(IntegrityError) columns scope, name are not unique":
            raise exception.DataIdentifierAlreadyExists('Data identifier %(scope)s:%(name)s already exists!' % locals())
        # msg for oracle / mysql
        else:
            raise e

    # Insert content with correct type
    for source in sources:
        try:
            new_child = models.DataIdentifierAssociation(scope=scope, name=name, child_scope=source['scope'], child_name=source['name'], type=data_type, child_type=child_type)
            new_child.save(session=session)
        except IntegrityError, e:
            session.rollback()
            if e.args[0] == '(IntegrityError) columns scope, name, child_scope, child_name are not unique':
                raise exception.DuplicateContent('The data identifier {0[source][scope]}:{0[source][name]} has been already added to {0[scope]}:{0[name]}.'.format(locals()))
            raise

    session.commit()


def append_identifier(scope, name, sources, issuer):
    """
    Append data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param sources: The content.
    :param issuer: The issuer account.
    """
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        did = query.one()
        if not did.open:
            raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is closed" % locals())
        if did.type == models.DataIdType.FILE:
            raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is a file" % locals())
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    child_type = models.DataIdType.FILE
    for source in sources:
        query = session.query(models.DataIdentifier).filter_by(scope=source['scope'], name=source['name'], deleted=False)
        try:
            query.one()
            # check the types...
        except NoResultFound:
            child_type = models.DataIdType.FILE
            if 'rse' not in source:
                raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % source)
            add_file_replica(issuer=issuer, **source)

        try:
            new_child = models.DataIdentifierAssociation(scope=scope, name=name, child_scope=source['scope'], child_name=source['name'], type=did.type, child_type=child_type)
            new_child.save(session=session)
        except IntegrityError, e:
            session.rollback()
            if e.args[0] == '(IntegrityError) columns scope, name, child_scope, child_name are not unique':
                raise exception.DuplicateContent('The data identifier {0[source][scope]}:{0[source][name]} has been already added to {0[scope]}:{0[name]}.'.format(locals()))
            raise e
    session.commit()


def list_content(scope, name):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    """

    dids = []
    try:
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, deleted=False)
        for tmp_did in query:
            dids.append({'scope': tmp_did.child_scope, 'name': tmp_did.child_name, 'type': tmp_did.child_type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    return dids


def list_files(scope, name):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    """

    # TODO: Optional traverse hierarchy
    files = []
    try:
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, child_type=models.DataIdType.FILE, deleted=False)
        for tmp_file in query:
            files.append({'scope': tmp_file.child_scope, 'name': tmp_file.child_name, 'type': tmp_file.child_type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

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
            dids.append({'scope': scope, 'name': did.name, 'type': did.type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Scope '%(scope)s' not found" % locals())

    return dids


def get_did(scope, name):
    """
    Retrieve a single data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    """

    did_r = {'scope': None, 'name': None, 'type': None}
    try:
        r = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False).one()
        if r:
            did_r = {'scope': r.scope, 'name': r.name, 'type': r.type,
                     'owner': r.owner, 'open': r.open}
            #  To add:  created_at, updated_at, deleted_at, deleted, monotonic, hidden, obsolete, complete
            #  ToDo: Add json encoder for datetime
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    return did_r


def set_metadata(scope, name, key, value):
    """
    Add metadata to data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param key: the key.
    :param value: the value.
    """
    new_meta = models.DIDAttribute(scope=scope, name=name, key=key, value=value)
    try:
        new_meta.save(session=session)
    except IntegrityError, e:
        session.rollback()
        print e.args[0]
        if e.args[0] == "(IntegrityError) foreign key constraint failed":
            raise exception.KeyNotFound("Key '%(key)s' not found" % locals())
        if e.args[0] == "(IntegrityError) columns scope, name, key are not unique":
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


def get_metadata(scope, name):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    """
    meta = {}
    query = session.query(models.DIDAttribute).filter_by(scope=scope, name=name, deleted=False)
    for row in query:
        meta[row.key] = row.value
    return meta


def set_status(scope, name, **kwargs):
    """
    Set data identifier status

    :param scope: The scope name.
    :param name: The data identifier name.
    :param kwargs:  Keyword arguments of the form status_name=value.
    """
    statuses = ['open', ]

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    values = {}
    for k in kwargs:
        if k not in statuses:
            raise exception.UnsupportedStatus("The status %(k)s is not a valid data identifier status." % locals())
        if k == 'open':
            query = query.filter_by(open=True).filter(models.DataIdentifier.type != "file")
            values['open'] = False

    rowcount = query.update(values)

    if not rowcount:
        query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)
        try:
            query.one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        raise exception.UnsupportedOperation("The status of the data identifier '%(scope)s:%(name)s' cannot be changed" % locals())

    session.commit()
