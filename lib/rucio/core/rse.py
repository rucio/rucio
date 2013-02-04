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

import sqlalchemy
import sqlalchemy.orm

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased

from rucio.common import exception
from rucio.db import models
from rucio.db.history import versioned_session
from rucio.db.session import read_session, transactional_session


@transactional_session
def add_rse(rse, session=None):
    """
    Add a rse with the given location name.

    :param rse: the name of the new rse.
    :param session: The database session in use.
    """

    new_rse = models.RSE(rse=rse)
    try:
        new_rse.save(session=session)
    except IntegrityError:
        session.rollback()
        raise exception.Duplicate('RSE \'%(rse)s\' already exists!' % locals())

    session.commit()

    return new_rse.id


@read_session
def rse_exists(rse, session=None):
    """
    Checks to see if RSE exists. This procedure does not check its status.

    :param rse: Name of the rse.
    :param session: The database session in use.

    :returns: True if found, otherwise false.
    """
    return True if session.query(models.RSE).filter_by(rse=rse).first() else False


@transactional_session
def del_rse(rse, session=None):
    """
    Disable a rse with the given rse name.

    :param rse: the rse name.
    :param session: The database session in use.
    """

    try:
        old_rse = session.query(models.RSE).filter_by(rse=rse).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE \'%s\' cannot be found' % rse)

    old_rse.delete(session)
    session.commit()


@read_session
def get_rse(rse, session=None):
    """
    Get a RSE or raise if it does not exist.

    :param rse: the rse name.
    :param session: The database session in use.
    """
    try:
        query = session.query(models.RSE).filter_by(rse=rse)
        location = query.one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE \'%s\' cannot be found' % rse)
    return location


@read_session
def list_rses(filters={}, session=None):
    """
    Returns a list of all RSE names.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    returns: a list of all RSE names.
    """

    rse_list = []

    if filters:
        query = session.query(models.RSEAttrAssociation).\
            join(models.RSE, models.RSE.id == models.RSEAttrAssociation.rse_id).\
            filter_by(deleted=False)
        for (k, v) in filters.items():
            if hasattr(models.RSE, k):
                query = query.filter(getattr(models.RSE, k) == v)
            else:
                t = aliased(models.RSEAttrAssociation)
                query = query.join(t, t.rse_id == models.RSEAttrAssociation.rse_id)
                query = query.filter(t.key == k)
                query = query.filter(t.value == v)

        for row in query:
            if row.rse.rse not in rse_list:
                rse_list.append(row.rse.rse)
    else:

        query = session.query(models.RSE).filter_by(deleted=False).order_by(models.RSE.rse)
        for row in query:
            rse_list.append(row.rse)

    return rse_list


@transactional_session
def add_rse_attribute(rse, key, value, session=None):
    """ Adds a RSE attribute.

    :param rse: the rse name.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.
    :param session: The database session in use.

    returns: True is successfull
    """
    try:
        # Check location
        l = get_rse(rse=rse, session=session)

        query = session.query(models.RSEAttribute).filter(models.RSEAttribute.key == key).filter(models.RSEAttribute.value == value)
        if not query.count():
            new_attr = models.RSEAttribute(key=key, value=value)
            new_attr.save(session=session)

        try:
            new_rse_attr = models.RSEAttrAssociation(rse_id=l.id, key=key, value=value, deleted=False)
            new_rse_attr = session.merge(new_rse_attr)
            new_rse_attr.save(session=session)
            session.commit()
        except IntegrityError:
                raise exception.Duplicate("RSE attribute '%(key)s-%(value)s\' for RSE '%(rse)s' already exists!" % locals())
    finally:
        session.rollback()


@transactional_session
def del_rse_attribute(rse, key, session=None):
    """
    Delete a RSE attribute.

    :param rse: the name of the rse.
    :param key: the attribute key.
    :param session: The database session in use.

    :return: True if RSE attribute was deleted successfully else False.
    """
    l = get_rse(rse=rse, session=session)
    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=l.id, deleted=False).filter(models.RSEAttrAssociation.key == key)
    try:
        rse_attr = query.one()
        rse_attr.delete(session=session)
        session.commit()
    except:
        pass


@read_session
def list_rse_attributes(rse, session=None):
    """ List RSE attributes for a RSE.

    :param rse: the rse name.
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """
    rse_attrs = {}
    l = get_rse(rse=rse, session=session)

    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=l.id, deleted=False)
    for attr in query:
        rse_attrs[attr.key] = attr.value
    return rse_attrs


@transactional_session
def set_rse_usage(rse, source, total, free, session=None):
    """
    Set RSE usage information.

    :param rse: the location name.
    :param source: the information source, e.g. srm.
    :param total: the total space in bytes.
    :param free: the free in bytes.
    :param session: The database session in use.

    :returns: True if successfull, otherwise false.
    """

    rse = session.query(models.RSE).filter_by(rse=rse).one()

    rse_usage = models.RSEUsage(rse_id=rse.id, source=source, total=total, free=free)

    versioned_session(session)
    merged_rse_usage = session.merge(rse_usage)
    merged_rse_usage.save(session=session)

    session.commit()
    return True


@read_session
def get_rse_usage(rse, filters=None, session=None):
    """
    get rse usage information.

    :param rse: the rse name.
    :param filters: dictionary of attributes by which the results should be filtered
    :param session: The database session in use.

    :returns: True if successfull, otherwise false.
    """

    query = session.query(models.RSEUsage).\
        join(models.RSE, models.RSE.id == models.RSEUsage.rse_id).\
        filter_by(rse=rse)

    if filters:
        for (k, v) in filters.items():
            if hasattr(models.RSEUsage, k):
                query = query.filter(getattr(models.RSEUsage, k) == v)

    result = list()
    for usage in query:
        result.append({'rse': usage.rse.rse, 'source': usage.source,
                       'total': usage.total, 'free': usage.free,
                       'updated_at': usage.updated_at})
    return result


@read_session
def get_rse_usage_history(rse, filters=None, session=None):
    """
    get location usage history information.

    :param location: The location name.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns:  list of locations.
    """
    result = list()
    query = session.query(models.LocationUsage.__history_mapper__.class_)
    for usage in query:
        result.append({'location': usage.location.location, 'source': usage.source, usage.name: usage.value, 'updated_at': usage.updated_at})


@transactional_session
def add_file_replica(rse, scope, name, size, checksum, issuer, dsn=None, pfn=None, meta=None, rules=None, session=None):
    """
    Add File replica.

    :param rse: the rse name.
    :param scope: the tag name.
    :param name: The data identifier name.
    :param size: the size of the file.
    :param checksum: the checksum of the file.
    :param issuer: The issuer account.
    :param pfn: Physical file name (for nondeterministic rse).
    :meta: Meta-data associated with the file. Represented as key/value pairs in a dictionary.
    :rules: Replication rules associated with the file. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param session: The database session in use.

    :returns: True is successfull.
    """
    new_data_id = models.DataIdentifier(scope=scope, name=name, owner=issuer, type=models.DataIdType.FILE)
    new_file = models.File(scope=scope, name=name, owner=issuer, size=size, checksum=checksum)
    replica_rse = get_rse(rse=rse, session=session)
    new_replica = models.RSEFileAssociation(rse_id=replica_rse.id, scope=scope, name=name, size=size, checksum=checksum, state='AVAILABLE')

    # Add optional pfn
    try:
        new_data_id = session.merge(new_data_id)
        new_file = session.merge(new_file)
        new_data_id.save(session=session)
        new_file.save(session=session)
    except IntegrityError, e:
        'columns scope, name are not unique'
        # needs to parse the exception string
        print e
        session.rollback()

    try:
        new_replica.save(session=session)
    except IntegrityError, e:
        print e
        session.rollback()
        raise exception.Duplicate("File replica '%(scope)s:%(name)s-%(rse)s' already exists!" % locals())

    # Insert dataset and content
    if dsn:
        new_dsn = models.DataIdentifier(scope=dsn['scope'], name=dsn['name'], owner=issuer, type=models.DataIdType.DATASET)
        try:
            new_dsn = session.merge(new_dsn)
            new_dsn.save(session=session)
        except IntegrityError, e:
            # needs to parse the exception string
            session.rollback()

        new_child = models.DataIdentifierAssociation(scope=dsn['scope'], name=dsn['name'], child_scope=scope, child_name=name, type=models.DataIdType.DATASET, child_type=models.DataIdType.FILE)
        try:
            new_child.save(session=session)
        except IntegrityError, e:
           # needs to parse the exception string
            session.rollback()

    session.commit()


@read_session
def list_replicas(rse, filters={}, session=None):
    """
    List RSE File replicas.

    :param rse: the rse name.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns: a list of dictionary replica.
    """

    rse = session.query(models.RSE).filter_by(rse=rse).one()

    query = session.query(models.RSEFileAssociation).filter_by(rse_id=rse.id)
    if filters:
        for (k, v) in filters.items():
            query = query.filter(getattr(models.RSEFileAssociation, k) == v)

    for row in query:
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        yield d


@transactional_session
def update_file_replica_state(rse, scope, name, state, session=None):
    """
    Update File replica information and state.

    :param rse: the rse name.
    :param scope: the tag name.
    :param name: The data identifier name.
    :param state: The state.
    :param session: The database session in use.
    """

    rse = session.query(models.RSE).filter_by(rse=rse).one()
    session.query(models.RSEFileAssociation).filter_by(rse_id=rse.id, scope=scope, name=name).update({'state': state})
    session.commit()
