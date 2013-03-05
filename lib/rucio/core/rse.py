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
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013


from re import match

import sqlalchemy
import sqlalchemy.orm

from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm import aliased

from rucio.common import exception
from rucio.db import models
from rucio.db.history import versioned_session
from rucio.db.session import read_session, transactional_session


@transactional_session
def add_rse(rse, prefix=None, deterministic=True, volatile=False, session=None):
    """
    Add a rse with the given location name.

    :param rse: the name of the new rse.
    :param prefix: the base path of the rse.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    :param session: The database session in use.
    """

    new_rse = models.RSE(rse=rse, prefix=prefix, deterministic=deterministic, volatile=volatile)
    try:
        new_rse.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('RSE \'%(rse)s\' already exists!' % locals())

    # Add rse name as a RSE-Tag
    add_rse_attribute(rse=rse, key=rse, value=True, session=session)

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
    old_rse.delete(session=session)
    del_rse_attribute(rse=rse, key=rse, session=session)


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
    # Check location
    l = get_rse(rse=rse, session=session)
    try:
        new_rse_attr = models.RSEAttrAssociation(rse_id=l.id, key=key, value=value)
        new_rse_attr = session.merge(new_rse_attr)
        new_rse_attr.save(session=session)
    except IntegrityError:
        raise exception.Duplicate("RSE attribute '%(key)s-%(value)s\' for RSE '%(rse)s' already exists!" % locals())


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
    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=l.id).filter(models.RSEAttrAssociation.key == key)
    rse_attr = query.one()
    rse_attr.delete(session=session)


@read_session
def list_rse_attributes(rse, session=None):
    """ List RSE attributes for a RSE.

    :param rse: the rse name.
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """
    rse_attrs = {}
    l = get_rse(rse=rse, session=session)

    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=l.id)
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
    replica_rse = get_rse(rse=rse, session=session)
    path = None
    if not replica_rse.deterministic:
        if not pfn:
            raise exception.UnsupportedOperation('PFN needed for this (non deterministic) RSE %(rse)s ' % locals())

        # Needs to add the parsing of the pfn to check if it matches a supported protocol
        # if the syntax is correct
        # extract the path
        path = ''

    else:
        if pfn:
            raise exception.UnsupportedOperation('PFN not needed for this (deterministic) RSE %(rse)s ' % locals())

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, type=models.DataIdType.FILE, deleted=False)
    if not query.first():
        try:
            new_data_id = models.DataIdentifier(scope=scope, name=name, owner=issuer, type=models.DataIdType.FILE)
            new_file = models.File(scope=scope, name=name, owner=issuer, size=size, checksum=checksum)
            new_data_id = session.merge(new_data_id)
            new_file = session.merge(new_file)
            new_data_id.save(session=session)
            new_file.save(session=session)
        except IntegrityError, e:
            if e.args[0] == "(IntegrityError) foreign key constraint failed":
                raise exception.ScopeNotFound('Scope %(scope)s not found!' % locals())
            raise

    new_replica = models.RSEFileAssociation(rse_id=replica_rse.id, scope=scope, name=name, size=size, checksum=checksum, path=path, state='AVAILABLE')
    try:
        new_replica.save(session=session)
    except IntegrityError:
        raise exception.Duplicate("File replica '%(scope)s:%(name)s-%(rse)s' already exists!" % locals())


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

    rid = get_rse(rse=rse, session=session).id
    session.query(models.RSEFileAssociation).filter_by(rse_id=rid, scope=scope, name=name).update({'state': state})


@transactional_session
def add_protocol(rse, parameter, session=None):
    """
    Add a protocol to an existing RSE. If entries with equal or less priority for
    an operation exist, the existing one will be reorded (i.e. +1).

    :param rse: the name of the new rse.
    :param parameter: parameters of the new protocol entry.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises Duplicate: If protocol with identifier, hostname and port already exists
                       for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')
    # Inster new protocol entry
    parameter['rse_id'] = rid
    try:
        new_protocol = models.RSEProtocols()
        new_protocol.update(parameter)
        new_protocol.save(session=session)
        # Updated priority numbers
        for op in ['read', 'write', 'delete']:
            if (op in parameter) and (parameter[op] != -1):
                f = sqlalchemy.and_(getattr(models.RSEProtocols, op) >= parameter[op], models.RSEProtocols.rse_id == rid)
                query = session.query(models.RSEProtocols).filter(f)
                for row in query:
                    setattr(row, op, getattr(row, op) + 1)
        __fill_gaps(rid, session)
    except IntegrityError, e:
        if 'not unique' in e.args[0]:
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (parameter['protocol'], parameter['port'], rse, parameter['hostname']))
        elif match('.*IntegrityError.*ORA-00001: unique constraint.*RSE_PROTOCOLS_PK.*violated.*', e.args[0]):
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (parameter['protocol'], parameter['port'], rse, parameter['hostname']))
        elif 'may not be NULL' in e.args[0]:
            raise exception.InvalidObject('Invalid values: %s' % e.args[0])
        elif match('.*IntegrityError.*ORA-01400: cannot insert NULL into.*RSE_PROTOCOLS.*IMPL.*', e.args[0]):
            raise exception.InvalidObject('Invalid values!')
        raise e
    return new_protocol


@read_session
def get_protocols(rse, operation=None, default=False, protocol=None, session=None):
    """
    Returns protocol information. Parameter comibantions are: (operation OR default) XOR protocol.

    :param rse: The name of the rse.
    :param operation: The name of the requested operation (read, write, or delete).
                      If None, all operations are queried.
    :param default: Indicates if only the default operations should be returned.
    :param protocol: The name of the requested protocol.
    :param session: The database session.

    :returns: A list with details about each matching protocol.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing protocol was found for the given RSE.
    :raises RSEOperationNotSupported: If no protocol supported the requested operation for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')
    query = None
    if protocol:
        query = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                          models.RSEProtocols.protocol == protocol))
    else:
        if operation:
            if default:
                query = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                  getattr(models.RSEProtocols, operation) == 1))
            else:
                query = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                  getattr(models.RSEProtocols, operation) > 0)
                                                                  ).order_by(getattr(models.RSEProtocols, operation))
        else:
            if default:
                query = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                  sqlalchemy.or_(models.RSEProtocols.read == 1,
                                                                                                 models.RSEProtocols.write == 1,
                                                                                                 models.RSEProtocols.delete == 1
                                                                                                 )))
            else:
                query = session.query(models.RSEProtocols).filter(models.RSEProtocols.rse_id == rid)
    protocols = list()
    for row in query:
        protocols.append({'hostname': row.hostname,
                          'protocol': row.protocol,
                          'port': row.port,
                          'prefix': row.prefix,
                          'impl': row.impl,
                          'read': row.read,
                          'write': row.write,
                          'delete': row.write,
                          'extended_attributes': row.extended_attributes
                          })
    if not protocols:
        if operation:
            raise exception.RSEOperationNotSupported('RSE \'%s\' has no protocol defined for operation \'%s\'' % (rse, operation))
        else:
            raise exception.RSEProtocolNotSupported('RSE \'%s\' does not support protocol \'%s\'' % (rse, protocol))
    return protocols


@transactional_session
def update_protocols(rse, protocol, data, hostname=None, port=None, session=None):
    """
    Updates an existing protocol entry for an RSE. If necessary, priorities for read,
    write, and delete operations of other protocol entires will be updated too.

    :param rse: the name of the new rse.
    :param protocol: Protocol identifer.
    :param data: Dict with new values (keys must match column names in the database).
    :param hostname: Hostname defined for the protocol, used if more than one protocol
                     is registered with the same identifier.
    :param port: The port registered for the hostename, used if more than one protocol
                 is regsitered with the same identifier and hostname.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing protocol was found for the given RSE.
    :raises KeyNotFound: Invalid data for update provided.
    :raises Duplicate: If protocol with identifier, hostname and port already exists
                       for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')

    f = sqlalchemy.and_(models.RSEProtocols.rse_id == rid, models.RSEProtocols.protocol == protocol)
    if hostname:
        f = sqlalchemy.and_(f, models.RSEProtocols.hostname == hostname)
        if port:
            f = sqlalchemy.and_(f, models.RSEProtocols.port == port)
    try:
        updated = session.query(models.RSEProtocols).filter(f).update(data)
        if not updated:
            msg = 'RSE \'%s\' does not support protocol \'%s\'' % (rse, protocol)
            msg += ' for hostname \'%s\'' % hostname if hostname else ''
            msg += ' on port \'%s\'' % port if port else ''
            raise exception.RSEProtocolNotSupported(msg)
        __fill_gaps(rid, session)
    except IntegrityError, e:
        if 'not unique' in e.args[0]:
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (protocol, port, rse, hostname))
        elif 'may not be NULL' in e.args[0]:
            raise exception.InvalidObject('Invalid values: %s' % e.args[0])
        raise e
    except DatabaseError, e:
        if match('.*DatabaseError.*ORA-01407: cannot update .*RSE_PROTOCOLS.*IMPL.*to NULL.*', e.args[0]):
            raise exception.InvalidObject('Invalid values!')


@transactional_session
def del_protocols(rse, protocol, hostname=None, port=None, session=None):
    """
    Deletes an existing protocol entry for an RSE.

    :param rse: the name of the new rse.
    :param protocol: Protocol identifer.
    :param hostname: Hostname defined for the protocol, used if more than one protocol
                     is registered with the same identifier.
    :param port: The port registered for the hostename, used if more than one protocol
                     is regsitered with the same identifier and hostname.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing protocol was found for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')
    f = sqlalchemy.and_(models.RSEProtocols.rse_id == rid, models.RSEProtocols.protocol == protocol)
    if hostname:
        f = sqlalchemy.and_(f, models.RSEProtocols.hostname == hostname)
        if port:
            f = sqlalchemy.and_(f, models.RSEProtocols.port == port)
    p = session.query(models.RSEProtocols).filter(f)

    if not p.all():
        msg = 'RSE \'%s\' does not support protocol \'%s\'' % (rse, protocol)
        msg += ' for hostname \'%s\'' % hostname if hostname else ''
        msg += ' on port \'%s\'' % port if port else ''
        raise exception.RSEProtocolNotSupported(msg)

    p.delete()


# Helper Functions


def __fill_gaps(rse_id, session):
    """
    Helper method to check if the priorities for the read, write, delete
    operations in the protocols are correct.

    :param rse_id: The database id of the requested RSE.
    :param session: The databiase session.
    """

    for op in ['read', 'write', 'delete']:
        i = 1
        query = session.query(models.RSEProtocols).filter(sqlalchemy.and_(getattr(models.RSEProtocols, op) != -1, models.RSEProtocols.rse_id == rse_id)).order_by(getattr(models.RSEProtocols, op))
        for row in query:
            if getattr(row, op) != i:
                setattr(row, op, i)
            i += 1
