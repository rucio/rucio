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
# - Martin Barisits, <martin.barisits@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

from re import match
from StringIO import StringIO

import json
import sqlalchemy
import sqlalchemy.orm

from sqlalchemy.exc import DatabaseError, IntegrityError, OperationalError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import FlushError

from rucio.common import exception, utils
from rucio.core.rse_counter import add_counter
from rucio.db import models
from rucio.db.session import read_session, transactional_session, stream_session


@transactional_session
def add_rse(rse, deterministic=True, volatile=False, session=None):
    """
    Add a rse with the given location name.

    :param rse: the name of the new rse.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    :param session: The database session in use.
    """

    new_rse = models.RSE(rse=rse, deterministic=deterministic, volatile=volatile)
    try:
        new_rse.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('RSE \'%(rse)s\' already exists!' % locals())
    except DatabaseError, e:
        raise exception.RucioException(e.args)

    # Add rse name as a RSE-Tag
    add_rse_attribute(rse=rse, key=rse, value=True, session=session)

    # Add counter to monitor the space usage
    add_counter(rse_id=new_rse.id, session=session)

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

    :raises RSENotFound: If referred RSE was not found in the database.
    """

    try:
        tmp = session.query(models.RSE).filter_by(rse=rse).one()
        tmp['type'] = tmp.rse_type
        return tmp
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE \'%s\' cannot be found' % rse)


@read_session
def get_rse_id(rse, session=None):
    """
    Get a RSE ID or raise if it does not exist.

    :param rse: the rse name.
    :param session: The database session in use.

    :raises RSENotFound: If referred RSE was not found in the database.
    """
    try:
        return session.query(models.RSE).filter_by(rse=rse).one().id
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE \'%s\' cannot be found' % rse)


@read_session
def get_rse_by_id(rse_id, session=None):
    """
    Get a RSE properties or raise if it does not exist.

    :param rse_id: the rse uuid from the database.
    :param session: The database session in use.

    :returns: The row-object od the matching RSE.

    :raises RSENotFound: If referred RSE was not found in the database.
    """
    try:
        return session.query(models.RSE).filter_by(id=rse_id).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with ID \'%s\' cannot be found' % rse_id)


@read_session
def list_rses(filters={}, session=None):
    """
    Returns a list of all RSEs.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns: a list of dictionaries.
    """

    rse_list = []

    false_value = False  # To make pep8 checker happy ...
    if filters:
        query = session.query(models.RSE).\
            join(models.RSEAttrAssociation, models.RSE.id == models.RSEAttrAssociation.rse_id).\
            filter(models.RSE.deleted == false_value).group_by(models.RSE)

        for (k, v) in filters.items():
            if hasattr(models.RSE, k):
                query = query.filter(getattr(models.RSE, k) == v)
            else:
                t = aliased(models.RSEAttrAssociation)
                query = query.join(t, t.rse_id == models.RSEAttrAssociation.rse_id)
                query = query.filter(t.key == k)
                query = query.filter(t.value == v)

        for row in query:
            d = {}
            for column in row.__table__.columns:
                d[column.name] = getattr(row, column.name)
            rse_list.append(d)
    else:

        query = session.query(models.RSE).filter_by(deleted=False).order_by(models.RSE.rse)
        for row in query:
            d = {}
            for column in row.__table__.columns:
                d[column.name] = getattr(row, column.name)
            rse_list.append(d)

    return rse_list


@transactional_session
def add_rse_attribute(rse, key, value, session=None):
    """ Adds a RSE attribute.

    :param rse: the rse name.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.
    :param session: The database session in use.

    :returns: True is successful
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
def list_rse_attributes(rse, rse_id=None, session=None):
    """
    List RSE attributes for a RSE.
    If both rse and rse_id is set, the rse_id will be used for the lookup.

    :param rse:     the rse name.
    :param rse_id:  The RSE id.
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """
    rse_attrs = {}
    if rse_id is None:
        rse_id = get_rse(rse=rse, session=session).id

    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=rse_id)
    for attr in query:
        rse_attrs[attr.key] = attr.value
    return rse_attrs


@transactional_session
def set_rse_usage(rse, source, used, free, session=None):
    """
    Set RSE usage information.

    :param rse: the location name.
    :param source: The information source, e.g. srm.
    :param used: the used space in bytes.
    :param free: the free in bytes.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    rse = get_rse(rse)
    rse_usage = models.RSEUsage(rse_id=rse.id, source=source, used=used, free=free)
    # versioned_session(session)
    rse_usage = session.merge(rse_usage)
    rse_usage.save(session=session)

    # rse_usage_history = models.RSEUsage.__history_mapper__.class_(rse_id=rse.id, source=source, used=used, free=free)
    # rse_usage_history.save(session=session)

    return True


@read_session
def get_rse_usage(rse, source=None, rse_id=None, session=None):
    """
    get rse usage information.

    :param rse: The rse name.
    :param source: The information source, e.g. srm.
    :param rse_id:  The RSE id.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    if not rse_id:
        rse_id = get_rse_id(rse, session=session)

    query = session.query(models.RSEUsage).filter_by(rse_id=rse_id)
    if source:
        query = query.filter_by(source=source)

    usage = list()
    for row in query:
        usage.append({'rse': rse, 'source': row.source,
                      'used': row.used, 'free': row.free,
                      'total': (row.free or 0) + (row.used or 0),
                      'updated_at': row.updated_at})
    return usage


@transactional_session
def set_rse_limits(rse, name, value, session=None):
    """
    Set RSE limits.

    :param rse: The RSE name.
    :param name: The name of the limit.
    :param value: The feature value. Set to -1 to remove the limit.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    rse = get_rse(rse=rse, session=session)
    rse_limit = models.RSELimit(rse_id=rse.id, name=name, value=value)
    rse_limit = session.merge(rse_limit)
    rse_limit.save(session=session)
    return True


@read_session
def get_rse_limits(rse, name=None, rse_id=None, session=None):
    """
    Get RSE limits.

    :param rse: The RSE name.
    :param name: A Limit name.
    :param rse_id: The RSE id.

    :returns: A dictionary with the limits {'limit.name': limit.value}.
    """
    if not rse_id:
        rse_id = get_rse_id(rse=rse, session=session)

    query = session.query(models.RSELimit).filter_by(rse_id=rse_id)
    if name:
        query = query.filter_by(name=name)
    limits = {}
    for limit in query:
        limits[limit.name] = limit.value
    return limits


@stream_session
def list_rse_usage_history(rse, source=None, session=None):
    """
    List location usage history information.

    :param location: The location name.
    :param source: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns:  list of locations.
    """
    rse = get_rse(rse)
    query = session.query(models.RSEUsage.__history_mapper__.class_).filter_by(rse_id=rse.id).order_by(models.RSEUsage.__history_mapper__.class_.updated_at.desc())
    for usage in query.yield_per(5):
        yield ({'rse': rse.rse, 'source': usage.source, 'used': usage.used, 'total': usage.used + usage.free, 'free': usage.free, 'updated_at': usage.updated_at})


@transactional_session
def add_protocol(rse, parameter, session=None):
    """
    Add a protocol to an existing RSE. If entries with equal or less priority for
    an operation exist, the existing one will be reorded (i.e. +1).

    :param rse: the name of the new rse.
    :param parameter: parameters of the new protocol entry.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEOperationNotSupported: If no scheme supported the requested operation for the given RSE.
    :raises RSEProtocolDomainNotSupported: If an undefined domain was provided.
    :raises RSEProtocolPriorityError: If the provided priority for the scheme is to big or below zero.
    :raises Duplicate: If scheme with identifier, hostname and port already exists
                       for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')
    # Insert new protocol entry
    parameter['rse_id'] = rid

    # Default values
    parameter['port'] = parameter.get('port', 0)
    parameter['hostname'] = parameter.get('hostname', 'localhost')

    # Transform nested domains to match DB schema e.g. [domains][lan][read] => [read_lan]
    if 'domains' in parameter.keys():
        for s in parameter['domains']:
            if s not in utils.rse_supported_protocol_domains():
                raise exception.RSEProtocolDomainNotSupported('The protocol domain \'%s\' is not defined in the schema.' % s)
            for op in parameter['domains'][s]:
                if op not in utils.rse_supported_protocol_operations():
                    raise exception.RSEOperationNotSupported('Operation \'%s\' not defined in schema.' % (op))
                op_name = ''.join([op, '_', s]).lower()
                no = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                               getattr(models.RSEProtocols, op_name) > 0,
                                                                               )).count()
                if not(0 <= parameter['domains'][s][op] <= (no + 1)):
                    raise exception.RSEProtocolPriorityError('The provided priority (%s)for operation \'%s\' in domain \'%s\' is not supported.' % (parameter['domains'][s][op], op, s))
                parameter[op_name] = parameter['domains'][s][op]
        del(parameter['domains'])

    if ('extended_attributes' in parameter) and parameter['extended_attributes']:
        try:
            parameter['extended_attributes'] = json.dumps(parameter['extended_attributes'], separators=(',', ':'))
        except ValueError:
            pass  # String is not JSON

    try:
        # Open gaps in protocols priorities for new protocol
        for domain in utils.rse_supported_protocol_domains():
            for op in utils.rse_supported_protocol_operations():
                op_name = ''.join([op, '_', domain])
                if (op_name in parameter) and parameter[op_name]:
                    prots = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                      getattr(models.RSEProtocols, op_name) >= parameter[op_name],
                                                                                      )).order_by(getattr(models.RSEProtocols, op_name).asc())
                    val = parameter[op_name] + 1
                    for p in prots:
                        p.update({op_name: val})
                        val += 1
        new_protocol = models.RSEProtocols()
        new_protocol.update(parameter)
        new_protocol.save(session=session)
    except (IntegrityError, FlushError, OperationalError) as e:
        if ('not unique' in e.args[0]) or ('conflicts with persistent instance' in e.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*RSE_PROTOCOLS_PK.*violated.*', e.args[0]):
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (parameter['scheme'], parameter['port'], rse, parameter['hostname']))
        elif 'may not be NULL' in e.args[0] \
             or match('.*IntegrityError.*ORA-01400: cannot insert NULL into.*RSE_PROTOCOLS.*IMPL.*', e.args[0]) \
             or match('.*OperationalError.*cannot be null.*', e.args[0]):
            raise exception.InvalidObject('Missing values!')
        raise e
    return new_protocol


@read_session
def get_protocols(rse, protocol_domain='ALL', operation=None, default=False, scheme=None, session=None):
    """
    Returns protocol information. Parameter comibantions are: (operation OR default) XOR scheme.

    :param rse: The name of the rse.
    :param protocol_domain: The domain of the requested protocol. Supported are either 'lan', 'wan' or, 'ALL' (as default).
    :param operation: The name of the requested operation (read, write, or delete).
                      If None, all operations are queried.
    :param default: Indicates if only the default operations should be returned.
    :param scheme: The name of the requested scheme.
    :param session: The database session.

    :returns: A list with details about each matching protocol.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing scheme was found for the given RSE.
    :raises RSEOperationNotSupported: If no scheme supported the requested operation for the given RSE.
    :raises RSEProtocolDomainNotSupported: If an undefined domain was provided.
    """

    if (operation is not None) and (operation not in utils.rse_supported_protocol_operations()):
        raise exception.RSEOperationNotSupported('Operation \'%s\' not defined in schema.' % (operation))
    if (protocol_domain != 'ALL') and (protocol_domain not in utils.rse_supported_protocol_domains()):
        raise exception.RSEProtocolDomainNotSupported('The protocol domain \'%s\' is not defined in the schema.' % protocol_domain)

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')
    query = None
    terms = [models.RSEProtocols.rse_id == rid]
    order_by = None
    if scheme:
        terms.append(models.RSEProtocols.scheme == scheme)
    else:
        if operation:
            if default:
                subterms = list()
                if protocol_domain != 'ALL':
                    subterms.append(getattr(models.RSEProtocols, ''.join([operation, '_', protocol_domain])) == 1)
                else:  # If protocol domain = ALL the operation must be supported by each domain
                    for domain in utils.rse_supported_protocol_domains():
                        subterms.append(getattr(models.RSEProtocols, ''.join([operation, '_', domain])) == 1)
                terms.append(sqlalchemy.and_(*subterms))
            else:
                subterms = list()
                if protocol_domain != 'ALL':
                    subterms.append(getattr(models.RSEProtocols, ''.join([operation, '_', protocol_domain])) > 0)
                    order_by = getattr(models.RSEProtocols, ''.join([operation, '_', protocol_domain]))
                else:  # If protocol domain = ALL the operation must be supported by each domain
                    for domain in utils.rse_supported_protocol_domains():
                        subterms.append(getattr(models.RSEProtocols, ''.join([operation, '_', domain])) > 0)
                terms.append(sqlalchemy.and_(*subterms))
        else:
            if default:
                subterms = list()
                for op in utils.rse_supported_protocol_operations():
                    if protocol_domain == 'ALL':
                        for d in utils.rse_supported_protocol_domains():
                            subterms.append(getattr(models.RSEProtocols, ''.join([op, '_', d])) == 1)
                    else:
                        subterms.append(getattr(models.RSEProtocols, ''.join([op, '_', protocol_domain])) == 1)
                terms.append(sqlalchemy.and_(*subterms))

    query = session.query(models.RSEProtocols).filter(*terms).order_by(order_by)
    protocols = list()
    for row in query:
        p = {'hostname': row.hostname,
             'scheme': row.scheme,
             'port': row.port,
             'prefix': row.prefix,
             'impl': row.impl,
             'domains': {
                 'lan': {'read': row.read_lan,
                         'write': row.write_lan,
                         'delete': row.delete_lan
                         },
                 'wan': {'read': row.read_wan,
                         'write': row.write_wan,
                         'delete': row.delete_wan
                         }
             },
             'extended_attributes': row.extended_attributes
             }

        try:
            p['extended_attributes'] = json.load(StringIO(p['extended_attributes']))
        except ValueError:
            pass  # If value is not a JSON string

        protocols.append(p)
    if not protocols:
        if operation:
            raise exception.RSEOperationNotSupported('RSE \'%s\' has no protocol defined for operation \'%s\'' % (rse, operation))
        else:
            raise exception.RSEProtocolNotSupported('RSE \'%s\' does not support protocol \'%s\'' % (rse, scheme))
    return protocols


@transactional_session
def update_protocols(rse, scheme, data, hostname, port, session=None):
    """
    Updates an existing protocol entry for an RSE. If necessary, priorities for read,
    write, and delete operations of other protocol entires will be updated too.

    :param rse: the name of the new rse.
    :param scheme: Protocol identifer.
    :param data: Dict with new values (keys must match column names in the database).
    :param hostname: Hostname defined for the scheme, used if more than one scheme
                     is registered with the same identifier.
    :param port: The port registered for the hostename, used if more than one scheme
                 is regsitered with the same identifier and hostname.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing protocol was found for the given RSE.
    :raises RSEOperationNotSupported: If no protocol supported the requested operation for the given RSE.
    :raises RSEProtocolDomainNotSupported: If an undefined domain was provided.
    :raises RSEProtocolPriorityError: If the provided priority for the protocol is to big or below zero.
    :raises KeyNotFound: Invalid data for update provided.
    :raises Duplicate: If protocol with identifier, hostname and port already exists
                       for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    # Transform nested domains to match DB schema e.g. [domains][lan][read] => [read_lan]
    if 'domains' in data:
        for s in data['domains']:
            if s not in utils.rse_supported_protocol_domains():
                raise exception.RSEProtocolDomainNotSupported('The protocol domain \'%s\' is not defined in the schema.' % s)
            for op in data['domains'][s]:
                if op not in utils.rse_supported_protocol_operations():
                    raise exception.RSEOperationNotSupported('Operation \'%s\' not defined in schema.' % (op))
                op_name = ''.join([op, '_', s])
                no = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                               getattr(models.RSEProtocols, op_name) > 0,
                                                                               )).count()
                if not(0 <= data['domains'][s][op] <= no):
                    raise exception.RSEProtocolPriorityError('The provided priority (%s)for operation \'%s\' in domain \'%s\' is not supported.' % (data['domains'][s][op], op, s))
                data[op_name] = data['domains'][s][op]
        del(data['domains'])

    if 'extended_attributes' in data:
        try:
            data['extended_attributes'] = json.dumps(data['extended_attributes'], separators=(',', ':'))
        except ValueError:
            pass  # String is not JSON

    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')

    terms = [models.RSEProtocols.rse_id == rid,
             models.RSEProtocols.scheme == scheme,
             models.RSEProtocols.hostname == hostname,
             models.RSEProtocols.port == port
             ]

    try:
        up = session.query(models.RSEProtocols).filter(*terms).first()
        if up is None:
            msg = 'RSE \'%s\' does not support protocol \'%s\' for hostname \'%s\' on port \'%s\'' % (rse, scheme, hostname, port)
            raise exception.RSEProtocolNotSupported(msg)

        # Preparing gaps if priority is updated
        for domain in utils.rse_supported_protocol_domains():
            for op in utils.rse_supported_protocol_operations():
                op_name = ''.join([op, '_', domain])
                if op_name in data:
                    if (not getattr(up, op_name)) and data[op_name]:  # reactivate protocol e.g. from 0 to 1
                        prots = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                          getattr(models.RSEProtocols, op_name) >= data[op_name]
                                                                                          )).order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = data[op_name] + 1
                    elif getattr(up, op_name) and (not data[op_name]):  # deactivate protocol e.g. from 1 to 0
                        prots = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                          getattr(models.RSEProtocols, op_name) > getattr(up, op_name)
                                                                                          )).order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = getattr(up, op_name)
                    elif getattr(up, op_name) > data[op_name]:  # shift forward e.g. from 5 to 2
                        prots = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                          getattr(models.RSEProtocols, op_name) >= data[op_name],
                                                                                          getattr(models.RSEProtocols, op_name) < getattr(up, op_name)
                                                                                          )).order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = data[op_name] + 1
                    elif getattr(up, op_name) < data[op_name]:  # shift backward e.g. from 1 to 3
                        prots = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                                          getattr(models.RSEProtocols, op_name) <= data[op_name],
                                                                                          getattr(models.RSEProtocols, op_name) > getattr(up, op_name)
                                                                                          )).order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = getattr(up, op_name)

                    for p in prots:
                        p.update({op_name: val})
                        val += 1

        up.update(data, flush=True, session=session)
    except (IntegrityError, OperationalError) as e:
        if 'unique' in e.args[0] or 'Duplicate' in e.args[0]:  # Covers SQLite, Oracle and MySQL error
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (scheme, port, rse, hostname))
        elif 'may not be NULL' in e.args[0] or "cannot be null" in e.args[0]:
            raise exception.InvalidObject('Missing values: %s' % e.args[0])
        raise e
    except DatabaseError, e:
        if match('.*DatabaseError.*ORA-01407: cannot update .*RSE_PROTOCOLS.*IMPL.*to NULL.*', e.args[0]):
            raise exception.InvalidObject('Invalid values !')
        raise e


@transactional_session
def del_protocols(rse, scheme, hostname=None, port=None, session=None):
    """
    Deletes an existing protocol entry for an RSE.

    :param rse: the name of the new rse.
    :param scheme: Protocol identifer.
    :param hostname: Hostname defined for the scheme, used if more than one scheme
                     is registered with the same identifier.
    :param port: The port registered for the hostename, used if more than one scheme
                     is regsitered with the same identifier and hostname.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing scheme was found for the given RSE.
    """

    rid = get_rse(rse=rse, session=session).id
    if not rid:
        raise exception.RSENotFound('RSE \'%s\' not found')
    terms = [models.RSEProtocols.rse_id == rid, models.RSEProtocols.scheme == scheme]
    if hostname:
        terms.append(models.RSEProtocols.hostname == hostname)
        if port:
            terms.append(models.RSEProtocols.port == port)
    p = session.query(models.RSEProtocols).filter(*terms)

    if not p.all():
        msg = 'RSE \'%s\' does not support protocol \'%s\'' % (rse, scheme)
        msg += ' for hostname \'%s\'' % hostname if hostname else ''
        msg += ' on port \'%s\'' % port if port else ''
        raise exception.RSEProtocolNotSupported(msg)

    for row in p:
        row.delete(session=session)

    # Filling gaps in protocol priorities
    for domain in utils.rse_supported_protocol_domains():
        for op in utils.rse_supported_protocol_operations():
            op_name = ''.join([op, '_', domain])
            prots = session.query(models.RSEProtocols).filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                                              getattr(models.RSEProtocols, op_name) > 0
                                                                              )).order_by(getattr(models.RSEProtocols, op_name).asc())
            i = 1
            for p in prots:
                p.update({op_name: i})
                i += 1
