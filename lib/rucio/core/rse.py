# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2016
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013-2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2016
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2015-2016

from re import match
from StringIO import StringIO

import json
import sqlalchemy
import sqlalchemy.orm

from sqlalchemy.exc import DatabaseError, IntegrityError, OperationalError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import FlushError
from sqlalchemy.sql.expression import or_

import rucio.core.account_counter

from rucio.core.rse_counter import add_counter

from rucio.common import exception, utils
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType
from rucio.db.sqla.session import read_session, transactional_session, stream_session


@transactional_session
def add_rse(rse, deterministic=True, volatile=False, city=None, region_code=None, country_name=None, continent=None, time_zone=None, ISP=None, staging_area=False, session=None):
    """
    Add a rse with the given location name.

    :param rse: the name of the new rse.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    :param city: City for the RSE.
    :param region_code: The region code for the RSE.
    :param country_name: The country.
    :param continent: The continent.
    :param time_zone: Timezone.
    :param ISP: Internet service provider.
    :param staging_area: Staging area.
    :param session: The database session in use.
    """
    new_rse = models.RSE(rse=rse, deterministic=deterministic, volatile=volatile, city=city,
                         region_code=region_code, country_name=country_name,
                         continent=continent, time_zone=time_zone, staging_area=staging_area, ISP=ISP, availability=7)
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

    # Add account counter
    rucio.core.account_counter.create_counters_for_new_rse(rse_id=new_rse.id, session=session)

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


@read_session
def sort_rses(rses, session=None):
    """
    Sort a list of RSES by srm free space (ascending order).

    :param rses: List of RSEs.
    :param session: The database session in use.

    :returns: Sorted list of RSEs
    """
    if not rses:
        raise exception.InputValidationError('The list rses should not be empty!')

    if len(rses) == 1:
        return rses

    false_value = False
    query = session.query(models.RSE.rse, models.RSE.staging_area, models.RSEUsage.rse_id).\
        filter(or_(models.RSEUsage.source == 'srm', models.RSEUsage.source == 'gsiftp')).\
        filter(models.RSEUsage.rse_id == models.RSE.id).\
        filter(models.RSE.deleted == false_value)
    condition = []
    for rse in rses:
        condition.append(models.RSE.id == rse['id'])
    query = query.filter(or_(*condition)).order_by(models.RSEUsage.free.asc())
    return [{'rse': rse, 'staging_area': staging_area, 'id': rse_id} for rse, staging_area, rse_id in query]
    # return sample(rses, len(rses))


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
def get_rse(rse, rse_id=None, session=None):
    """
    Get a RSE or raise if it does not exist.

    :param rse:     The rse name.
    :param rse_id:  The rse id. To be used if the rse parameter is none.
    :param session: The database session in use.

    :raises RSENotFound: If referred RSE was not found in the database.
    """

    false_value = False  # To make pep8 checker happy ...
    try:
        if rse:
            tmp = session.query(models.RSE).\
                filter(sqlalchemy.and_(models.RSE.deleted == false_value,
                                       models.RSE.rse == rse))\
                .one()
        else:
            tmp = session.query(models.RSE).\
                filter(sqlalchemy.and_(models.RSE.deleted == false_value,
                                       models.RSE.id == rse_id))\
                .one()
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

    :returns: The rse id.

    :raises RSENotFound: If referred RSE was not found in the database.
    """
    try:
        return session.query(models.RSE.id).filter_by(rse=rse).one()[0]
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE \'%s\' cannot be found' % rse)


@read_session
def get_rse_name(rse_id, session=None):
    """
    Get a RSE name or raise if it does not exist.

    :param rse_id: the rse uuid from the database.
    :param session: The database session in use.

    :returns: The rse name.

    :raises RSENotFound: If referred RSE was not found in the database.
    """
    try:
        return session.query(models.RSE.rse).filter_by(id=rse_id).one()[0]
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
    availability_mask1 = 0
    availability_mask2 = 7
    availability_mapping = {'availability_read': 4, 'availability_write': 2, 'availability_delete': 1}
    false_value = False  # To make pep8 checker happy ...
    if filters:
        if 'availability' in filters and ('availability_read' in filters or 'availability_write' in filters or 'availability_delete' in filters):
            raise exception.InvalidObject('Cannot use availability and read, write, delete filter at the same time.')
        query = session.query(models.RSE).\
            join(models.RSEAttrAssociation, models.RSE.id == models.RSEAttrAssociation.rse_id).\
            filter(models.RSE.deleted == false_value).group_by(models.RSE)

        for (k, v) in filters.items():
            if hasattr(models.RSE, k):
                if k == 'rse_type':
                    query = query.filter(getattr(models.RSE, k) == RSEType.from_sym(v))
                else:
                    query = query.filter(getattr(models.RSE, k) == v)
            elif k in ['availability_read', 'availability_write', 'availability_delete']:
                if v:
                    availability_mask1 = availability_mask1 | availability_mapping[k]
                else:
                    availability_mask2 = availability_mask2 & ~availability_mapping[k]
            else:
                t = aliased(models.RSEAttrAssociation)
                query = query.join(t, t.rse_id == models.RSEAttrAssociation.rse_id)
                query = query.filter(t.key == k)
                query = query.filter(t.value == v)

        condition1, condition2 = [], []
        for i in xrange(0, 8):
            if i | availability_mask1 == i:
                condition1.append(models.RSE.availability == i)
            if i & availability_mask2 == i:
                condition2.append(models.RSE.availability == i)

        if 'availability' not in filters:
            query = query.filter(sqlalchemy.and_(sqlalchemy.or_(*condition1), sqlalchemy.or_(*condition2)))

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
    rse_id = get_rse_id(rse, session=session)
    try:
        new_rse_attr = models.RSEAttrAssociation(rse_id=rse_id, key=key, value=value)
        new_rse_attr = session.merge(new_rse_attr)
        new_rse_attr.save(session=session)
    except IntegrityError:
        raise exception.Duplicate("RSE attribute '%(key)s-%(value)s\' for RSE '%(rse)s' already exists!" % locals())
    return True


@transactional_session
def del_rse_attribute(rse, key, session=None):
    """
    Delete a RSE attribute.

    :param rse: the name of the rse.
    :param key: the attribute key.
    :param session: The database session in use.

    :return: True if RSE attribute was deleted.
    """
    rse_id = get_rse_id(rse, session=session)
    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=rse_id).filter(models.RSEAttrAssociation.key == key)
    rse_attr = query.one()
    rse_attr.delete(session=session)
    return True


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
        rse_id = get_rse_id(rse=rse, session=session)

    query = session.query(models.RSEAttrAssociation).filter_by(rse_id=rse_id)
    for attr in query:
        rse_attrs[attr.key] = attr.value
    return rse_attrs


@read_session
def has_rse_attribute(rse_id, key, session=None):
    """
    Indicates whether the named key is present for the RSE.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.
    :param session: The database session in use.

    :returns: True or False
    """
    if session.query(models.RSEAttrAssociation.value).filter_by(rse_id=rse_id, key=key).first():
        return True
    return False


@read_session
def get_rses_with_attribute(key, session=None):
    """
    Return all RSEs with a certain attribute.

    :param key: The key for the attribute.
    :param session: The database session in use.

    :returns: List of rse dictionaries
    """
    rse_list = []

    query = session.query(models.RSE).\
        join(models.RSEAttrAssociation, models.RSE.id == models.RSEAttrAssociation.rse_id).\
        filter(models.RSE.deleted == False, models.RSEAttrAssociation.key == key).group_by(models.RSE)  # NOQA

    for row in query:
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        rse_list.append(d)

    return rse_list


@read_session
def get_rse_attribute(key, rse_id=None, session=None):
    """
    Retrieve RSE attribute value.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.
    :param session: The database session in use.

    :returns: A list with RSE attribute values for a Key.
    """
    rse_attrs = []
    if rse_id:
        query = session.query(models.RSEAttrAssociation.value).filter_by(rse_id=rse_id, key=key).distinct()
    else:
        query = session.query(models.RSEAttrAssociation.value).filter_by(key=key).distinct()
    for attr_value in query:
        rse_attrs.append(attr_value[0])
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
    rse_id = get_rse_id(rse, session=session)
    rse_usage = models.RSEUsage(rse_id=rse_id, source=source, used=used, free=free)
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
    rse_id = get_rse_id(rse, session=session)
    rse_limit = models.RSELimit(rse_id=rse_id, name=name, value=value)
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


@transactional_session
def set_rse_transfer_limits(rse, activity, rse_id=None, rse_expression=None, max_transfers=0, transfers=0, waitings=0, session=None):
    """
    Set RSE transfer limits.

    :param rse: The RSE name.
    :param activity: The activity.
    :param rse_expression: RSE expression string.
    :param max_transfers: Maximum transfers.
    :param transfers: Current number of tranfers.
    :param waitings: Current number of waitings.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    try:
        if not rse_id:
            rse_id = get_rse_id(rse=rse, session=session)

        rse_tr_limit = models.RSETransferLimit(rse_id=rse_id, activity=activity, rse_expression=rse_expression, max_transfers=max_transfers, transfers=transfers, waitings=waitings)
        rse_tr_limit = session.merge(rse_tr_limit)
        rowcount = rse_tr_limit.save(session=session)
        return rowcount
    except IntegrityError, e:
        raise exception.RucioException(e.args)


@read_session
def get_rse_transfer_limits(rse=None, activity=None, rse_id=None, session=None):
    """
    Get RSE transfer limits.

    :param rse: The RSE name.
    :param activity: The activity.
    :param rse_id: The RSE id.

    :returns: A dictionary with the limits {'limit.activity': {'limit.rse_id': limit.max_transfers}}.
    """
    try:
        if not rse_id and rse:
            rse_id = get_rse_id(rse=rse, session=session)

        query = session.query(models.RSETransferLimit)
        if rse_id:
            query = query.filter_by(rse_id=rse_id)
        if activity:
            query = query.filter_by(activity=activity)

        limits = {}
        for limit in query:
            if limit.activity not in limits:
                limits[limit.activity] = {}
            limits[limit.activity][limit.rse_id] = {'max_transfers': limit.max_transfers,
                                                    'transfers': limit.transfers,
                                                    'waitings': limit.waitings}
        return limits
    except IntegrityError, e:
        raise exception.RucioException(e.args)


@transactional_session
def delete_rse_transfer_limits(rse, activity=None, rse_id=None, session=None):
    """
    Delete RSE transfer limits.

    :param rse: The RSE name.
    :param activity: The activity.
    :param rse_id: The RSE id.
    """
    try:
        if not rse_id:
            rse_id = get_rse_id(rse=rse, session=session)

        query = session.query(models.RSETransferLimit).filter_by(rse_id=rse_id)
        if activity:
            query = query.filter_by(activity=activity)
        rowcount = query.delete()
        return rowcount
    except IntegrityError, e:
        raise exception.RucioException(e.args)


@stream_session
def list_rse_usage_history(rse, source=None, session=None):
    """
    List RSE usage history information.

    :param RSE: The RSE name.
    :param source: The source of the usage information (srm, rucio).
    :param session: The database session in use.

    :returns: A list of historic RSE usage.
    """
    rse_id = get_rse_id(rse=rse, session=session)
    query = session.query(models.RSEUsage.__history_mapper__.class_).filter_by(rse_id=rse_id).order_by(models.RSEUsage.__history_mapper__.class_.updated_at.desc())
    if source:
        query = query.filter_by(source=source)

    for usage in query.yield_per(5):
        yield ({'rse': rse, 'source': usage.source, 'used': usage.used if usage.used else 0, 'total': usage.used if usage.used else 0 + usage.free if usage.free else 0, 'free': usage.free if usage.free else 0, 'updated_at': usage.updated_at})


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

    rid = get_rse_id(rse=rse, session=session)
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
                if parameter['domains'][s][op] < 0:
                    raise exception.RSEProtocolPriorityError('The provided priority (%s)for operation \'%s\' in domain \'%s\' is not supported.' % (parameter['domains'][s][op], op, s))
                parameter[op_name] = parameter['domains'][s][op]
        del parameter['domains']

    if ('extended_attributes' in parameter) and parameter['extended_attributes']:
        try:
            parameter['extended_attributes'] = json.dumps(parameter['extended_attributes'], separators=(',', ':'))
        except ValueError:
            pass  # String is not JSON

    if parameter['scheme'] == 'srm':
        if ('space_token' not in parameter['extended_attributes']) or ('web_service_path' not in parameter['extended_attributes']):
            raise exception.InvalidObject('Missing values! For SRM, extended_attributes and web_service_path must be specified')

    try:
        new_protocol = models.RSEProtocols()
        new_protocol.update(parameter)
        new_protocol.save(session=session)
    except (IntegrityError, FlushError, OperationalError) as e:
        if ('UNIQUE constraint failed' in e.args[0]) or ('conflicts with persistent instance' in e.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*RSE_PROTOCOLS_PK.*violated.*', e.args[0]):

            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (parameter['scheme'], parameter['port'], rse, parameter['hostname']))
        elif 'may not be NULL' in e.args[0] \
             or match('.*IntegrityError.*ORA-01400: cannot insert NULL into.*RSE_PROTOCOLS.*IMPL.*', e.args[0]) \
             or match('.*OperationalError.*cannot be null.*', e.args[0]):
            raise exception.InvalidObject('Missing values!')
        raise e
    return new_protocol


@read_session
def get_rse_protocols(rse, schemes=None, session=None):
    """
    Returns protocol information. Parameter combinations are: (operation OR default) XOR scheme.

    :param rse: The name of the rse.
    :param schemes: a list of schemes to filter by.
    :param session: The database session.

    :returns: A dict with RSE information and supported protocols

    :raises RSENotFound: If RSE is not found.
    """

    _rse = get_rse(rse=rse, session=session)
    if not _rse:
        raise exception.RSENotFound('RSE \'%s\' not found')

    read = True if _rse.availability & 4 else False
    write = True if _rse.availability & 2 else False
    delete = True if _rse.availability & 1 else False

    info = {'id': _rse.id,
            'rse': _rse.rse,
            'availability_read': read,
            'availability_write': write,
            'availability_delete': delete,
            'domain': utils.rse_supported_protocol_domains(),
            'protocols': list(),
            'deterministic': _rse.deterministic,
            'rse_type': str(_rse.rse_type),
            'credentials': None,
            'volatile': _rse.volatile,
            'staging_area': _rse.staging_area}

    for op in utils.rse_supported_protocol_operations():
        info['%s_protocol' % op] = 1  # 1 indicates the default protocol

    query = None
    terms = [models.RSEProtocols.rse_id == _rse.id]
    if schemes:
        if not type(schemes) is list:
            schemes = [schemes]
        terms.extend([models.RSEProtocols.scheme.in_(schemes)])

    query = session.query(models.RSEProtocols.hostname,
                          models.RSEProtocols.scheme,
                          models.RSEProtocols.port,
                          models.RSEProtocols.prefix,
                          models.RSEProtocols.impl,
                          models.RSEProtocols.read_lan,
                          models.RSEProtocols.write_lan,
                          models.RSEProtocols.delete_lan,
                          models.RSEProtocols.read_wan,
                          models.RSEProtocols.write_wan,
                          models.RSEProtocols.delete_wan,
                          models.RSEProtocols.third_party_copy,
                          models.RSEProtocols.extended_attributes).filter(*terms)

    for row in query:
        p = {'hostname': row.hostname,
             'scheme': row.scheme,
             'port': row.port,
             'prefix': row.prefix if row.prefix is not None else '',
             'impl': row.impl,
             'domains': {
                 'lan': {'read': row.read_lan,
                         'write': row.write_lan,
                         'delete': row.delete_lan},
                 'wan': {'read': row.read_wan,
                         'write': row.write_wan,
                         'delete': row.delete_wan,
                         'third_party_copy': row.third_party_copy}
             },
             'extended_attributes': row.extended_attributes}

        try:
            p['extended_attributes'] = json.load(StringIO(p['extended_attributes']))
        except ValueError:
            pass  # If value is not a JSON string

        info['protocols'].append(p)
    return info


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

    rid = get_rse_id(rse=rse, session=session)
    # Transform nested domains to match DB schema e.g. [domains][lan][read] => [read_lan]
    if 'domains' in data:
        for s in data['domains']:
            if s not in utils.rse_supported_protocol_domains():
                raise exception.RSEProtocolDomainNotSupported('The protocol domain \'%s\' is not defined in the schema.' % s)
            for op in data['domains'][s]:
                if op not in utils.rse_supported_protocol_operations():
                    raise exception.RSEOperationNotSupported('Operation \'%s\' not defined in schema.' % (op))
                op_name = ''.join([op, '_', s])
                no = session.query(models.RSEProtocols).\
                    filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                           getattr(models.RSEProtocols, op_name) > 0)).\
                    count()
                if not 0 <= data['domains'][s][op] <= no:
                    raise exception.RSEProtocolPriorityError('The provided priority (%s)for operation \'%s\' in domain \'%s\' is not supported.' % (data['domains'][s][op], op, s))
                data[op_name] = data['domains'][s][op]
        del data['domains']

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
             models.RSEProtocols.port == port]

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
                    prots = []
                    if (not getattr(up, op_name)) and data[op_name]:  # reactivate protocol e.g. from 0 to 1
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                   getattr(models.RSEProtocols, op_name) >= data[op_name])).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = data[op_name] + 1
                    elif getattr(up, op_name) and (not data[op_name]):  # deactivate protocol e.g. from 1 to 0
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                   getattr(models.RSEProtocols, op_name) > getattr(up, op_name))).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = getattr(up, op_name)
                    elif getattr(up, op_name) > data[op_name]:  # shift forward e.g. from 5 to 2
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                   getattr(models.RSEProtocols, op_name) >= data[op_name],
                                                   getattr(models.RSEProtocols, op_name) < getattr(up, op_name))).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = data[op_name] + 1
                    elif getattr(up, op_name) < data[op_name]:  # shift backward e.g. from 1 to 3
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                                   getattr(models.RSEProtocols, op_name) <= data[op_name],
                                                   getattr(models.RSEProtocols, op_name) > getattr(up, op_name))).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = getattr(up, op_name)

                    for p in prots:
                        p.update({op_name: val})
                        val += 1

        up.update(data, flush=True, session=session)
    except (IntegrityError, OperationalError) as e:
        if 'UNIQUE'.lower() in e.args[0].lower() or 'Duplicate' in e.args[0]:  # Covers SQLite, Oracle and MySQL error
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

    rid = get_rse_id(rse=rse, session=session)
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
            prots = session.query(models.RSEProtocols).\
                filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rid,
                                       getattr(models.RSEProtocols, op_name) > 0)).\
                order_by(getattr(models.RSEProtocols, op_name).asc())
            i = 1
            for p in prots:
                p.update({op_name: i})
                i += 1


@transactional_session
def update_rse(rse, parameters, session=None):
    """
    Update RSE properties like availability or name.

    :param rse: the name of the new rse.
    :param  parameters: A dictionnary with property (name, read, write, delete as keys).
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    """
    try:
        query = session.query(models.RSE).filter_by(rse=rse).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE \'%s\' cannot be found' % rse)
    rse_id = query.id
    availability = 0
    for column in query:
        if column[0] == 'availability':
            availability = column[1] or availability
    param = {}
    availability_mapping = {'availability_read': 4, 'availability_write': 2, 'availability_delete': 1}
    for key in parameters:
        if key == 'name':
            param['rse'] = parameters['name']
        if key in ['availability_read', 'availability_write', 'availability_delete']:
            if parameters[key] is True:
                availability = availability | availability_mapping[key]
            else:
                availability = availability & ~availability_mapping[key]
    param['availability'] = availability
    query.update(param)
    if 'name' in parameters:
        add_rse_attribute(rse=parameters['name'], key=parameters['name'], value=1, session=session)
        query = session.query(models.RSEAttrAssociation).filter_by(rse_id=rse_id).filter(models.RSEAttrAssociation.key == rse)
        rse_attr = query.one()
        rse_attr.delete(session=session)
