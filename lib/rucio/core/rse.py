# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2012-2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2020
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2017
# - Wen Guan <wguan.icedew@gmail.com>, 2015-2016
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Frank Berghaus <frank.berghaus@cern.ch>, 2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Gabriele Fronze' <gfronze@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019-2020
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from __future__ import division

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import json
import sqlalchemy
import sqlalchemy.orm

from re import match
from six import string_types

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE

from sqlalchemy.exc import DatabaseError, IntegrityError, OperationalError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import FlushError
from sqlalchemy.sql.expression import or_, false

import rucio.core.account_counter

from rucio.core.rse_counter import add_counter, get_counter
from rucio.common import exception, utils
from rucio.common.config import get_lfn2pfn_algorithm_default, config_get
from rucio.common.utils import CHECKSUM_KEY, is_checksum_valid, GLOBALLY_SUPPORTED_CHECKSUMS
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType
from rucio.db.sqla.session import read_session, transactional_session, stream_session


REGION = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=3600,
                                 arguments={'url': config_get('cache', 'url', False, '127.0.0.1:11211'),
                                            'distributed_lock': True})


@transactional_session
def add_rse(rse, vo='def', deterministic=True, volatile=False, city=None, region_code=None, country_name=None, continent=None, time_zone=None,
            ISP=None, staging_area=False, rse_type=RSEType.DISK, longitude=None, latitude=None, ASN=None, availability=7, session=None):
    """
    Add a rse with the given location name.

    :param rse: the name of the new rse.
    :param vo: the vo to add the RSE to.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    :param city: City for the RSE.
    :param region_code: The region code for the RSE.
    :param country_name: The country.
    :param continent: The continent.
    :param time_zone: Timezone.
    :param ISP: Internet service provider.
    :param staging_area: Staging area.
    :param rse_type: RSE type.
    :param latitude: Latitude coordinate of RSE.
    :param longitude: Longitude coordinate of RSE.
    :param ASN: Access service network.
    :param availability: Availability.
    :param session: The database session in use.
    """
    if isinstance(rse_type, string_types):
        rse_type = RSEType.from_string(str(rse_type))

    new_rse = models.RSE(rse=rse, vo=vo, deterministic=deterministic, volatile=volatile, city=city,
                         region_code=region_code, country_name=country_name,
                         continent=continent, time_zone=time_zone, staging_area=staging_area, ISP=ISP, availability=availability,
                         rse_type=rse_type, longitude=longitude, latitude=latitude, ASN=ASN)
    try:
        new_rse.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('RSE \'%(rse)s\' already exists!' % locals())
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    # Add rse name as a RSE-Tag
    add_rse_attribute(rse_id=new_rse.id, key=rse, value=True, session=session)

    # Add counter to monitor the space usage
    add_counter(rse_id=new_rse.id, session=session)

    # Add account counter
    rucio.core.account_counter.create_counters_for_new_rse(rse_id=new_rse.id, session=session)

    return new_rse.id


@read_session
def rse_exists(rse, vo='def', include_deleted=False, session=None):
    """
    Checks to see if RSE exists.

    :param rse: Name of the rse.
    :param vo: The VO for the RSE.
    :param session: The database session in use.

    :returns: True if found, otherwise false.
    """
    return True if session.query(models.RSE).filter_by(rse=rse, vo=vo, deleted=include_deleted).first() else False


@read_session
def sort_rses(rses, session=None):
    """
    Sort a list of RSES by free space (ascending order).

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
        filter(models.RSEUsage.source == 'storage').\
        filter(models.RSEUsage.rse_id == models.RSE.id).\
        filter(models.RSE.deleted == false_value)
    condition = []
    for rse in rses:
        condition.append(models.RSE.id == rse['id'])
    query = query.filter(or_(*condition)).order_by(models.RSEUsage.free.asc())
    return [{'rse': rse, 'staging_area': staging_area, 'id': rse_id} for rse, staging_area, rse_id in query]


@transactional_session
def del_rse(rse_id, session=None):
    """
    Disable a rse with the given rse id.

    :param rse_id: the rse id.
    :param session: The database session in use.
    """

    old_rse = None
    try:
        old_rse = session.query(models.RSE).filter_by(id=rse_id, deleted=False).one()
        if not rse_is_empty(rse_id=rse_id, session=session):
            raise exception.RSEOperationNotSupported('RSE \'%s\' is not empty' % get_rse_name(rse_id=rse_id, session=session))
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with id \'%s\' cannot be found' % rse_id)
    rse = old_rse.rse
    old_rse.delete(session=session)
    try:
        del_rse_attribute(rse_id=rse_id, key=rse, session=session)
    except exception.RSEAttributeNotFound:
        pass


@transactional_session
def restore_rse(rse_id, session=None):
    """
    Restore a rse with the given rse id.

    :param rse_id: the rse id.
    :param session: The database session in use.
    """

    old_rse = None
    try:
        old_rse = session.query(models.RSE).filter_by(id=rse_id, deleted=True).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with id \'%s\' cannot be found' % rse_id)
    old_rse.deleted = False
    old_rse.deleted_at = None
    old_rse.save(session=session)
    rse = old_rse.rse
    add_rse_attribute(rse_id=rse_id, key=rse, value=True, session=session)


@read_session
def rse_is_empty(rse_id, session=None):
    """
    Check if a RSE is empty.

    :param rse_id: the rse id.
    :param session: the database session in use.
    """

    is_empty = False
    try:
        is_empty = get_counter(rse_id, session=session)['bytes'] == 0
    except exception.CounterNotFound:
        is_empty = True
    return is_empty


@read_session
def get_rse(rse_id, session=None):
    """
    Get a RSE or raise if it does not exist.

    :param rse_id:  The rse id.
    :param session: The database session in use.

    :raises RSENotFound: If referred RSE was not found in the database.
    """

    false_value = False  # To make pep8 checker happy ...
    try:
        tmp = session.query(models.RSE).\
            filter(sqlalchemy.and_(models.RSE.deleted == false_value,
                                   models.RSE.id == rse_id))\
            .one()
        tmp['type'] = tmp.rse_type
        return tmp
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with id \'%s\' cannot be found' % rse_id)


@read_session
def get_rse_id(rse, vo='def', session=None, include_deleted=True):
    """
    Get a RSE ID or raise if it does not exist.

    :param rse: the rse name.
    :param session: The database session in use.
    :param include_deleted: Flag to toggle finding rse's marked as deleted.

    :returns: The rse id.

    :raises RSENotFound: If referred RSE was not found in the database.
    """

    if include_deleted:
        if vo != 'def':
            cache_key = 'rse-id_{}@{}'.format(rse, vo).replace(' ', '.')
        else:
            cache_key = 'rse-id_{}'.format(rse).replace(' ', '.')
        result = REGION.get(cache_key)
        if result != NO_VALUE:
            return result

    try:
        query = session.query(models.RSE.id).filter_by(rse=rse, vo=vo)
        if not include_deleted:
            query = query.filter_by(deleted=False)
        result = query.one()[0]
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound("RSE '%s' cannot be found in vo '%s'" % (rse, vo))

    if include_deleted:
        REGION.set(cache_key, result)
    return result


@read_session
def get_rse_name(rse_id, session=None, include_deleted=True):
    """
    Get a RSE name or raise if it does not exist.

    :param rse_id: the rse uuid from the database.
    :param session: The database session in use.
    :param include_deleted: Flag to toggle finding rse's marked as deleted.

    :returns: The rse name.

    :raises RSENotFound: If referred RSE was not found in the database.
    """

    if include_deleted:
        cache_key = 'rse-name_{}'.format(rse_id)
        result = REGION.get(cache_key)
        if result != NO_VALUE:
            return result

    try:
        query = session.query(models.RSE.rse).filter_by(id=rse_id)
        if not include_deleted:
            query = query.filter_by(deleted=False)
        result = query.one()[0]
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with ID \'%s\' cannot be found' % rse_id)

    if include_deleted:
        REGION.set(cache_key, result)
    return result


@read_session
def get_rse_vo(rse_id, session=None, include_deleted=True):
    """
    Get the VO for a given RSE id.

    :param rse_id: the rse uuid from the database.
    :param session: the database session in use.
    :param include_deleted: Flag to toggle finding rse's marked as deleted.

    :returns The vo name.

    :raises RSENotFound: If referred RSE was not found in database.
    """

    if include_deleted:
        cache_key = 'rse-vo_{}'.format(rse_id)
        result = REGION.get(cache_key)
        if result != NO_VALUE:
            return result

    try:
        query = session.query(models.RSE.vo).filter_by(id=rse_id)
        if not include_deleted:
            query = query.filter_by(deleted=False)
        result = query.one()[0]
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with ID \'%s\' cannot be found' % rse_id)

    if include_deleted:
        REGION.set(cache_key, result)
    return result


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

    if filters and filters.get('vo'):
        filters = filters.copy()  # Make a copy so we can pop('vo') without affecting the object `filters` outside this function
        vo = filters.pop('vo')
    else:
        vo = None

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
                query = query.filter(t.key == k,
                                     t.value == v)

        condition1, condition2 = [], []
        for i in range(0, 8):
            if i | availability_mask1 == i:
                condition1.append(models.RSE.availability == i)
            if i & availability_mask2 == i:
                condition2.append(models.RSE.availability == i)

        if 'availability' not in filters:
            query = query.filter(sqlalchemy.and_(sqlalchemy.or_(*condition1), sqlalchemy.or_(*condition2)))
    else:

        query = session.query(models.RSE).filter_by(deleted=False).order_by(models.RSE.rse)

    if vo:
        query = query.filter(getattr(models.RSE, 'vo') == vo)

    for row in query:
        dic = {}
        for column in row.__table__.columns:
            dic[column.name] = getattr(row, column.name)
        rse_list.append(dic)

    return rse_list


@transactional_session
def add_rse_attribute(rse_id, key, value, session=None):
    """ Adds a RSE attribute.

    :param rse_id: the rse id.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.
    :param session: The database session in use.

    :returns: True is successful
    """
    try:
        new_rse_attr = models.RSEAttrAssociation(rse_id=rse_id, key=key, value=value)
        new_rse_attr = session.merge(new_rse_attr)
        new_rse_attr.save(session=session)
    except IntegrityError:
        rse = get_rse_name(rse_id=rse_id, session=session)
        raise exception.Duplicate("RSE attribute '%(key)s-%(value)s\' for RSE '%(rse)s' already exists!" % locals())
    return True


@transactional_session
def del_rse_attribute(rse_id, key, session=None):
    """
    Delete a RSE attribute.

    :param rse_id: the id of the rse.
    :param key: the attribute key.
    :param session: The database session in use.

    :return: True if RSE attribute was deleted.
    """
    rse_attr = None
    try:
        query = session.query(models.RSEAttrAssociation).filter_by(rse_id=rse_id).filter(models.RSEAttrAssociation.key == key)
        rse_attr = query.one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSEAttributeNotFound('RSE attribute \'%s\' cannot be found' % key)
    rse_attr.delete(session=session)
    return True


@read_session
def list_rse_attributes(rse_id, session=None):
    """
    List RSE attributes for a RSE.

    :param rse_id:  The RSE id.
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """
    rse_attrs = {}

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
def get_rses_with_attribute_value(key, value, lookup_key, vo='def', session=None):
    """
    Return all RSEs with a certain attribute.

    :param key: The key for the attribute.
    :param value: The value for the attribute.
    :param lookup_key: The value of the this key will be returned.
    :param session: The database session in use.

    :returns: List of rse dictionaries with the rse_id and lookup_key/value pair
    """
    if vo != 'def':
        cache_key = 'av-%s-%s-%s@%s' % (key, value, lookup_key, vo)
    else:
        cache_key = 'av-%s-%s-%s' % (key, value, lookup_key)

    result = REGION.get(cache_key)
    if result is NO_VALUE:

        rse_list = []

        subquery = session.query(models.RSEAttrAssociation.rse_id)\
                          .filter(models.RSEAttrAssociation.key == key,
                                  models.RSEAttrAssociation.value == value)\
                          .subquery()

        query = session.query(models.RSEAttrAssociation.rse_id,
                              models.RSEAttrAssociation.key,
                              models.RSEAttrAssociation.value)\
                       .join(models.RSE, models.RSE.id == models.RSEAttrAssociation.rse_id)\
                       .join(subquery, models.RSEAttrAssociation.rse_id == subquery.c.rse_id)\
                       .filter(models.RSE.deleted == false(),
                               models.RSEAttrAssociation.key == lookup_key,
                               models.RSE.vo == vo)

        for row in query:
            rse_list.append({'rse_id': row[0],
                             'key': row[1],
                             'value': row[2]})

        REGION.set(cache_key, rse_list)
        return rse_list

    return result


@read_session
def get_rse_attribute(key, rse_id=None, value=None, use_cache=True, session=None):
    """
    Retrieve RSE attribute value.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.
    :param value: Optionally, the desired value for the attribute.
    :param use_cache: Boolean to use memcached.
    :param session: The database session in use.

    :returns: A list with RSE attribute values for a Key.
    """

    result = NO_VALUE
    if use_cache:
        result = REGION.get('%s-%s-%s' % (key, rse_id, value))
    if result is NO_VALUE:

        rse_attrs = []
        if rse_id:
            query = session.query(models.RSEAttrAssociation.value).filter_by(rse_id=rse_id, key=key).distinct()
            if value:
                query = session.query(models.RSEAttrAssociation.value).filter_by(rse_id=rse_id, key=key, value=value).distinct()
        else:
            query = session.query(models.RSEAttrAssociation.value).filter_by(key=key).distinct()
            if value:
                query = session.query(models.RSEAttrAssociation.value).filter_by(key=key, value=value).distinct()
        for attr_value in query:
            rse_attrs.append(attr_value[0])
        REGION.set('%s-%s-%s' % (key, rse_id, value), rse_attrs)
        return rse_attrs

    return result


@read_session
def get_rse_supported_checksums(rse_id=None, session=None):
    """
    Retrieve RSE attribute value.

    :param rse_id: The RSE id.
    :param session: The database session in use.

    :returns: The list of checksums supported by the selected RSE.
              If the list is empty (aka attribute is not set) it returns all the default checksums.
              Use 'none' to explicitly tell the RSE does not support any checksum algorithm.
    """

    checksum_support_attribute_list = get_rse_attribute(key=CHECKSUM_KEY, rse_id=rse_id, session=session)

    if not checksum_support_attribute_list:
        return GLOBALLY_SUPPORTED_CHECKSUMS
    else:
        supported_checksum_list = checksum_support_attribute_list[0].split(',')
        if 'none' in supported_checksum_list:
            return []
        return supported_checksum_list


@read_session
def get_rse_is_checksum_supported(checksum_name, rse_id=None, session=None):
    """
    Retrieve RSE attribute value.

    :param checksum_name: The desired checksum name for the attribute.
    :param rse_id: The RSE id.
    :param session: The database session in use.

    :returns: True if required checksum is supported, False otherwise.
    """
    if is_checksum_valid(checksum_name):
        return checksum_name in get_rse_supported_checksums(rse_id=rse_id, session=session)
    else:
        return False


@transactional_session
def set_rse_usage(rse_id, source, used, free, session=None):
    """
    Set RSE usage information.

    :param rse_id: the location id.
    :param source: The information source, e.g. srm.
    :param used: the used space in bytes.
    :param free: the free in bytes.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    rse_usage = models.RSEUsage(rse_id=rse_id, source=source, used=used, free=free)
    # versioned_session(session)
    rse_usage = session.merge(rse_usage)
    rse_usage.save(session=session)

    # rse_usage_history = models.RSEUsage.__history_mapper__.class_(rse_id=rse.id, source=source, used=used, free=free)
    # rse_usage_history.save(session=session)

    return True


@read_session
def get_rse_usage(rse_id, source=None, session=None, per_account=False):
    """
    get rse usage information.

    :param rse_id:  The RSE id.
    :param source: The information source, e.g. srm.
    :param session: The database session in use.
    :param per_account: Boolean whether the usage should be also calculated per account or not.

    :returns: List of RSE usage data.
    """

    query_rse_usage = session.query(models.RSEUsage).filter_by(rse_id=rse_id)
    usage = list()

    if source:
        query_rse_usage = query_rse_usage.filter_by(source=source)

    rse = get_rse_name(rse_id=rse_id, session=session)
    for row in query_rse_usage:
        total = (row.free or 0) + (row.used or 0)
        rse_usage = {'rse_id': rse_id,
                     'rse': rse,
                     'source': row.source,
                     'used': row.used, 'free': row.free,
                     'total': total,
                     'files': row.files,
                     'updated_at': row.updated_at}
        if per_account:
            query_account_usage = session.query(models.AccountUsage).filter_by(rse_id=rse_id)
            account_usages = []
            for row in query_account_usage:
                if row.bytes != 0:
                    percentage = round(float(row.bytes) / float(total) * 100, 2) if total else 0
                    account_usages.append({'used': row.bytes, 'account': row.account, 'percentage': percentage})
            account_usages.sort(key=lambda x: x['used'], reverse=True)
            rse_usage['account_usages'] = account_usages
        usage.append(rse_usage)
    return usage


@transactional_session
def set_rse_limits(rse_id, name, value, session=None):
    """
    Set RSE limits.

    :param rse_id: The RSE id.
    :param name: The name of the limit.
    :param value: The feature value. Set to -1 to remove the limit.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    rse_limit = models.RSELimit(rse_id=rse_id, name=name, value=value)
    rse_limit = session.merge(rse_limit)
    rse_limit.save(session=session)
    return True


@read_session
def get_rse_limits(rse_id, name=None, session=None):
    """
    Get RSE limits.

    :param rse_id: The RSE id.
    :param name: A Limit name.

    :returns: A dictionary with the limits {'limit.name': limit.value}.
    """

    query = session.query(models.RSELimit).filter_by(rse_id=rse_id)
    if name:
        query = query.filter_by(name=name)
    limits = {}
    for limit in query:
        limits[limit.name] = limit.value
    return limits


@transactional_session
def delete_rse_limit(rse_id, name=None, session=None):
    """
    Delete RSE limit.

    :param rse_id: The RSE id.
    :param name: The name of the limit.
    """
    try:
        session.query(models.RSELimit).filter_by(rse_id=rse_id, name=name).delete()
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@transactional_session
def set_rse_transfer_limits(rse_id, activity, rse_expression=None, max_transfers=0, transfers=0, waitings=0, volume=0, deadline=1, strategy='fifo', session=None):
    """
    Set RSE transfer limits.

    :param rse_id: The RSE id.
    :param activity: The activity.
    :param rse_expression: RSE expression string.
    :param max_transfers: Maximum transfers.
    :param transfers: Current number of tranfers.
    :param waitings: Current number of waitings.
    :param volume: Maximum transfer volume in bytes.
    :param deadline: Maximum waiting time in hours until a datasets gets released.
    :param strategy: Stragey to handle datasets `fifo` or `grouped_fifo`.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    try:
        rse_tr_limit = models.RSETransferLimit(rse_id=rse_id, activity=activity, rse_expression=rse_expression,
                                               max_transfers=max_transfers, transfers=transfers,
                                               waitings=waitings, volume=volume, strategy=strategy, deadline=deadline)
        rse_tr_limit = session.merge(rse_tr_limit)
        rowcount = rse_tr_limit.save(session=session)
        return rowcount
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@read_session
def get_rse_transfer_limits(rse_id=None, activity=None, session=None):
    """
    Get RSE transfer limits.

    :param rse_id: The RSE id.
    :param activity: The activity.

    :returns: A dictionary with the limits {'limit.activity': {'limit.rse_id': {'max_transfers': limit.max_transfers, 'transfers': 0, 'waitings': 0, 'volume': 1}}}.
    """
    try:
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
                                                    'waitings': limit.waitings,
                                                    'volume': limit.volume,
                                                    'strategy': limit.strategy,
                                                    'deadline': limit.deadline}
        return limits
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@transactional_session
def delete_rse_transfer_limits(rse_id, activity=None, session=None):
    """
    Delete RSE transfer limits.

    :param rse_id: The RSE id.
    :param activity: The activity.
    """
    try:
        query = session.query(models.RSETransferLimit).filter_by(rse_id=rse_id)
        if activity:
            query = query.filter_by(activity=activity)
        rowcount = query.delete()
        return rowcount
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@stream_session
def list_rse_usage_history(rse_id, source=None, session=None):
    """
    List RSE usage history information.

    :param rse_id: The RSE id.
    :param source: The source of the usage information (srm, rucio).
    :param session: The database session in use.

    :returns: A list of historic RSE usage.
    """
    query = session.query(models.RSEUsage.__history_mapper__.class_).filter_by(rse_id=rse_id).order_by(models.RSEUsage.__history_mapper__.class_.updated_at.desc())
    if source:
        query = query.filter_by(source=source)

    rse = get_rse_name(rse_id=rse_id, session=session)
    for usage in query.yield_per(5):
        yield ({'rse_id': rse_id, 'rse': rse,
                'source': usage.source,
                'used': usage.used if usage.used else 0,
                'total': usage.used if usage.used else 0 + usage.free if usage.free else 0,
                'free': usage.free if usage.free else 0,
                'updated_at': usage.updated_at})


@transactional_session
def add_protocol(rse_id, parameter, session=None):
    """
    Add a protocol to an existing RSE. If entries with equal or less priority for
    an operation exist, the existing one will be reorded (i.e. +1).

    :param rse_id: the id of the new rse.
    :param parameter: parameters of the new protocol entry.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEOperationNotSupported: If no scheme supported the requested operation for the given RSE.
    :raises RSEProtocolDomainNotSupported: If an undefined domain was provided.
    :raises RSEProtocolPriorityError: If the provided priority for the scheme is to big or below zero.
    :raises Duplicate: If scheme with identifier, hostname and port already exists
                       for the given RSE.
    """

    rse = ""
    try:
        rse = get_rse_name(rse_id=rse_id, session=session, include_deleted=False)
    except exception.RSENotFound:
        raise exception.RSENotFound('RSE id \'%s\' not found' % rse_id)
    # Insert new protocol entry
    parameter['rse_id'] = rse_id

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
                op_name = op if op == 'third_party_copy' else ''.join([op, '_', s]).lower()
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
        if ('extended_attributes' not in parameter) or ('web_service_path' not in parameter['extended_attributes']):
            raise exception.InvalidObject('Missing values! For SRM, extended_attributes and web_service_path must be specified')

    try:
        new_protocol = models.RSEProtocols()
        new_protocol.update(parameter)
        new_protocol.save(session=session)
    except (IntegrityError, FlushError, OperationalError) as error:
        if ('UNIQUE constraint failed' in error.args[0]) or ('conflicts with persistent instance' in error.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*RSE_PROTOCOLS_PK.*violated.*', error.args[0]) \
           or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
           or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0])\
           or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0])\
           or match('.*IntegrityError.*columns.*are not unique.*', error.args[0]):
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (parameter['scheme'], parameter['port'], rse, parameter['hostname']))
        elif 'may not be NULL' in error.args[0] \
             or match('.*IntegrityError.*ORA-01400: cannot insert NULL into.*RSE_PROTOCOLS.*IMPL.*', error.args[0]) \
             or match('.*OperationalError.*cannot be null.*', error.args[0]):
            raise exception.InvalidObject('Missing values!')
        raise error
    return new_protocol


@read_session
def get_rse_protocols(rse_id, schemes=None, session=None):
    """
    Returns protocol information. Parameter combinations are: (operation OR default) XOR scheme.

    :param rse_id: The id of the rse.
    :param schemes: a list of schemes to filter by.
    :param session: The database session.

    :returns: A dict with RSE information and supported protocols

    :raises RSENotFound: If RSE is not found.
    """

    _rse = get_rse(rse_id=rse_id, session=session)
    if not _rse:
        raise exception.RSENotFound('RSE with id \'%s\' not found' % rse_id)

    lfn2pfn_algorithms = get_rse_attribute('lfn2pfn_algorithm', rse_id=_rse.id, session=session)
    # Resolve LFN2PFN default algorithm as soon as possible.  This way, we can send back the actual
    # algorithm name in response to REST queries.
    lfn2pfn_algorithm = get_lfn2pfn_algorithm_default()
    if lfn2pfn_algorithms:
        lfn2pfn_algorithm = lfn2pfn_algorithms[0]

    # Copy verify_checksum from the attributes, later: assume True if not specified
    verify_checksum = get_rse_attribute('verify_checksum', rse_id=_rse.id, session=session)

    # Copy sign_url from the attributes
    sign_url = get_rse_attribute('sign_url', rse_id=_rse.id, session=session)

    read = True if _rse.availability & 4 else False
    write = True if _rse.availability & 2 else False
    delete = True if _rse.availability & 1 else False

    info = {'availability_delete': delete,
            'availability_read': read,
            'availability_write': write,
            'credentials': None,
            'deterministic': _rse.deterministic,
            'domain': utils.rse_supported_protocol_domains(),
            'id': _rse.id,
            'lfn2pfn_algorithm': lfn2pfn_algorithm,
            'protocols': list(),
            'qos_class': _rse.qos_class,
            'rse': _rse.rse,
            'rse_type': str(_rse.rse_type),
            'sign_url': sign_url[0] if sign_url else None,
            'staging_area': _rse.staging_area,
            'verify_checksum': verify_checksum[0] if verify_checksum else True,
            'volatile': _rse.volatile}

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
    info['protocols'] = sorted(info['protocols'], key=lambda p: (p['hostname'], p['scheme'], p['port']))
    return info


@transactional_session
def update_protocols(rse_id, scheme, data, hostname, port, session=None):
    """
    Updates an existing protocol entry for an RSE. If necessary, priorities for read,
    write, and delete operations of other protocol entires will be updated too.

    :param rse_id: the id of the new rse.
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

    # Transform nested domains to match DB schema e.g. [domains][lan][read] => [read_lan]
    if 'domains' in data:
        for s in data['domains']:
            if s not in utils.rse_supported_protocol_domains():
                raise exception.RSEProtocolDomainNotSupported('The protocol domain \'%s\' is not defined in the schema.' % s)
            for op in data['domains'][s]:
                if op not in utils.rse_supported_protocol_operations():
                    raise exception.RSEOperationNotSupported('Operation \'%s\' not defined in schema.' % (op))
                op_name = op
                if op != 'third_party_copy':
                    op_name = ''.join([op, '_', s])
                no = session.query(models.RSEProtocols).\
                    filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rse_id,
                                           getattr(models.RSEProtocols, op_name) >= 0)).\
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

    try:
        rse = get_rse_name(rse_id=rse_id, session=session, include_deleted=False)
    except exception.RSENotFound:
        raise exception.RSENotFound('RSE with id \'%s\' not found' % rse_id)

    terms = [models.RSEProtocols.rse_id == rse_id,
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
                op_name = op
                if op != 'third_party_copy':
                    op_name = ''.join([op, '_', domain])
                if op_name in data:
                    prots = []
                    if (not getattr(up, op_name)) and data[op_name]:  # reactivate protocol e.g. from 0 to 1
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rse_id,
                                                   getattr(models.RSEProtocols, op_name) >= data[op_name])).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = data[op_name] + 1
                    elif getattr(up, op_name) and (not data[op_name]):  # deactivate protocol e.g. from 1 to 0
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rse_id,
                                                   getattr(models.RSEProtocols, op_name) > getattr(up, op_name))).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = getattr(up, op_name)
                    elif getattr(up, op_name) > data[op_name]:  # shift forward e.g. from 5 to 2
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rse_id,
                                                   getattr(models.RSEProtocols, op_name) >= data[op_name],
                                                   getattr(models.RSEProtocols, op_name) < getattr(up, op_name))).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = data[op_name] + 1
                    elif getattr(up, op_name) < data[op_name]:  # shift backward e.g. from 1 to 3
                        prots = session.query(models.RSEProtocols).\
                            filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rse_id,
                                                   getattr(models.RSEProtocols, op_name) <= data[op_name],
                                                   getattr(models.RSEProtocols, op_name) > getattr(up, op_name))).\
                            order_by(getattr(models.RSEProtocols, op_name).asc())
                        val = getattr(up, op_name)

                    for p in prots:
                        p.update({op_name: val})
                        val += 1

        up.update(data, flush=True, session=session)
    except (IntegrityError, OperationalError) as error:
        if 'UNIQUE'.lower() in error.args[0].lower() or 'Duplicate' in error.args[0]:  # Covers SQLite, Oracle and MySQL error
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (scheme, port, rse, hostname))
        elif 'may not be NULL' in error.args[0] or "cannot be null" in error.args[0]:
            raise exception.InvalidObject('Missing values: %s' % error.args[0])
        raise error
    except DatabaseError as error:
        if match('.*DatabaseError.*ORA-01407: cannot update .*RSE_PROTOCOLS.*IMPL.*to NULL.*', error.args[0]):
            raise exception.InvalidObject('Invalid values !')
        raise error


@transactional_session
def del_protocols(rse_id, scheme, hostname=None, port=None, session=None):
    """
    Deletes an existing protocol entry for an RSE.

    :param rse_id: the id of the new rse.
    :param scheme: Protocol identifer.
    :param hostname: Hostname defined for the scheme, used if more than one scheme
                     is registered with the same identifier.
    :param port: The port registered for the hostename, used if more than one scheme
                     is regsitered with the same identifier and hostname.
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises RSEProtocolNotSupported: If no macthing scheme was found for the given RSE.
    """
    try:
        rse_name = get_rse_name(rse_id=rse_id, session=session, include_deleted=False)
    except exception.RSENotFound:
        raise exception.RSENotFound('RSE \'%s\' not found' % rse_id)
    terms = [models.RSEProtocols.rse_id == rse_id, models.RSEProtocols.scheme == scheme]
    if hostname:
        terms.append(models.RSEProtocols.hostname == hostname)
        if port:
            terms.append(models.RSEProtocols.port == port)
    p = session.query(models.RSEProtocols).filter(*terms)

    if not p.all():
        msg = 'RSE \'%s\' does not support protocol \'%s\'' % (rse_name, scheme)
        msg += ' for hostname \'%s\'' % hostname if hostname else ''
        msg += ' on port \'%s\'' % port if port else ''
        raise exception.RSEProtocolNotSupported(msg)

    for row in p:
        row.delete(session=session)

    # Filling gaps in protocol priorities
    for domain in utils.rse_supported_protocol_domains():
        for op in utils.rse_supported_protocol_operations():
            op_name = ''.join([op, '_', domain])
            if getattr(models.RSEProtocols, op_name, None):
                prots = session.query(models.RSEProtocols).\
                    filter(sqlalchemy.and_(models.RSEProtocols.rse_id == rse_id,
                                           getattr(models.RSEProtocols, op_name) > 0)).\
                    order_by(getattr(models.RSEProtocols, op_name).asc())
                i = 1
                for p in prots:
                    p.update({op_name: i})
                    i += 1


@transactional_session
def update_rse(rse_id, parameters, session=None):
    """
    Update RSE properties like availability or name.

    :param rse_id: the id of the new rse.
    :param  parameters: A dictionnary with property (name, read, write, delete as keys).
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    """
    try:
        query = session.query(models.RSE).filter_by(id=rse_id).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with ID \'%s\' cannot be found' % rse_id)
    availability = 0
    rse = query.rse
    for column in query:
        if column[0] == 'availability':
            availability = column[1] or availability

    param = {}
    availability_mapping = {'availability_read': 4, 'availability_write': 2, 'availability_delete': 1}

    for key in parameters:
        if key == 'name' and parameters['name'] != rse:  # Needed due to wrongly setting name in pre1.22.7 clients
            param['rse'] = parameters['name']
        elif key in ['availability_read', 'availability_write', 'availability_delete']:
            if parameters[key] is True:
                availability = availability | availability_mapping[key]
            else:
                availability = availability & ~availability_mapping[key]
        elif key in ['latitude', 'longitude', 'time_zone', 'rse_type', 'volatile', 'deterministic', 'region_code', 'country_name', 'city', 'staging_area', 'qos_class']:
            param[key] = parameters[key]
    param['availability'] = availability

    # handle null-able keys
    for key in parameters:
        if key in ['qos_class']:
            if param[key] and param[key].lower() in ['', 'none', 'null']:
                param[key] = None

    query.update(param)
    if 'rse' in param:
        add_rse_attribute(rse_id=rse_id, key=parameters['name'], value=True, session=session)
        query = session.query(models.RSEAttrAssociation).filter_by(rse_id=rse_id).filter(models.RSEAttrAssociation.key == rse)
        rse_attr = query.one()
        rse_attr.delete(session=session)


@read_session
def export_rse(rse_id, session=None):
    """
    Get the internal representation of an RSE.

    :param rse_id: The RSE id.

    :returns: A dictionary with the internal representation of an RSE.
    """

    query = session.query(models.RSE).filter_by(id=rse_id)

    rse_data = {}
    for _rse in query:
        for k, v in _rse:
            rse_data[k] = v

    rse_data.pop('continent')
    rse_data.pop('ASN')
    rse_data.pop('ISP')
    rse_data.pop('deleted')
    rse_data.pop('deleted_at')

    # get RSE attributes
    rse_data['attributes'] = list_rse_attributes(rse_id=rse_id)

    protocols = get_rse_protocols(rse_id=rse_id)
    rse_data['lfn2pfn_algorithm'] = protocols.get('lfn2pfn_algorithm')
    rse_data['verify_checksum'] = protocols.get('verify_checksum')
    rse_data['credentials'] = protocols.get('credentials')
    rse_data['availability_delete'] = protocols.get('availability_delete')
    rse_data['availability_write'] = protocols.get('availability_write')
    rse_data['availability_read'] = protocols.get('availability_read')
    rse_data['protocols'] = protocols.get('protocols')

    # get RSE limits
    limits = get_rse_limits(rse_id=rse_id)
    rse_data['MinFreeSpace'] = limits.get('MinFreeSpace')
    rse_data['MaxBeingDeletedFiles'] = limits.get('MaxBeingDeletedFiles')

    return rse_data


@transactional_session
def add_qos_policy(rse_id, qos_policy, session=None):
    """
    Add a QoS policy from an RSE.

    :param rse_id: The id of the RSE.
    :param qos_policy: The QoS policy to add.
    :param session: The database session in use.

    :raises Duplicate: If the QoS policy already exists.
    :returns: True if successful, except otherwise.
    """

    try:
        new_qos_policy = models.RSEQoSAssociation()
        new_qos_policy.update({'rse_id': rse_id,
                               'qos_policy': qos_policy})
        new_qos_policy.save(session=session)
    except (IntegrityError, FlushError, OperationalError) as error:
        if ('UNIQUE constraint failed' in error.args[0]) or ('conflicts with persistent instance' in error.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*RSE_PROTOCOLS_PK.*violated.*', error.args[0]) \
           or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
           or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0])\
           or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0])\
           or match('.*IntegrityError.*columns.*are not unique.*', error.args[0]):
            raise exception.Duplicate('QoS policy %s already exists!' % qos_policy)
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    return True


@transactional_session
def delete_qos_policy(rse_id, qos_policy, session=None):
    """
    Delete a QoS policy from an RSE.

    :param rse_id: The id of the RSE.
    :param qos_policy: The QoS policy to delete.
    :param session: The database session in use.

    :returns: True if successful, silent failure if QoS policy does not exist.
    """

    try:
        session.query(models.RSEQoSAssociation.qos_policy).filter_by(rse_id=rse_id, qos_policy=qos_policy).delete()
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    return True


@read_session
def list_qos_policies(rse_id, session=None):
    """
    List all QoS policies of an RSE.

    :param rse_id: The id of the RSE.
    :param session: The database session in use.

    :returns: List containing all QoS policies.
    """

    qos_policies = []
    try:
        query = session.query(models.RSEQoSAssociation.qos_policy).filter_by(rse_id=rse_id)
        for qos_policy in query:
            qos_policies.append(qos_policy[0])
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    return qos_policies
