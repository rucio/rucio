# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from datetime import datetime
import json
from io import StringIO
from re import match
from typing import Any, Dict, List, Optional, Iterable, Union, TYPE_CHECKING

import sqlalchemy
from dogpile.cache.api import NO_VALUE
from sqlalchemy.exc import DatabaseError, IntegrityError, OperationalError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import FlushError
from sqlalchemy.sql.expression import or_, and_, asc, desc, true, false, func, select, delete

from rucio.common import exception, utils
from rucio.common.cache import make_region_memcached
from rucio.common.config import get_lfn2pfn_algorithm_default
from rucio.common.utils import CHECKSUM_KEY, GLOBALLY_SUPPORTED_CHECKSUMS, Availability
from rucio.core.rse_counter import add_counter, get_counter
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType, ReplicaState
from rucio.db.sqla.session import read_session, transactional_session, stream_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


RSE_SETTINGS = ["continent", "city", "region_code", "country_name", "time_zone", "ISP", "ASN"]
REGION = make_region_memcached(expiration_time=900)


class RseData:
    """
    Helper data class storing rse data grouped in one place.
    """
    def __init__(self, id_, name: "Optional[str]" = None, columns=None, attributes=None, info=None, usage=None, limits=None, transfer_limits=None):
        self.id = id_
        self._name = name
        self._columns = columns
        self._attributes = attributes
        self._info = info
        self._usage = usage
        self._limits = limits
        self._transfer_limits = transfer_limits

    @property
    def name(self) -> str:
        if self._name is None:
            raise ValueError(f'name not loaded for rse {self}')
        return self._name

    @property
    def columns(self) -> 'Dict[str, Any]':
        if self._columns is None:
            raise ValueError(f'columns not loaded for rse {self}')
        return self._columns

    @property
    def attributes(self) -> 'Dict[str, Any]':
        if self._attributes is None:
            raise ValueError(f'attributes not loaded for rse {self}')
        return self._attributes

    @property
    def info(self) -> 'Dict[str, Any]':
        if self._info is None:
            raise ValueError(f'info not loaded for rse {self}')
        return self._info

    @property
    def usage(self) -> 'List[Dict[str, Any]]':
        if self._usage is None:
            raise ValueError(f'usage not loaded for rse {self}')
        return self._usage

    @property
    def limits(self) -> 'Dict[str, Any]':
        if self._limits is None:
            raise ValueError(f'limits not loaded for rse {self}')
        return self._limits

    @property
    def transfer_limits(self):
        if self._transfer_limits is None:
            raise ValueError(f'transfer_limits not loaded for rse {self}')
        return self._transfer_limits

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        if self._name is not None:
            return self._name
        return self.id

    def __eq__(self, other):
        if other is None:
            return False
        return self.id == other.id

    def is_tape(self):
        if self.info['rse_type'] == RSEType.TAPE or self.info['rse_type'] == 'TAPE':
            return True
        return False

    def is_tape_or_staging_required(self):
        if self.is_tape() or self.attributes.get('staging_required', False):
            return True
        return False

    @read_session
    def ensure_loaded(self, load_name=False, load_columns=False, load_attributes=False,
                      load_info=False, load_usage=False, load_limits=False, load_transfer_limits=False, *, session: "Session"):
        if self._columns is None and load_columns:
            self._columns = get_rse(rse_id=self.id, session=session)
            self._name = self._columns['rse']
        if self._attributes is None and load_attributes:
            self._attributes = list_rse_attributes(self.id, use_cache=True, session=session)
        if self._info is None and load_info:
            self._info = get_rse_info(self.id, session=session)
            self._name = self._info['rse']
        if self._usage is None and load_usage:
            self._usage = get_rse_usage(rse_id=self.id, session=session)
        if self._limits is None and load_limits:
            self._limits = get_rse_limits(rse_id=self.id, session=session)
        if self._transfer_limits is None and load_transfer_limits:
            self._transfer_limits = get_rse_transfer_limits(rse_id=self.id, session=session)
        if self._name is None and load_name:
            self._name = get_rse_name(rse_id=self.id, session=session)
        return self

    @staticmethod
    @read_session
    def bulk_load(rse_datas: "Iterable[RseData]", load_name=False, load_columns=False, load_attributes=False,
                  load_info=False, load_usage=False, load_limits=False, *, session: "Session"):
        """
        Given a sequence of RseData objects, ensure that the desired fields are initialised
        in all objects from the input.
        """
        rse_datas_by_id = {}
        names_to_load = set()
        columns_to_load = set()
        attributes_to_load = set()
        infos_to_load = set()
        usages_to_load = set()
        limits_to_load = set()
        for rse_data in rse_datas:
            rse_id = rse_data.id
            rse_datas_by_id.setdefault(rse_id, []).append(rse_data)
            if load_name and rse_data._name is None:
                names_to_load.add(rse_id)
            if load_columns and rse_data._columns is None:
                columns_to_load.add(rse_id)
            if load_attributes and rse_data._attributes is None:
                attributes_to_load.add(rse_id)
            if load_info and rse_data._info is None:
                infos_to_load.add(rse_id)
            if load_usage and rse_data._usage is None:
                usages_to_load.add(rse_id)
            if load_limits and rse_data._limits is None:
                limits_to_load.add(rse_id)

        for rse_id in names_to_load:
            name = get_rse_name(rse_id=rse_id, session=session)
            for rse_data in rse_datas_by_id[rse_id]:
                rse_data._name = name

        for rse_id in columns_to_load:
            rse = get_rse(rse_id=rse_id, session=session)
            for rse_data in rse_datas_by_id[rse_id]:
                rse_data._columns = rse
                rse_data._name = rse['rse']

        for rse_id in attributes_to_load:
            attributes = list_rse_attributes(rse_id=rse_id, use_cache=True, session=session)
            for rse_data in rse_datas_by_id[rse_id]:
                rse_data._attributes = attributes

        for rse_id in infos_to_load:
            info = get_rse_info(rse_id=rse_id, session=session)
            for rse_data in rse_datas_by_id[rse_id]:
                rse_data._info = info
                rse_data._name = info['rse']

        for rse_id in usages_to_load:
            usage = get_rse_usage(rse_id=rse_id, session=session)
            for rse_data in rse_datas_by_id[rse_id]:
                rse_data._usage = usage

        for rse_id in limits_to_load:
            limits = get_rse_limits(rse_id=rse_id, session=session)
            for rse_data in rse_datas_by_id[rse_id]:
                rse_data._limits = limits


class RseCollection:
    """
    Container which stores
    """

    def __init__(self):
        self.rse_id_to_data_map = {}

    def __getitem__(self, item):
        return self.get(item)

    def get(self, rse_id: str):
        rse_data = self.rse_id_to_data_map.get(rse_id)
        if rse_data is None:
            self.rse_id_to_data_map[rse_id] = rse_data = RseData(rse_id)
        return rse_data

    def setdefault(self, rse_id: str, rse_data: RseData):
        return self.rse_id_to_data_map.setdefault(rse_id, rse_data)

    @transactional_session
    def ensure_loaded(
            self,
            rse_ids: "Iterable[str]",
            load_name: bool = False,
            load_columns: bool = False,
            load_attributes: bool = False,
            load_info: bool = False,
            load_usage: bool = False,
            load_limits: bool = False,
            *,
            session: "Session",
    ):
        RseData.bulk_load(
            rse_datas=(self.rse_id_to_data_map.setdefault(rse_id, RseData(rse_id)) for rse_id in rse_ids),
            load_name=load_name,
            load_columns=load_columns,
            load_attributes=load_attributes,
            load_info=load_info,
            load_usage=load_usage,
            load_limits=load_limits,
            session=session,
        )


@transactional_session
def add_rse(rse, vo='def', deterministic=True, volatile=False, city=None, region_code=None, country_name=None, continent=None, time_zone=None,
            ISP=None, staging_area=False, rse_type=RSEType.DISK, longitude=None, latitude=None, ASN=None, availability_read: Optional[bool] = None,
            availability_write: Optional[bool] = None, availability_delete: Optional[bool] = None, *, session: "Session"):
    """
    Add a rse with the given location name.

    :param rse: the name of the new rse.
    :param vo: the vo to add the RSE to.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    :param city: City for the RSE. Accessed by `locals()`.
    :param region_code: The region code for the RSE. Accessed by `locals()`.
    :param country_name: The country. Accessed by `locals()`.
    :param continent: The continent. Accessed by `locals()`.
    :param time_zone: Timezone. Accessed by `locals()`.
    :param ISP: Internet service provider. Accessed by `locals()`.
    :param staging_area: Staging area.
    :param rse_type: RSE type.
    :param latitude: Latitude coordinate of RSE.
    :param longitude: Longitude coordinate of RSE.
    :param ASN: Access service network. Accessed by `locals()`.
    :param availability_read: If the RSE is readable.
    :param availability_write: If the RSE is writable.
    :param availability_delete: If the RSE is deletable.
    :param session: The database session in use.
    """
    if isinstance(rse_type, str):
        rse_type = RSEType(rse_type)

    availability = Availability(availability_read, availability_write, availability_delete).integer
    new_rse = models.RSE(rse=rse, vo=vo, deterministic=deterministic, volatile=volatile,
                         staging_area=staging_area, rse_type=rse_type, longitude=longitude,
                         latitude=latitude, availability=availability, availability_read=availability_read,
                         availability_write=availability_write, availability_delete=availability_delete,

                         # The following fields will be deprecated, they are RSE attributes now.
                         # (Still in the code for backwards compatibility)
                         city=city, region_code=region_code, country_name=country_name,
                         continent=continent, time_zone=time_zone, ISP=ISP, ASN=ASN)
    try:
        new_rse.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('RSE \'%(rse)s\' already exists!' % locals())
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    # Add rse name as a RSE-Tag
    add_rse_attribute(rse_id=new_rse.id, key=rse, value=True, session=session)

    for setting in RSE_SETTINGS:
        # The value accessed by locals is defined in the code and it can not be
        # changed by a user request. This thus does not provide a scurity risk.
        setting_value = locals().get(setting, None)
        if setting_value:
            add_rse_attribute(rse_id=new_rse.id, key=setting, value=setting_value, session=session)

    # Add counter to monitor the space usage
    add_counter(rse_id=new_rse.id, session=session)

    return new_rse.id


@read_session
def rse_exists(rse, vo='def', include_deleted=False, *, session: "Session"):
    """
    Checks to see if RSE exists.

    :param rse: Name of the rse.
    :param vo: The VO for the RSE.
    :param session: The database session in use.

    :returns: True if found, otherwise false.
    """
    stmt = select(
        models.RSE
    ).where(
        and_(
            models.RSE.rse == rse,
            models.RSE.vo == vo
        )
    )
    if not include_deleted:
        stmt = stmt.where(models.RSE.deleted == false())
    return True if session.execute(stmt).scalar() else False


@transactional_session
def del_rse(rse_id, *, session: "Session"):
    """
    Disable a rse with the given rse id.

    :param rse_id: the rse id.
    :param session: The database session in use.
    """

    try:
        stmt = select(
            models.RSE
        ).where(
            models.RSE.id == rse_id,
            models.RSE.deleted == false()
        )
        db_rse = session.execute(stmt).scalar_one()
        rse_name = db_rse.rse
        if not rse_is_empty(rse_id=rse_id, session=session):
            raise exception.RSEOperationNotSupported('RSE \'%s\' is not empty' % rse_name)
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with id \'%s\' cannot be found' % rse_id)
    db_rse.delete(session=session)
    try:
        del_rse_attribute(rse_id=rse_id, key=rse_name, session=session)
    except exception.RSEAttributeNotFound:
        pass


@transactional_session
def restore_rse(rse_id, *, session: "Session"):
    """
    Restore a rse with the given rse id.

    :param rse_id: the rse id.
    :param session: The database session in use.
    """

    try:
        stmt = select(
            models.RSE
        ).where(
            models.RSE.id == rse_id,
            models.RSE.deleted == true()
        )
        db_rse = session.execute(stmt).scalar_one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with id \'%s\' cannot be found' % rse_id)
    db_rse.deleted = False
    db_rse.deleted_at = None
    db_rse.save(session=session)
    rse_name = db_rse.rse
    add_rse_attribute(rse_id=rse_id, key=rse_name, value=True, session=session)


@read_session
def rse_is_empty(rse_id, *, session: "Session"):
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
def _format_get_rse(db_rse, rse_attributes: Optional[Dict[str, Any]] = None, *, session: "Session"):
    """
    Given a models.RSE object, return it formatted as expected by callers of get_rse
    """
    result = db_rse.to_dict()
    result['type'] = db_rse.rse_type
    if rse_attributes is not None:
        rse_settings = {key: rse_attributes[key] for key in RSE_SETTINGS if key in rse_attributes}
    else:
        stmt = select(
            models.RSEAttrAssociation
        ).where(
            and_(models.RSEAttrAssociation.rse_id == db_rse.id,
                 models.RSEAttrAssociation.key.in_(RSE_SETTINGS)),
        )
        rse_settings = {row.key: row.value for row in session.execute(stmt).scalars()}
    result.update(rse_settings)
    return result


@read_session
def get_rse(rse_id, *, session: "Session"):
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
        return _format_get_rse(tmp, session=session)
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with id \'%s\' cannot be found' % rse_id)


@read_session
def get_rse_id(rse, vo='def', include_deleted=True, *, session: "Session"):
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
        stmt = select(
            models.RSE.id
        ).where(
            models.RSE.rse == rse,
            models.RSE.vo == vo
        )
        if not include_deleted:
            stmt = stmt.where(models.RSE.deleted == false())
        result = session.execute(stmt).scalar_one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound("RSE '%s' cannot be found in vo '%s'" % (rse, vo))

    if include_deleted:
        REGION.set(cache_key, result)
    return result


@read_session
def _get_rse_db_column(rse_id: str, column, cache_prefix: str, include_deleted: bool = True, *, session: "Session"):
    if include_deleted:
        cache_key = '{}_{}'.format(cache_prefix, rse_id)
        result = REGION.get(cache_key)
        if result != NO_VALUE:
            return result

    try:
        stmt = select(
            column
        ).where(
            models.RSE.id == rse_id
        )
        if not include_deleted:
            stmt = stmt.where(models.RSE.deleted == false())
        result = session.execute(stmt).scalar_one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with ID \'%s\' cannot be found' % rse_id)

    if include_deleted:
        REGION.set(cache_key, result)
    return result


@read_session
def get_rse_name(rse_id: str, include_deleted: bool = True, *, session: "Session"):
    """
    Get a RSE name or raise if it does not exist.

    :param rse_id: the rse uuid from the database.
    :param session: The database session in use.
    :param include_deleted: Flag to toggle finding rse's marked as deleted.

    :returns: The rse name.

    :raises RSENotFound: If referred RSE was not found in the database.
    """
    return _get_rse_db_column(
        rse_id=rse_id,
        column=models.RSE.rse,
        cache_prefix='rse-name',
        include_deleted=include_deleted,
        session=session
    )


@read_session
def get_rse_vo(rse_id: str, include_deleted: bool = True, *, session: "Session"):
    """
    Get the VO for a given RSE id.

    :param rse_id: the rse uuid from the database.
    :param session: the database session in use.
    :param include_deleted: Flag to toggle finding rse's marked as deleted.

    :returns The vo name.

    :raises RSENotFound: If referred RSE was not found in database.
    """
    return _get_rse_db_column(
        rse_id=rse_id,
        column=models.RSE.vo,
        cache_prefix='rse-vo',
        include_deleted=include_deleted,
        session=session
    )


@read_session
def list_rses(filters={}, *, session: "Session"):
    """
    Returns a list of all RSEs.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns: a list of dictionaries.
    """

    rse_list = []
    filters = filters.copy()  # Make a copy, so we can pop() without affecting the object `filters` outside this function

    stmt = select(
        models.RSE
    ).where(
        models.RSE.deleted == false()
    )
    if filters:
        if 'availability' in filters and ('availability_read' in filters or 'availability_write' in filters or 'availability_delete' in filters):
            raise exception.InvalidObject('Cannot use availability and read, write, delete filter at the same time.')

        if 'availability' in filters:
            availability = Availability.from_integer(filters['availability'])
            filters['availability_read'] = availability.read
            filters['availability_write'] = availability.write
            filters['availability_delete'] = availability.delete
            del filters['availability']

        for (k, v) in filters.items():
            if hasattr(models.RSE, k):
                if k == 'rse_type':
                    stmt = stmt.where(getattr(models.RSE, k) == RSEType[v])
                else:
                    stmt = stmt.where(getattr(models.RSE, k) == v)
            else:
                attr_assoc_alias = aliased(models.RSEAttrAssociation)
                stmt = stmt.join(
                    attr_assoc_alias,
                    and_(
                        attr_assoc_alias.rse_id == models.RSE.id,
                        attr_assoc_alias.key == k,
                        attr_assoc_alias.value == v,
                    )
                )
    else:
        stmt = stmt.order_by(
            models.RSE.rse
        )

    for row in session.execute(stmt).scalars():
        dic = {}
        for column in row.__table__.columns:
            dic[column.name] = getattr(row, column.name)
        rse_list.append(dic)

    return rse_list


@transactional_session
def add_rse_attribute(rse_id, key, value, *, session: "Session"):
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
def del_rse_attribute(rse_id, key, *, session: "Session"):
    """
    Delete a RSE attribute.

    :param rse_id: the id of the rse.
    :param key: the attribute key.
    :param session: The database session in use.

    :return: True if RSE attribute was deleted.
    """
    try:
        stmt = select(
            models.RSEAttrAssociation
        ).where(
            models.RSEAttrAssociation.rse_id == rse_id,
            models.RSEAttrAssociation.key == key
        )
        rse_attr = session.execute(stmt).scalar_one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSEAttributeNotFound('RSE attribute \'%s\' cannot be found' % key)
    rse_attr.delete(session=session)
    return True


@read_session
def list_rse_attributes(rse_id: str, use_cache: bool = False, *, session: "Session"):
    """
    List RSE attributes for a RSE.

    :param rse_id:  The RSE id.
    :param use_cache: decides if cache will be used or not
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """
    cache_key = 'rse_attributes_%s' % rse_id
    if use_cache:
        value = REGION.get(cache_key)

        if value is not NO_VALUE:
            return value

    rse_attrs = {}

    stmt = select(
        models.RSEAttrAssociation
    ).where(
        models.RSEAttrAssociation.rse_id == rse_id
    )
    for attr in session.execute(stmt).scalars():
        rse_attrs[attr.key] = attr.value

    if use_cache:
        REGION.set(cache_key, rse_attrs)

    return rse_attrs


@read_session
def has_rse_attribute(rse_id, key, *, session: "Session"):
    """
    Indicates whether the named key is present for the RSE.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.
    :param session: The database session in use.

    :returns: True or False
    """
    stmt = select(
        models.RSEAttrAssociation.value
    ).where(
        models.RSEAttrAssociation.rse_id == rse_id,
        models.RSEAttrAssociation.key == key
    )
    if session.execute(stmt).scalar():
        return True
    return False


@read_session
def get_rses_with_attribute(key, *, session: "Session"):
    """
    Return all RSEs with a certain attribute.

    :param key: The key for the attribute.
    :param session: The database session in use.

    :returns: List of rse dictionaries
    """
    rse_list = []

    stmt = select(
        models.RSE
    ).where(
        models.RSE.deleted == false()
    ).join(
        models.RSEAttrAssociation,
        and_(
            models.RSEAttrAssociation.rse_id == models.RSE.id,
            models.RSEAttrAssociation.key == key
        )
    )

    for db_rse in session.execute(stmt).scalars():
        d = {}
        for column in db_rse.__table__.columns:
            d[column.name] = getattr(db_rse, column.name)
        rse_list.append(d)

    return rse_list


@read_session
def get_rses_with_attribute_value(key, value, vo='def', *, session: "Session"):
    """
    Return all RSEs with a certain attribute.

    :param key: The key for the attribute.
    :param value: The value for the attribute.
    :param session: The database session in use.

    :returns: List of rse dictionaries with the rse_id and rse_name
    """
    if vo != 'def':
        cache_key = 'av-%s-%s@%s' % (key, value, vo)
    else:
        cache_key = 'av-%s-%s' % (key, value)

    result = REGION.get(cache_key)
    if result is NO_VALUE:

        rse_list = []

        stmt = select(
            models.RSE.id,
            models.RSE.rse,
        ).where(
            models.RSE.deleted == false(),
            models.RSE.vo == vo
        ).join(
            models.RSEAttrAssociation,
            and_(
                models.RSEAttrAssociation.rse_id == models.RSE.id,
                models.RSEAttrAssociation.key == key,
                models.RSEAttrAssociation.value == value
            )
        )

        for row in session.execute(stmt):
            rse_list.append({
                'rse_id': row.id,
                'rse_name': row.rse
            })

        REGION.set(cache_key, rse_list)
        return rse_list

    return result


@read_session
def get_rse_attribute(rse_id: str, key: str, use_cache: bool = True, *, session: "Session") -> Optional[Union[str, bool]]:
    """
    Retrieve RSE attribute value. If it is not cached, look it up in the
    database. If the value exists and is not cached, it will be added to the
    cache.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.
    :param session: The database session in use.

    :returns: The value for the rse attribute, None if it does not exist.
    """
    cache_key = f'rse_attributes_{rse_id}_{key}'
    if use_cache:
        value = REGION.get(cache_key)

        if value is not NO_VALUE:
            return value

    stmt = select(
        models.RSEAttrAssociation.value
    ).where(
        models.RSEAttrAssociation.rse_id == rse_id,
        models.RSEAttrAssociation.key == key
    )
    value = session.execute(stmt).scalar_one_or_none()

    if use_cache:
        REGION.set(cache_key, value)

    return value


def get_rse_supported_checksums_from_attributes(rse_attributes: Dict[str, Any]) -> List[str]:
    """
    Parse the RSE attribute defining the checksum supported by the RSE
    :param rse_attributes: attributes retrieved using list_rse_attributes
    :returns: A list of the names of supported checksums indicated by the specified attributes.
    """
    return parse_checksum_support_attribute(rse_attributes.get(CHECKSUM_KEY, ''))


def parse_checksum_support_attribute(checksum_attribute: str) -> List[str]:
    """
    Parse the checksum support RSE attribute.
    :param checksum_attribute: The value of the RSE attribute storing the checksum value

    :returns: The list of checksums supported by the selected RSE.
              If the list is empty (aka attribute is not set) it returns all the default checksums.
              Use 'none' to explicitly tell the RSE does not support any checksum algorithm.
    """

    if not checksum_attribute:
        return GLOBALLY_SUPPORTED_CHECKSUMS

    supported_checksum_list = [c.strip() for c in checksum_attribute.split(',') if c.strip()]

    if 'none' in supported_checksum_list:
        return []
    else:
        return supported_checksum_list


@transactional_session
def set_rse_usage(rse_id, source, used, free, files=None, *, session: "Session"):
    """
    Set RSE usage information.

    :param rse_id: the location id.
    :param source: The information source, e.g. srm.
    :param used: the used space in bytes.
    :param free: the free in bytes.
    :param files: the number of files
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    rse_usage = models.RSEUsage(rse_id=rse_id, source=source, used=used, free=free, files=files)
    # versioned_session(session)
    rse_usage = session.merge(rse_usage)
    rse_usage.save(session=session)

    # rse_usage_history = models.RSEUsage.__history_mapper__.class_(rse_id=rse.id, source=source, used=used, free=free)
    # rse_usage_history.save(session=session)

    return True


@read_session
def get_rse_usage(rse_id, source=None, per_account=False, *, session: "Session"):
    """
    get rse usage information.

    :param rse_id:  The RSE id.
    :param source: The information source, e.g. srm.
    :param session: The database session in use.
    :param per_account: Boolean whether the usage should be also calculated per account or not.

    :returns: List of RSE usage data.
    """

    stmt_rse_usage = select(
        models.RSEUsage
    ).where(
        models.RSEUsage.rse_id == rse_id
    )
    usage = list()

    if source:
        stmt_rse_usage = stmt_rse_usage.where(
            models.RSEUsage.source == source
        )

    for row in session.execute(stmt_rse_usage).scalars():
        total = (row.free or 0) + (row.used or 0)
        rse_usage = {'rse_id': rse_id,
                     'source': row.source,
                     'used': row.used,
                     'free': row.free,
                     'total': total,
                     'files': row.files,
                     'updated_at': row.updated_at}
        if per_account and row.source == 'rucio':
            stmt_account_usage = select(
                models.AccountUsage
            ).where(
                models.AccountUsage.rse_id == rse_id
            )
            account_usages = []
            for row in session.execute(stmt_account_usage).scalars():
                if row.bytes != 0:
                    percentage = round(float(row.bytes) / float(total) * 100, 2) if total else 0
                    account_usages.append({'used': row.bytes, 'account': row.account, 'percentage': percentage})
            account_usages.sort(key=lambda x: x['used'], reverse=True)
            rse_usage['account_usages'] = account_usages
        usage.append(rse_usage)
    return usage


@transactional_session
def set_rse_limits(rse_id: str, name: str, value: int, *, session: 'Session') -> bool:
    """
    Set RSE limits.

    :param rse_id: The RSE id.
    :param name: The name of the limit.
    :param value: The feature value.
    :param session: The database session in use.

    :returns: True if successful, otherwise false.
    """
    rse_limit = models.RSELimit(rse_id=rse_id, name=name, value=value)
    rse_limit = session.merge(rse_limit)
    rse_limit.save(session=session)
    return True


@read_session
def get_rse_limits(rse_id: str, name: "Optional[str]" = None, *, session: 'Session') -> 'Dict[str, int]':
    """
    Get RSE limits.

    :param rse_id: The RSE id.
    :param name: A Limit name.

    :returns: A dictionary with the limits {'limit.name': limit.value}.
    """

    stmt = select(
        models.RSELimit
    ).where(
        models.RSELimit.rse_id == rse_id
    )
    if name:
        stmt = stmt.where(
            models.RSELimit.name == name
        )
    return {limit.name: limit.value for limit in session.execute(stmt).scalars()}


@transactional_session
def delete_rse_limits(rse_id: str, name: "Optional[str]" = None, *, session: 'Session') -> None:
    """
    Delete RSE limit.

    :param rse_id: The RSE id.
    :param name: The name of the limit.
    """
    try:
        stmt = delete(
            models.RSELimit
        ).where(
            models.RSELimit.rse_id == rse_id,
        )
        if name is not None:
            stmt = stmt.where(
                models.RSELimit.name == name
            )
        session.execute(stmt)
    except IntegrityError as error:
        raise exception.RucioException(error.args)


def _sanitize_rse_transfer_limit_dict(limit_dict):
    if limit_dict['activity'] == 'all_activities':
        limit_dict['activity'] = None
    return limit_dict


@read_session
def get_rse_transfer_limits(rse_id, activity=None, *, session: "Session"):
    """
    Get RSE transfer limits.

    :param rse_id: The RSE id.
    :param activity: The activity.

    :returns: A dictionary with the limits {'limit.direction': {'limit.activity': limit}}.
    """
    try:
        stmt = select(
            models.TransferLimit
        ).join_from(
            models.RSETransferLimit,
            models.TransferLimit,
            and_(models.RSETransferLimit.limit_id == models.TransferLimit.id,
                 models.RSETransferLimit.rse_id == rse_id)
        )
        if activity:
            stmt = stmt.where(
                or_(
                    models.TransferLimit.activity == activity,
                    models.TransferLimit.activity == 'all_activities',
                )
            )

        limits = {}
        for limit in session.execute(stmt).scalars():
            limit_dict = _sanitize_rse_transfer_limit_dict(limit.to_dict())
            limits.setdefault(limit_dict['direction'], {}).setdefault(limit_dict['activity'], limit_dict)

        return limits
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@stream_session
def list_rse_usage_history(rse_id, source=None, *, session: "Session"):
    """
    List RSE usage history information.

    :param rse_id: The RSE id.
    :param source: The source of the usage information (srm, rucio).
    :param session: The database session in use.

    :returns: A list of historic RSE usage.
    """
    stmt = select(
        models.RSEUsageHistory
    ).where(
        models.RSEUsageHistory.rse_id == rse_id
    ).order_by(
        desc(models.RSEUsageHistory.updated_at)
    )
    if source:
        stmt = stmt.where(
            models.RSEUsageHistory.source == source
        )

    rse = get_rse_name(rse_id=rse_id, session=session)
    for usage in session.execute(stmt).yield_per(5).scalars():
        yield ({'rse_id': rse_id,
                'rse': rse,
                'source': usage.source,
                'used': usage.used if usage.used else 0,
                'total': usage.used if usage.used else 0 + usage.free if usage.free else 0,
                'free': usage.free if usage.free else 0,
                'updated_at': usage.updated_at})


@transactional_session
def add_protocol(rse_id, parameter, *, session: "Session"):
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
                op_name = op if op.startswith('third_party_copy') else ''.join([op, '_', s]).lower()
                try:
                    if parameter['domains'][s][op] < 0:
                        raise exception.RSEProtocolPriorityError('The provided priority (%s)for operation \'%s\' in domain \'%s\' is not supported.' % (parameter['domains'][s][op], op, s))
                except TypeError:
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
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.*columns.*are not unique.*', error.args[0]):
            raise exception.Duplicate('Protocol \'%s\' on port %s already registered for  \'%s\' with hostname \'%s\'.' % (parameter['scheme'], parameter['port'], rse, parameter['hostname']))
        elif 'may not be NULL' in error.args[0] \
                or match('.*IntegrityError.*ORA-01400: cannot insert NULL into.*RSE_PROTOCOLS.*IMPL.*', error.args[0]) \
                or match('.*IntegrityError.*Column.*cannot be null.*', error.args[0]) \
                or match('.*IntegrityError.*null value in column.*violates not-null constraint.*', error.args[0]) \
                or match('.*IntegrityError.*NOT NULL constraint failed.*', error.args[0]) \
                or match('.*NotNullViolation.*null value in column.*violates not-null constraint.*', error.args[0]) \
                or match('.*OperationalError.*cannot be null.*', error.args[0]):
            raise exception.InvalidObject('Missing values!')

        raise exception.RucioException(error.args)
    return new_protocol


@read_session
def get_rse_protocols(rse_id, schemes=None, *, session: "Session"):
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

    lfn2pfn_algorithm = get_rse_attribute(_rse['id'], 'lfn2pfn_algorithm', session=session)
    # Resolve LFN2PFN default algorithm as soon as possible.  This way, we can send back the actual
    # algorithm name in response to REST queries.
    if not lfn2pfn_algorithm:
        lfn2pfn_algorithm = get_lfn2pfn_algorithm_default()

    # Copy verify_checksum from the attributes, later: assume True if not specified
    verify_checksum = get_rse_attribute(_rse['id'], 'verify_checksum', session=session)

    # Copy sign_url from the attributes
    sign_url = get_rse_attribute(_rse['id'], 'sign_url', session=session)

    info = {'availability_delete': _rse['availability_delete'],
            'availability_read': _rse['availability_read'],
            'availability_write': _rse['availability_write'],
            'credentials': None,
            'deterministic': _rse['deterministic'],
            'domain': utils.rse_supported_protocol_domains(),
            'id': _rse['id'],
            'lfn2pfn_algorithm': lfn2pfn_algorithm,
            'protocols': list(),
            'qos_class': _rse['qos_class'],
            'rse': _rse['rse'],
            'rse_type': _rse['rse_type'].name,
            'sign_url': sign_url,
            'staging_area': _rse['staging_area'],
            'verify_checksum': verify_checksum if verify_checksum is not None else True,
            'volatile': _rse['volatile']}

    for op in utils.rse_supported_protocol_operations():
        info['%s_protocol' % op] = 1  # 1 indicates the default protocol

    terms = [models.RSEProtocols.rse_id == _rse['id']]
    if schemes:
        if not type(schemes) is list:
            schemes = [schemes]
        terms.extend([models.RSEProtocols.scheme.in_(schemes)])

    stmt = select(
        models.RSEProtocols.hostname,
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
        models.RSEProtocols.third_party_copy_read,
        models.RSEProtocols.third_party_copy_write,
        models.RSEProtocols.extended_attributes
    ).filter(
        *terms
    )

    for row in session.execute(stmt):
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
                         'third_party_copy_read': row.third_party_copy_read,
                         'third_party_copy_write': row.third_party_copy_write}
             },
             'extended_attributes': row.extended_attributes}

        try:
            p['extended_attributes'] = json.load(StringIO(p['extended_attributes']))
        except ValueError:
            pass  # If value is not a JSON string

        info['protocols'].append(p)
    info['protocols'] = sorted(info['protocols'], key=lambda p: (p['hostname'], p['scheme'], p['port']))
    return info


@read_session
def get_rse_info(rse_id, *, session: "Session"):
    """
    For historical reasons, related to usage of rsemanager, "rse_info" is equivalent to
    a cached call to get_rse_protocols without any schemes set.

    :param rse_id: The id of the rse.
    :param session: The database session.
    :returns: A dict with RSE information and supported protocols
    """
    key = 'rse_info_%s' % rse_id
    result = REGION.get(key)
    if result is NO_VALUE:
        result = get_rse_protocols(rse_id=rse_id, session=session)
        REGION.set(key, result)
    return result


@transactional_session
def update_protocols(rse_id, scheme, data, hostname, port, *, session: "Session"):
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
                if not op.startswith('third_party_copy'):
                    op_name = ''.join([op, '_', s])
                stmt = select(
                    func.count(models.RSEProtocols.rse_id)
                ).where(
                    models.RSEProtocols.rse_id == rse_id,
                    getattr(models.RSEProtocols, op_name) >= 0
                )
                no = session.execute(stmt).scalar()
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
        stmt = select(
            models.RSEProtocols
        ).where(
            *terms
        )
        up = session.execute(stmt).scalar()
        if up is None:
            msg = 'RSE \'%s\' does not support protocol \'%s\' for hostname \'%s\' on port \'%s\'' % (rse, scheme, hostname, port)
            raise exception.RSEProtocolNotSupported(msg)

        # Preparing gaps if priority is updated
        for domain in utils.rse_supported_protocol_domains():
            for op in utils.rse_supported_protocol_operations():
                op_name = op
                if not op.startswith('third_party_copy'):
                    op_name = ''.join([op, '_', domain])
                if op_name in data:
                    stmt = None
                    if (not getattr(up, op_name)) and data[op_name]:  # reactivate protocol e.g. from 0 to 1
                        stmt = select(
                            models.RSEProtocols
                        ).where(
                            models.RSEProtocols.rse_id == rse_id,
                            getattr(models.RSEProtocols, op_name) >= data[op_name]
                        ).order_by(
                            asc(getattr(models.RSEProtocols, op_name))
                        )
                        val = data[op_name] + 1
                    elif getattr(up, op_name) and (not data[op_name]):  # deactivate protocol e.g. from 1 to 0
                        stmt = select(
                            models.RSEProtocols
                        ).where(
                            models.RSEProtocols.rse_id == rse_id,
                            getattr(models.RSEProtocols, op_name) > getattr(up, op_name)
                        ).order_by(
                            asc(getattr(models.RSEProtocols, op_name))
                        )
                        val = getattr(up, op_name)
                    elif getattr(up, op_name) > data[op_name]:  # shift forward e.g. from 5 to 2
                        stmt = select(
                            models.RSEProtocols
                        ).where(
                            models.RSEProtocols.rse_id == rse_id,
                            getattr(models.RSEProtocols, op_name) >= data[op_name],
                            getattr(models.RSEProtocols, op_name) < getattr(up, op_name)
                        ).order_by(
                            asc(getattr(models.RSEProtocols, op_name))
                        )
                        val = data[op_name] + 1
                    elif getattr(up, op_name) < data[op_name]:  # shift backward e.g. from 1 to 3
                        stmt = select(
                            models.RSEProtocols
                        ).where(
                            models.RSEProtocols.rse_id == rse_id,
                            getattr(models.RSEProtocols, op_name) <= data[op_name],
                            getattr(models.RSEProtocols, op_name) > getattr(up, op_name)
                        ).order_by(
                            asc(getattr(models.RSEProtocols, op_name))
                        )
                        val = getattr(up, op_name)

                    if stmt is not None:
                        for p in session.execute(stmt).scalars():
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
def del_protocols(rse_id, scheme, hostname=None, port=None, *, session: "Session"):
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
    stmt = select(
        models.RSEProtocols
    ).where(
        *terms
    )
    p = session.execute(stmt).scalars().all()

    if not p:
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
                stmt = select(
                    models.RSEProtocols
                ).where(
                    models.RSEProtocols.rse_id == rse_id,
                    getattr(models.RSEProtocols, op_name) > 0
                ).order_by(
                    asc(getattr(models.RSEProtocols, op_name))
                )
                i = 1
                for p in session.execute(stmt).scalars():
                    p.update({op_name: i})
                    i += 1


MUTABLE_RSE_PROPERTIES = {
    'name',
    'availability_read',
    'availability_write',
    'availability_delete',
    'latitude',
    'longitude',
    'time_zone',
    'rse_type',
    'volatile',
    'deterministic',
    'region_code',
    'country_name',
    'city',
    'staging_area',
    'qos_class',
    'continent',
    'availability'
}


@transactional_session
def update_rse(rse_id: str, parameters: 'Dict[str, Any]', *, session: "Session"):
    """
    Update RSE properties like availability or name.

    :param rse_id: the id of the new rse.
    :param parameters: A dictionary with property (name, read, write, delete as keys).
    :param session: The database session in use.

    :raises RSENotFound: If RSE is not found.
    :raises InputValidationError: If a parameter does not exist. Nothing will be added then.
    """
    for key in parameters.keys():
        if key not in MUTABLE_RSE_PROPERTIES:
            raise exception.InputValidationError(f"The key '{key}' does not exist for RSE properties.")

    try:
        stmt = select(
            models.RSE
        ).where(
            models.RSE.id == rse_id
        )
        db_rse = session.execute(stmt).scalar_one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise exception.RSENotFound('RSE with ID \'%s\' cannot be found' % rse_id)
    old_rse_name = db_rse.rse

    param = {}

    if 'availability' in parameters:
        availability = Availability.from_integer(parameters['availability'])
        param['availability_read'] = availability.read
        param['availability_write'] = availability.write
        param['availability_delete'] = availability.delete

    for key in parameters:
        if key == 'name' and parameters['name'] != old_rse_name:  # Needed due to wrongly setting name in pre1.22.7 clients
            param['rse'] = parameters['name']
        elif key in MUTABLE_RSE_PROPERTIES - {'name'}:
            param[key] = parameters[key]

    # handle null-able keys
    for key in parameters:
        if key in ['qos_class']:
            if param[key] and param[key].lower() in ['', 'none', 'null']:
                param[key] = None

    # handle rse settings
    for setting in set(param.keys()).intersection(RSE_SETTINGS):
        if has_rse_attribute(rse_id, setting, session=session):
            del_rse_attribute(rse_id, setting, session=session)
        add_rse_attribute(rse_id, setting, param[setting], session=session)

    db_rse.update(param, session=session)
    if 'rse' in param:
        add_rse_attribute(rse_id=rse_id, key=parameters['name'], value=True, session=session)
        del_rse_attribute(rse_id=rse_id, key=old_rse_name, session=session)


@read_session
def export_rse(rse_id, *, session: "Session"):
    """
    Get the internal representation of an RSE.

    :param rse_id: The RSE id.

    :returns: A dictionary with the internal representation of an RSE.
    """

    stmt = select(
        models.RSE
    ).where(
        models.RSE.id == rse_id
    )

    rse_data = {}
    for _rse in session.execute(stmt).scalars():
        for k, v in _rse:
            rse_data[k] = v

    rse_data.pop('continent')
    rse_data.pop('ASN')
    rse_data.pop('ISP')
    rse_data.pop('deleted')
    rse_data.pop('deleted_at')

    # get RSE attributes
    rse_data['attributes'] = list_rse_attributes(rse_id=rse_id, session=session)

    protocols = get_rse_protocols(rse_id=rse_id, session=session)
    rse_data['lfn2pfn_algorithm'] = protocols.get('lfn2pfn_algorithm')
    rse_data['verify_checksum'] = protocols.get('verify_checksum')
    rse_data['credentials'] = protocols.get('credentials')
    rse_data['availability_delete'] = protocols.get('availability_delete')
    rse_data['availability_write'] = protocols.get('availability_write')
    rse_data['availability_read'] = protocols.get('availability_read')
    rse_data['protocols'] = protocols.get('protocols')

    # get RSE limits
    limits = get_rse_limits(rse_id=rse_id, session=session)
    rse_data['MinFreeSpace'] = limits.get('MinFreeSpace')
    rse_data['MaxBeingDeletedFiles'] = limits.get('MaxBeingDeletedFiles')

    return rse_data


@transactional_session
def add_qos_policy(rse_id, qos_policy, *, session: "Session"):
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
def delete_qos_policy(rse_id, qos_policy, *, session: "Session"):
    """
    Delete a QoS policy from an RSE.

    :param rse_id: The id of the RSE.
    :param qos_policy: The QoS policy to delete.
    :param session: The database session in use.

    :returns: True if successful, silent failure if QoS policy does not exist.
    """

    try:
        stmt = delete(
            models.RSEQoSAssociation
        ).where(
            models.RSEQoSAssociation.rse_id == rse_id,
            models.RSEQoSAssociation.qos_policy == qos_policy
        )
        session.execute(stmt)
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    return True


@read_session
def list_qos_policies(rse_id, *, session: "Session"):
    """
    List all QoS policies of an RSE.

    :param rse_id: The id of the RSE.
    :param session: The database session in use.

    :returns: List containing all QoS policies.
    """

    qos_policies = []
    try:
        stmt = select(
            models.RSEQoSAssociation.qos_policy
        ).where(
            models.RSEQoSAssociation.rse_id == rse_id
        )
        for qos_policy in session.execute(stmt).scalars():
            qos_policies.append(qos_policy)
    except DatabaseError as error:
        raise exception.RucioException(error.args)

    return qos_policies


@transactional_session
def fill_rse_expired(rse_id, *, session: "Session"):
    """
    Fill the rse_usage for source expired

    :param rse_id: The RSE id.

    :returns: True if successful, except otherwise.
    """
    stmt = select(
        func.sum(models.RSEFileAssociation.bytes).label("bytes"),
        func.count().label("length")
    ).with_hint(
        models.RSEFileAssociation, "INDEX(REPLICAS REPLICAS_RSE_ID_TOMBSTONE_IDX)", 'oracle'
    ).where(
        models.RSEFileAssociation.tombstone < datetime.utcnow(),
        models.RSEFileAssociation.lock_cnt == 0,
        models.RSEFileAssociation.rse_id == rse_id,
        models.RSEFileAssociation.state.in_((ReplicaState.AVAILABLE, ReplicaState.UNAVAILABLE, ReplicaState.BAD))
    )

    sum_bytes, sum_files = session.execute(stmt).one()
    models.RSEUsage(rse_id=rse_id,
                    used=sum_bytes,
                    files=sum_files,
                    source='expired').save(session=session)
