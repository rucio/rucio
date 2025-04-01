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

from typing import TYPE_CHECKING, Any

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO
from rucio.common.schema import validate_schema
from rucio.common.utils import gateway_update_return_dict
from rucio.core import distance as distance_module
from rucio.core import rse as rse_module
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from typing import Optional


def add_rse(
    rse,
    issuer,
    vo=DEFAULT_VO,
    deterministic=True,
    volatile=False,
    city=None,
    region_code=None,
    country_name=None,
    continent=None,
    time_zone=None,
    ISP=None,  # noqa: N803
    staging_area=False,
    rse_type=None,
    latitude=None,
    longitude=None,
    ASN=None,  # noqa: N803
    availability_read: "Optional[bool]" = None,
    availability_write: "Optional[bool]" = None,
    availability_delete: "Optional[bool]" = None,
):
    """
    Creates a new Rucio Storage Element(RSE).

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param deterministic: Boolean to know if the pfn is generated deterministically.
    :param volatile: Boolean for RSE cache.
    :param city: City for the RSE.
    :param region_code: The region code for the RSE.
    :param country_name: The country.
    :param continent: The continent.
    :param time_zone: Timezone.
    :param staging_area: staging area.
    :param ISP: Internet service provider.
    :param rse_type: RSE type.
    :param latitude: Latitude coordinate of RSE.
    :param longitude: Longitude coordinate of RSE.
    :param ASN: Access service network.
    :param availability_read: If the RSE is readable.
    :param availability_write: If the RSE is writable.
    :param availability_delete: If the RSE is deletable.
    """
    validate_schema(name='rse', obj=rse, vo=vo)
    kwargs = {'rse': rse}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_rse', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not add RSE. %s' % (issuer, auth_result.message))

        return rse_module.add_rse(rse, vo=vo, deterministic=deterministic, volatile=volatile, city=city,
                                  region_code=region_code, country_name=country_name, staging_area=staging_area,
                                  continent=continent, time_zone=time_zone, ISP=ISP, rse_type=rse_type, latitude=latitude,
                                  longitude=longitude, ASN=ASN, availability_read=availability_read,
                                  availability_write=availability_write, availability_delete=availability_delete, session=session)


def get_rse(rse, vo=DEFAULT_VO):
    """
    Provides details about the specified RSE.

    :param rse: The RSE name.
    :param vo: The VO to act on.

    :returns: a dict with details about the RSE

    :raises RSENotFound: if the referred RSE was not found in the database
    """

    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        return rse_module.get_rse_protocols(rse_id=rse_id, session=session)


def del_rse(rse, issuer, vo=DEFAULT_VO):
    """
    Disables an RSE with the provided RSE name.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='del_rse', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not delete RSE. %s' % (issuer, auth_result.message))

        return rse_module.del_rse(rse_id, session=session)


def list_rses(filters: "Optional[dict[str, Any]]" = None, vo: str = DEFAULT_VO) -> list[dict[str, Any]]:
    """
    Lists all RSEs.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param vo: The VO to act on.

    :returns: List of all RSEs.
    """
    filters = filters or {}

    filters['vo'] = vo

    with db_session(DatabaseOperationType.READ) as session:
        return rse_module.list_rses(filters=filters, session=session)


def del_rse_attribute(rse, key, issuer, vo=DEFAULT_VO):
    """
    Delete a RSE attribute.

    :param rse: the name of the rse_module.
    :param key: the attribute key.
    :param vo: The VO to act on.

    :return: True if RSE attribute was deleted successfully, False otherwise.
    """

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id, 'key': key}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='del_rse_attribute', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not delete RSE attributes. %s' % (issuer, auth_result.message))

        return rse_module.del_rse_attribute(rse_id=rse_id, key=key, session=session)


def add_rse_attribute(rse, key, value, issuer, vo=DEFAULT_VO):
    """ Adds a RSE attribute.

    :param rse: the rse name.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    returns: True if successful, False otherwise.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id, 'key': key, 'value': value}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_rse_attribute', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not add RSE attributes. %s' % (issuer, auth_result.message))

        return rse_module.add_rse_attribute(rse_id=rse_id, key=key, value=value, session=session)


def list_rse_attributes(rse, vo=DEFAULT_VO):
    """
    List RSE attributes for a RSE_MODULE.

    :param rse: The RSE name.
    :param vo: The VO to act on.

    :returns: List of all RSE attributes for a RSE_MODULE.
    """

    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        return rse_module.list_rse_attributes(rse_id=rse_id, session=session)


def has_rse_attribute(rse_id, key):
    """
    Indicates whether the named key is present for the RSE.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.

    :returns: True or False
    """
    with db_session(DatabaseOperationType.READ) as session:
        return rse_module.has_rse_attribute(rse_id=rse_id, key=key, session=session)


def get_rses_with_attribute(key):
    """
    Return all RSEs with a certain attribute.

    :param key: The key for the attribute.

    :returns: List of rse dictionaries
    """
    with db_session(DatabaseOperationType.READ) as session:
        return rse_module.get_rses_with_attribute(key=key, session=session)


def add_protocol(rse, issuer, vo=DEFAULT_VO, **data):
    """
    Creates a new protocol entry for an existing RSE.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param data: Parameters (protocol identifier, port, hostname, ...) provided by the request.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_protocol', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not add protocols to RSE %s. %s' % (issuer, rse, auth_result.message))
        rse_module.add_protocol(rse_id, data['data'], session=session)


def get_rse_protocols(rse, issuer, vo=DEFAULT_VO):
    """
    Returns all matching protocols (including detailed information) for the given RSE.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: A dict with all supported protocols and their attributes.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        return rse_module.get_rse_protocols(rse_id, session=session)


def del_protocols(rse, scheme, issuer, vo=DEFAULT_VO, hostname=None, port=None):
    """
    Deletes all matching protocol entries for the given RSE..

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param scheme: The protocol identifier.
    :param hostname: The hostname (to be used if more then one protocol using the
                     same identifier are present)
    :param port: The port (to be used if more than one protocol using the same
                 identifier and hostname are present)
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='del_protocol', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not delete protocols from RSE %s. %s' % (issuer, rse, auth_result.message))
        rse_module.del_protocols(rse_id=rse_id, scheme=scheme, hostname=hostname, port=port, session=session)


def update_protocols(rse, scheme, data, issuer, vo=DEFAULT_VO, hostname=None, port=None):
    """
    Updates all provided attributes for all matching protocol entries of the given RSE..

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param scheme: The protocol identifier.
    :param data: A dict including the attributes of the protocol to be updated. Keys must match the column names in the database.
    :param hostname: The hostname (to be used if more then one protocol using the same identifier are present)
    :param port: The port (to be used if more than one protocol using the same identifier and hostname are present)
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='update_protocol', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update protocols from RSE %s. %s' % (issuer, rse, auth_result.message))
        rse_module.update_protocols(rse_id=rse_id, scheme=scheme, hostname=hostname, port=port, data=data, session=session)


def set_rse_usage(rse, source, used, free, issuer, files=None, vo=DEFAULT_VO):
    """
    Set RSE usage information.

    :param rse: The RSE name.
    :param source: the information source, e.g. srm.
    :param used: the used space in bytes.
    :param free: the free space in bytes.
    :param issuer: The issuer account.
    :param files: the number of files
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='set_rse_usage', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update RSE usage information for RSE %s. %s' % (issuer, rse, auth_result.message))

        return rse_module.set_rse_usage(rse_id=rse_id, source=source, used=used, free=free, files=files, session=session)


def get_rse_usage(rse, issuer, source=None, per_account=False, vo=DEFAULT_VO):
    """
    get RSE usage information.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param source: dictionary of attributes by which the results should be filtered
    :param vo: The VO to act on.

    :returns: List of RSE usage data.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        usages = rse_module.get_rse_usage(rse_id=rse_id, source=source, per_account=per_account, session=session)

        for u in usages:
            u['rse'] = rse
            if 'account_usages' in u:
                for account_usage in u['account_usages']:
                    account_usage['account'] = account_usage['account'].external
        return [gateway_update_return_dict(u, session=session) for u in usages]


def list_rse_usage_history(rse, issuer, source=None, vo=DEFAULT_VO):
    """
    List RSE usage history information.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param source: The source of the usage information (srm, rucio).
    :param vo: The VO to act on.

    :returns: A list of historic RSE usage.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        for u in rse_module.list_rse_usage_history(rse_id=rse_id, source=source, session=session):
            yield gateway_update_return_dict(u, session=session)


def set_rse_limits(rse, name, value, issuer, vo=DEFAULT_VO):
    """
    Set RSE limits.

    :param rse: The RSE name.
    :param name: The name of the limit.
    :param value: The feature value.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='set_rse_limits', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update RSE limits for RSE %s. %s' % (issuer, rse, auth_result.message))

        return rse_module.set_rse_limits(rse_id=rse_id, name=name, value=value, session=session)


def delete_rse_limits(rse, name, issuer, vo=DEFAULT_VO):
    """
    Set RSE limits.

    :param rse: The RSE name.
    :param name: The name of the limit.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='delete_rse_limits', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update RSE limits for RSE %s. %s' % (issuer, rse, auth_result.message))

        return rse_module.delete_rse_limits(rse_id=rse_id, name=name, session=session)


def get_rse_limits(rse, issuer, vo=DEFAULT_VO):
    """
    Get RSE limits.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        return rse_module.get_rse_limits(rse_id=rse_id, session=session)


def parse_rse_expression(rse_expression, vo=DEFAULT_VO):
    """
    Parse an RSE expression and return the list of RSEs.

    :param rse_expression:  The RSE expression.
    :param vo: The VO to act on.

    :returns:  List of RSEs
    :raises:   InvalidRSEExpression
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rses = parse_expression(rse_expression, filter_={'vo': vo}, session=session)
    return [rse['rse'] for rse in rses]


def update_rse(rse, parameters, issuer, vo=DEFAULT_VO):
    """
    Update RSE properties like availability or name.

    :param rse: the name of the new rse.
    :param parameters: A dictionary with property (name, read, write, delete as keys).
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :raises RSENotFound: If RSE is not found.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='update_rse', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update RSE. %s' % (issuer, auth_result.message))
        return rse_module.update_rse(rse_id=rse_id, parameters=parameters, session=session)


def add_distance(source, destination, issuer, vo=DEFAULT_VO, distance=None):
    """
    Add a src-dest distance.

    :param source: The source.
    :param destination: The destination.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param distance: Distance as an integer.
    """
    kwargs = {'source': source, 'destination': destination}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_distance', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not add RSE distances. %s' % (issuer, auth_result.message))
        try:
            return distance_module.add_distance(src_rse_id=rse_module.get_rse_id(source, vo=vo, session=session),
                                                dest_rse_id=rse_module.get_rse_id(destination, vo=vo, session=session),
                                                distance=distance, session=session)
        except exception.Duplicate:
            # use source and destination RSE names
            raise exception.Duplicate('Distance from %s to %s already exists!' % (source, destination))


def update_distance(source, destination, distance, issuer, vo=DEFAULT_VO):
    """
    Update distances with the given RSE ids.

    :param source: The source RSE.
    :param destination: The destination RSE.
    :param distance: The new distance to set
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'source': source, 'destination': destination}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='update_distance', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update RSE distances. %s' % (issuer, auth_result.message))

        return distance_module.update_distances(src_rse_id=rse_module.get_rse_id(source, vo=vo, session=session),
                                                dest_rse_id=rse_module.get_rse_id(destination, vo=vo, session=session),
                                                distance=distance, session=session)


def get_distance(source, destination, issuer, vo=DEFAULT_VO):
    """
    Get distances between rses.

    :param source: The source RSE.
    :param destination: The destination RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns distance: List of dictionaries.
    """
    with db_session(DatabaseOperationType.READ) as session:
        distances = distance_module.get_distances(src_rse_id=rse_module.get_rse_id(source, vo=vo, session=session),
                                                  dest_rse_id=rse_module.get_rse_id(destination, vo=vo, session=session),
                                                  session=session)

        return [gateway_update_return_dict(d, session=session) for d in distances]


def delete_distance(source, destination, issuer, vo=DEFAULT_VO):
    """
    Delete distances with the given RSE ids.

    :param source: The source RSE.
    :param destination: The destination RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'source': source, 'destination': destination}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='delete_distance', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update RSE distances. %s' % (issuer, auth_result.message))

        return distance_module.delete_distances(src_rse_id=rse_module.get_rse_id(source, vo=vo, session=session),
                                                dest_rse_id=rse_module.get_rse_id(destination, vo=vo, session=session),
                                                session=session)


def add_qos_policy(rse, qos_policy, issuer, vo=DEFAULT_VO):
    """
    Add a QoS policy from an RSE.

    :param rse: The name of the RSE.
    :param qos_policy: The QoS policy to add.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :raises Duplicate: If the QoS policy already exists.
    :returns: True if successful, except otherwise.
    """

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, action='add_qos_policy', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s cannot add QoS policies to RSE %s. %s' % (issuer, rse, auth_result.message))

        return rse_module.add_qos_policy(rse_id, qos_policy, session=session)


def delete_qos_policy(rse, qos_policy, issuer, vo=DEFAULT_VO):
    """
    Delete a QoS policy from an RSE.

    :param rse: The name of the RSE.
    :param qos_policy: The QoS policy to delete.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, silent failure if QoS policy does not exist.
    """

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        kwargs = {'rse_id': rse}
        auth_result = permission.has_permission(issuer=issuer, action='delete_qos_policy', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s cannot delete QoS policies from RSE %s. %s' % (issuer, rse, auth_result.message))

        return rse_module.delete_qos_policy(rse_id, qos_policy, session=session)


def list_qos_policies(rse, issuer, vo=DEFAULT_VO):
    """
    List all QoS policies of an RSE.

    :param rse: The id of the RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: List containing all QoS policies.
    """

    with db_session(DatabaseOperationType.READ) as session:
        rse_id = rse_module.get_rse_id(rse=rse, vo=vo, session=session)
        return rse_module.list_qos_policies(rse_id, session=session)
