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
# - Mario Lassnig <mario@lassnig.net>, 2012-2020
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2017
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2014
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Gabriele <sucre.91@hotmail.it>, 2019
# - elichad <eli.chadwick.256@gmail.com>, 2020
# - patrick-austin <patrick.austin@stfc.ac.uk>, 2020
#
#  PY3K COMPATIBLE

from rucio.api import permission
from rucio.common import exception
from rucio.common.schema import validate_schema
from rucio.common.utils import api_update_return_dict
from rucio.core import distance as distance_module
from rucio.core import rse as rse_module
from rucio.core.rse_expression_parser import parse_expression


def add_rse(rse, issuer, vo='def', deterministic=True, volatile=False, city=None, region_code=None,
            country_name=None, continent=None, time_zone=None, ISP=None,
            staging_area=False, rse_type=None, latitude=None, longitude=None, ASN=None,
            availability=None):
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
    :param availability: Availability.
    """
    validate_schema(name='rse', obj=rse)
    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, vo=vo, action='add_rse', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add RSE' % (issuer))

    return rse_module.add_rse(rse, vo=vo, deterministic=deterministic, volatile=volatile, city=city,
                              region_code=region_code, country_name=country_name, staging_area=staging_area,
                              continent=continent, time_zone=time_zone, ISP=ISP, rse_type=rse_type, latitude=latitude,
                              longitude=longitude, ASN=ASN, availability=availability)


def get_rse(rse, vo='def'):
    """
    Provides details about the specified RSE.

    :param rse: The RSE name.
    :param vo: The VO to act on.

    :returns: a dict with details about the RSE

    :raises RSENotFound: if the referred RSE was not found in the database
    """

    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    return rse_module.get_rse_protocols(rse_id=rse_id)


def del_rse(rse, issuer, vo='def'):
    """
    Disables an RSE with the provided RSE name.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)

    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_rse', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete RSE' % (issuer))

    return rse_module.del_rse(rse_id)


def list_rses(filters={}, vo='def'):
    """
    Lists all RSEs.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param vo: The VO to act on.

    :returns: List of all RSEs.
    """
    if not filters:
        filters = {}

    filters['vo'] = vo

    return rse_module.list_rses(filters=filters)


def del_rse_attribute(rse, key, issuer, vo='def'):
    """
    Delete a RSE attribute.

    :param rse: the name of the rse_module.
    :param key: the attribute key.
    :param vo: The VO to act on.

    :return: True if RSE attribute was deleted successfully, False otherwise.
    """

    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)

    kwargs = {'rse': rse, 'rse_id': rse_id, 'key': key}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_rse_attribute', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete RSE attributes' % (issuer))

    return rse_module.del_rse_attribute(rse_id=rse_id, key=key)


def add_rse_attribute(rse, key, value, issuer, vo='def'):
    """ Adds a RSE attribute.

    :param rse: the rse name.
    :param key: the key name.
    :param value: the value name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    returns: True if successful, False otherwise.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)

    kwargs = {'rse': rse, 'rse_id': rse_id, 'key': key, 'value': value}
    if not permission.has_permission(issuer=issuer, vo=vo, action='add_rse_attribute', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add RSE attributes' % (issuer))

    return rse_module.add_rse_attribute(rse_id=rse_id, key=key, value=value)


def list_rse_attributes(rse, vo='def'):
    """
    List RSE attributes for a RSE_MODULE.

    :param rse: The RSE name.
    :param vo: The VO to act on.

    :returns: List of all RSE attributes for a RSE_MODULE.
    """

    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    return rse_module.list_rse_attributes(rse_id=rse_id)


def has_rse_attribute(rse_id, key):
    """
    Indicates whether the named key is present for the RSE.

    :param rse_id: The RSE id.
    :param key: The key for the attribute.

    :returns: True or False
    """
    return rse_module.has_rse_attribute(rse_id=rse_id, key=key)


def get_rses_with_attribute(key):
    """
    Return all RSEs with a certain attribute.

    :param key: The key for the attribute.

    :returns: List of rse dictionaries
    """
    return rse_module.get_rses_with_attribute(key=key)


def add_protocol(rse, issuer, vo='def', **data):
    """
    Creates a new protocol entry for an existing RSE.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param data: Parameters (protocol identifier, port, hostname, ...) provided by the request.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)

    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='add_protocol', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add protocols to RSE %s' % (issuer, rse))
    rse_module.add_protocol(rse_id, data['data'])


def get_rse_protocols(rse, issuer, vo='def'):
    """
    Returns all matching protocols (including detailed information) for the given RSE.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: A dict with all supported protocols and their attibutes.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    return rse_module.get_rse_protocols(rse_id)


def del_protocols(rse, scheme, issuer, vo='def', hostname=None, port=None):
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
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_protocol', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete protocols from RSE %s' % (issuer, rse))
    rse_module.del_protocols(rse_id=rse_id, scheme=scheme, hostname=hostname, port=port)


def update_protocols(rse, scheme, data, issuer, vo='def', hostname=None, port=None):
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
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='update_protocol', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update protocols from RSE %s' % (issuer, rse))
    rse_module.update_protocols(rse_id=rse_id, scheme=scheme, hostname=hostname, port=port, data=data)


def set_rse_usage(rse, source, used, free, issuer, vo='def'):
    """
    Set RSE usage information.

    :param rse: The RSE name.
    :param source: the information source, e.g. srm.
    :param used: the used space in bytes.
    :param free: the free space in bytes.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: List of RSE usage data.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)

    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='set_rse_usage', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update RSE usage information for RSE %s' % (issuer, rse))

    return rse_module.set_rse_usage(rse_id=rse_id, source=source, used=used, free=free)


def get_rse_usage(rse, issuer, source=None, per_account=False, vo='def'):
    """
    get RSE usage information.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param source: dictionary of attributes by which the results should be filtered
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    usages = rse_module.get_rse_usage(rse_id=rse_id, source=source, per_account=per_account)

    for u in usages:
        if 'account_usages' in u:
            for account_usage in u['account_usages']:
                account_usage['account'] = account_usage['account'].external
    return [api_update_return_dict(u) for u in usages]


def list_rse_usage_history(rse, issuer, source=None, vo='def'):
    """
    List RSE usage history information.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param source: The source of the usage information (srm, rucio).
    :param vo: The VO to act on.

    :returns: A list of historic RSE usage.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    for u in rse_module.list_rse_usage_history(rse_id=rse_id, source=source):
        yield api_update_return_dict(u)


def set_rse_limits(rse, name, value, issuer, vo='def'):
    """
    Set RSE limits.

    :param rse: The RSE name.
    :param name: The name of the limit.
    :param value: The feature value. Set to -1 to remove the limit.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='set_rse_limits', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update RSE limits for RSE %s' % (issuer, rse))

    return rse_module.set_rse_limits(rse_id=rse_id, name=name, value=value)


def get_rse_limits(rse, issuer, vo='def'):
    """
    Get RSE limits.

    :param rse: The RSE name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, otherwise false.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    return rse_module.get_rse_limits(rse_id=rse_id)


def parse_rse_expression(rse_expression, vo='def'):
    """
    Parse an RSE expression and return the list of RSEs.

    :param rse_expression:  The RSE expression.
    :param vo: The VO to act on.

    :returns:  List of RSEs
    :raises:   InvalidRSEExpression
    """
    rses = parse_expression(rse_expression, filter={'vo': vo})
    return [rse['rse'] for rse in rses]


def update_rse(rse, parameters, issuer, vo='def'):
    """
    Update RSE properties like availability or name.

    :param rse: the name of the new rse.
    :param parameters: A dictionnary with property (name, read, write, delete as keys).
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :raises RSENotFound: If RSE is not found.
    """
    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    kwargs = {'rse': rse, 'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='update_rse', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update RSE' % (issuer))
    return rse_module.update_rse(rse_id=rse_id, parameters=parameters)


def add_distance(source, destination, issuer, vo='def', ranking=None, distance=None,
                 geoip_distance=None, active=None, submitted=None, finished=None,
                 failed=None, transfer_speed=None):
    """
    Add a src-dest distance.

    :param source: The source.
    :param destination: The destination.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param ranking: Ranking as an integer.
    :param distance: Distance as an integer.
    :param geoip_distance: GEOIP Distance as an integer.
    :param active: Active FTS transfers as an integer.
    :param submitted: Submitted FTS transfers as an integer.
    :param finished: Finished FTS transfers as an integer.
    :param failed: Failed FTS transfers as an integer.
    :param transfer_speed: FTS transfer speed as an integer.
    """
    kwargs = {'source': source, 'destination': destination}
    if not permission.has_permission(issuer=issuer, vo=vo, action='add_distance', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add RSE distances' % (issuer))
    return distance_module.add_distance(src_rse_id=rse_module.get_rse_id(source, vo=vo),
                                        dest_rse_id=rse_module.get_rse_id(destination, vo=vo),
                                        ranking=ranking, agis_distance=distance,
                                        geoip_distance=geoip_distance, active=active,
                                        submitted=submitted, finished=finished,
                                        failed=failed, transfer_speed=transfer_speed)


def update_distance(source, destination, parameters, issuer, vo='def'):
    """
    Update distances with the given RSE ids.

    :param source: The source RSE.
    :param destination: The destination RSE.
    :param  parameters: A dictionnary with property
    :param session: The database session to use.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'source': source, 'destination': destination}
    if not permission.has_permission(issuer=issuer, vo=vo, action='update_distance', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update RSE distances' % (issuer))
    if 'distance' in parameters:
        parameters['agis_distance'] = parameters['distance']
        parameters.pop('distance', None)

    return distance_module.update_distances(src_rse_id=rse_module.get_rse_id(source, vo=vo),
                                            dest_rse_id=rse_module.get_rse_id(destination, vo=vo),
                                            parameters=parameters)


def get_distance(source, destination, issuer, vo='def'):
    """
    Get distances between rses.

    :param source: The source RSE.
    :param destination: The destination RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns distance: List of dictionaries.
    """
    distances = distance_module.get_distances(src_rse_id=rse_module.get_rse_id(source, vo=vo),
                                              dest_rse_id=rse_module.get_rse_id(destination, vo=vo))

    return [api_update_return_dict(d) for d in distances]


def add_qos_policy(rse, qos_policy, issuer, vo='def'):
    """
    Add a QoS policy from an RSE.

    :param rse: The name of the RSE.
    :param qos_policy: The QoS policy to add.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :raises Duplicate: If the QoS policy already exists.
    :returns: True if successful, except otherwise.
    """

    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    kwargs = {'rse_id': rse_id}
    if not permission.has_permission(issuer=issuer, action='add_qos_policy', kwargs=kwargs):
        raise exception.AccessDenied('Account %s cannot add QoS policies to RSE %s' % (issuer, rse))

    return rse_module.add_qos_policy(rse_id, qos_policy)


def delete_qos_policy(rse, qos_policy, issuer, vo='def'):
    """
    Delete a QoS policy from an RSE.

    :param rse: The name of the RSE.
    :param qos_policy: The QoS policy to delete.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: True if successful, silent failure if QoS policy does not exist.
    """

    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    kwargs = {'rse_id': rse}
    if not permission.has_permission(issuer=issuer, action='delete_qos_policy', kwargs=kwargs):
        raise exception.AccessDenied('Account %s cannot delete QoS policies from RSE %s' % (issuer, rse))

    return rse_module.delete_qos_policy(rse_id, qos_policy)


def list_qos_policies(rse, issuer, vo='def'):
    """
    List all QoS policies of an RSE.

    :param rse: The id of the RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    :returns: List containing all QoS policies.
    """

    rse_id = rse_module.get_rse_id(rse=rse, vo=vo)
    return rse_module.list_qos_policies(rse_id)
