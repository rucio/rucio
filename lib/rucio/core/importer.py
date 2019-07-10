# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from six import string_types
from rucio.common.exception import RSEOperationNotSupported
from rucio.core import rse as rse_module, distance as distance_module
from rucio.db.sqla.constants import RSEType
from rucio.db.sqla.session import transactional_session


@transactional_session
def import_rses(rses, session=None):
    new_rses = []
    for rse_name in rses:
        new_rses.append(rse_name)
        rse = rses[rse_name]
        if isinstance(rse.get('rse_type'), string_types):
            rse['rse_type'] = RSEType.from_string(str(rse['rse_type']))
        if not rse_module.rse_exists(rse_name, session=session):
            rse_module.add_rse(rse_name, deterministic=rse.get('deterministic'), volatile=rse.get('volatile'),
                               city=rse.get('city'), region_code=rse.get('region_code'), country_name=rse.get('country_name'),
                               staging_area=rse.get('staging_area'), continent=rse.get('continent'), time_zone=rse.get('time_zone'),
                               ISP=rse.get('ISP'), rse_type=rse.get('rse_type'), latitude=rse.get('latitude'),
                               longitude=rse.get('longitude'), ASN=rse.get('ASN'), availability=rse.get('availability'),
                               session=session)
        else:
            rse_module.update_rse(rse_name, rse, session=session)

        # Protocols
        new_protocols = rse.get('protocols')
        if new_protocols:
            # update existing, add missing and remove left over protocols
            old_protocols = [{'scheme': protocol['scheme'], 'hostname': protocol['hostname'], 'port': protocol['port']} for protocol in rse_module.get_rse_protocols(rse=rse_name, session=session)['protocols']]
            missing_protocols = [new_protocol for new_protocol in new_protocols if {'scheme': new_protocol['scheme'], 'hostname': new_protocol['hostname'], 'port': new_protocol['port']} not in old_protocols]
            outdated_protocols = [new_protocol for new_protocol in new_protocols if {'scheme': new_protocol['scheme'], 'hostname': new_protocol['hostname'], 'port': new_protocol['port']} in old_protocols]
            new_protocols = [{'scheme': protocol['scheme'], 'hostname': protocol['hostname'], 'port': protocol['port']} for protocol in new_protocols]
            to_be_removed_protocols = [old_protocol for old_protocol in old_protocols if old_protocol not in new_protocols]
            for protocol in outdated_protocols:
                scheme = protocol['scheme']
                port = protocol['port']
                hostname = protocol['hostname']
                del protocol['scheme']
                del protocol['hostname']
                del protocol['port']
                rse_module.update_protocols(rse=rse_name, scheme=scheme, data=protocol, hostname=hostname, port=port, session=session)

            for protocol in missing_protocols:
                rse_module.add_protocol(rse=rse_name, parameter=protocol, session=session)

            for protocol in to_be_removed_protocols:
                scheme = protocol['scheme']
                port = protocol['port']
                hostname = protocol['hostname']
                rse_module.del_protocols(rse=rse_name, scheme=scheme, port=port, hostname=hostname, session=session)

        # Limits
        old_limits = rse_module.get_rse_limits(rse=rse_name, session=session)
        for limit_name in ['MaxBeingDeletedFiles', 'MinFreeSpace']:
            limit = rse.get(limit_name)
            if limit:
                if limit_name in old_limits:
                    rse_module.delete_rse_limit(rse=rse_name, name=limit_name, session=session)
                rse_module.set_rse_limits(rse=rse_name, name=limit_name, value=limit, session=session)

        # Attributes
        attributes = rse.get('attributes', {})
        attributes['lfn2pfn_algorithm'] = rse.get('lfn2pfn_algorithm')
        attributes['verify_checksum'] = rse.get('verify_checksum')

        old_attributes = rse_module.list_rse_attributes(rse=rse_name, session=session)
        for attr in attributes:
            value = attributes[attr]
            if value is not None:
                if attr in old_attributes:
                    rse_module.del_rse_attribute(rse=rse_name, key=attr, session=session)
                rse_module.add_rse_attribute(rse=rse_name, key=attr, value=value, session=session)

    # set deleted flag to RSEs that are missing in the import data
    old_rses = [old_rse['rse'] for old_rse in rse_module.list_rses(session=session)]
    for old_rse in old_rses:
        if old_rse not in new_rses:
            try:
                rse_module.del_rse(rse=old_rse, session=session)
            except RSEOperationNotSupported:
                pass


@transactional_session
def import_distances(distances, session=None):
    for src_rse_name in distances:
        src = rse_module.get_rse_id(src_rse_name, session=session)
        for dest_rse_name in distances[src_rse_name]:
            dest = rse_module.get_rse_id(dest_rse_name, session=session)
            distance = distances[src_rse_name][dest_rse_name]
            del distance['src_rse_id']
            del distance['dest_rse_id']

            old_distance = distance_module.get_distances(src_rse_id=src, dest_rse_id=dest, session=session)
            if old_distance:
                distance_module.update_distances(src_rse_id=src, dest_rse_id=dest, parameters=distance, session=session)
            else:
                distance_module.add_distance(src_rse_id=src, dest_rse_id=dest, ranking=distance.get('ranking'),
                                             agis_distance=distance.get('agis_distance'), geoip_distance=distance.get('geoip_distance'),
                                             active=distance.get('active'), submitted=distance.get('submitted'),
                                             transfer_speed=distance.get('transfer_speed'), finished=distance.get('finished'),
                                             failed=distance.get('failed'), session=session)


@transactional_session
def import_data(data, session=None):
    """
    Import data to add and update records in Rucio.

    :param data: data to be imported as dictionary.
    :param session: database session in use.
    """
    # RSEs
    rses = data.get('rses')
    if rses:
        import_rses(rses, session=session)

    # Distances
    distances = data.get('distances')
    if distances:
        import_distances(distances, session=session)
