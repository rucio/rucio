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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from rucio.core import rse as rse_module, distance as distance_module
from rucio.db.sqla.session import transactional_session


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
        for rse in rses:
            protocols = rse.get('protocols')
            if protocols:
                protocols = protocols.get('protocols')
                del rse['protocols']
            rse_name = rse['rse']
            del rse['rse']
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
            if protocols:
                old_protocols = rse_module.get_rse_protocols(rse=rse_name, session=session)
                for protocol in protocols:
                    scheme = protocol.get('scheme')
                    hostname = protocol.get('hostname')
                    port = protocol.get('port')
                    intersection = [old_protocol for old_protocol in old_protocols['protocols'] if old_protocol['scheme'] == scheme and old_protocol['hostname'] == hostname and
                                    old_protocol['port'] == port]
                    if intersection:
                        del protocol['scheme']
                        del protocol['hostname']
                        del protocol['port']
                        rse_module.update_protocols(rse=rse_name, scheme=scheme, data=protocol, hostname=hostname, port=port, session=session)
                    else:
                        rse_module.add_protocol(rse=rse_name, parameter=protocol, session=session)

            # Limits
            limits = rse.get('limits')
            if limits:
                old_limits = rse_module.get_rse_limits(rse=rse_name, session=session)
                for limit in limits:
                    if limit in old_limits:
                        rse_module.delete_rse_limit(rse=rse_name, name=limit, session=session)
                    rse_module.set_rse_limits(rse=rse_name, name=limit, value=limits[limit], session=session)

            # Transfer limits
            transfer_limits = rse.get('transfer_limits')
            if transfer_limits:
                for limit in transfer_limits:
                    old_transfer_limits = rse_module.get_rse_transfer_limits(rse=rse_name, activity=limit, session=session)
                    if limit in old_transfer_limits:
                        rse_module.delete_rse_transfer_limits(rse=rse_name, activity=limit, session=session)
                    max_transfers = transfer_limits[limit].items()[0][1]['max_transfers']
                    rse_module.set_rse_transfer_limits(rse=rse_name, activity=limit, max_transfers=max_transfers, session=session)

            # Attributes
            attributes = rse.get('attributes')
            if attributes:
                old_attributes = rse_module.list_rse_attributes(rse=rse_name, session=session)
                for attr in attributes:
                    if attr in old_attributes:
                        rse_module.del_rse_attribute(rse=rse_name, key=attr, session=session)
                    rse_module.add_rse_attribute(rse=rse_name, key=attr, value=attributes[attr], session=session)

    # Distances
    distances = data.get('distances')
    if distances:
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
