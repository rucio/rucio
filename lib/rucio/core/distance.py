# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2015-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from typing import TYPE_CHECKING

from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm import aliased

from rucio.common import exception
from rucio.db.sqla.models import Distance, RSE
from rucio.db.sqla.session import transactional_session, read_session

if TYPE_CHECKING:
    from typing import List, Dict


@transactional_session
def add_distance(src_rse_id, dest_rse_id, ranking=None, agis_distance=None, geoip_distance=None,
                 active=None, submitted=None, finished=None, failed=None, transfer_speed=None, session=None):
    """
    Add a src-dest distance.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param ranking: Ranking as an integer.
    :param agis_distance: AGIS Distance as an integer.
    :param geoip_distance: GEOIP Distance as an integer.
    :param active: Active FTS transfers as an integer.
    :param submitted: Submitted FTS transfers as an integer.
    :param finished: Finished FTS transfers as an integer.
    :param failed: Failed FTS transfers as an integer.
    :param transfer_speed: FTS transfer speed as an integer.
    :param session: The database session to use.
    """

    try:
        new_distance = Distance(src_rse_id=src_rse_id, dest_rse_id=dest_rse_id, ranking=ranking, agis_distance=agis_distance, geoip_distance=geoip_distance,
                                active=active, submitted=submitted, finished=finished, failed=failed, transfer_speed=transfer_speed)
        new_distance.save(session=session)
    except IntegrityError:
        raise exception.Duplicate()
    except DatabaseError as error:
        raise exception.RucioException(error.args)


@transactional_session
def add_distance_short(src_rse_id, dest_rse_id, distance=None, session=None):
    """
    Add a src-dest distance.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param distance: A dictionary with different values.
    """

    add_distance(src_rse_id, dest_rse_id, ranking=distance.get('ranking', None), agis_distance=distance.get('agis_distance', None),
                 geoip_distance=distance.get('geoip_distance', None), active=distance.get('active', None), submitted=distance.get('submitted', None),
                 finished=distance.get('finished', None), failed=distance.get('failed', None), transfer_speed=distance.get('transfer_speed', None),
                 session=session)


@read_session
def get_distances(src_rse_id=None, dest_rse_id=None, session=None) -> "List[Dict]":
    """
    Get distances between rses.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param session: The database session to use.

    :returns distance: List of dictionaries.
    """

    try:
        query = session.query(Distance)
        if src_rse_id:
            query = query.filter(Distance.src_rse_id == src_rse_id)
        if dest_rse_id:
            query = query.filter(Distance.dest_rse_id == dest_rse_id)

        distances = []
        tmp = query.all()
        if tmp:
            for t in tmp:
                t2 = dict(t)
                t2['distance'] = t2['agis_distance']
                t2.pop('_sa_instance_state')
                distances.append(t2)
        return distances
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@transactional_session
def delete_distances(src_rse_id=None, dest_rse_id=None, session=None):
    """
    Delete distances with the given RSE ids.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param session: The database session to use.
    """

    try:
        query = session.query(Distance)

        if src_rse_id:
            query = query.filter(Distance.src_rse_id == src_rse_id)
        if dest_rse_id:
            query = query.filter(Distance.dest_rse_id == dest_rse_id)

        query.delete()
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@transactional_session
def update_distances(src_rse_id=None, dest_rse_id=None, parameters=None, session=None):
    """
    Update distances with the given RSE ids.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param  parameters: A dictionnary with property
    :param session: The database session to use.
    """
    params = {}
    for key in parameters:
        if key in ['ranking', 'agis_distance', 'geoip_distance', 'active', 'submitted', 'finished', 'failed', 'transfer_speed', 'packet_loss', 'latency', 'mbps_file', 'mbps_link', 'queued_total', 'done_1h', 'done_6h']:
            params[key] = parameters[key]
    try:
        query = session.query(Distance)
        if src_rse_id:
            query = query.filter(Distance.src_rse_id == src_rse_id)
        if dest_rse_id:
            query = query.filter(Distance.dest_rse_id == dest_rse_id)
        query.update(params)
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@read_session
def list_distances(filter={}, session=None):
    """
    Get distances between all the RSEs.

    :param filter: dictionary to filter distances.
    :param session: The database session in use.
    """
    return [distance.to_dict() for distance in session.query(Distance).all()]


@read_session
def export_distances(vo='def', session=None):
    """
    Export distances between all the RSEs using RSE ids.
    :param vo: The VO to export.
    :param session: The database session to use.
    :returns distance: dictionary of dictionaries with all the distances.
    """

    distances = {}
    try:
        rse_src = aliased(RSE)
        rse_dest = aliased(RSE)
        query = session.query(Distance, rse_src.id, rse_dest.id)\
                       .join(rse_src, rse_src.id == Distance.src_rse_id)\
                       .join(rse_dest, rse_dest.id == Distance.dest_rse_id)\
                       .filter(rse_src.vo == vo)\
                       .filter(rse_dest.vo == vo)
        for result in query.all():
            distance = result[0]
            src_id = result[1]
            dst_id = result[2]
            if src_id not in distances:
                distances[src_id] = {}
            distances[src_id][dst_id] = {}
            distance['distance'] = distance['agis_distance']
            distances[src_id][dst_id] = distance.to_dict()
            del distances[src_id][dst_id]['_sa_instance_state']
        return distances
    except IntegrityError as error:
        raise exception.RucioException(error.args)
