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

from typing import TYPE_CHECKING

from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm import aliased

from rucio.common import exception
from rucio.db.sqla.models import Distance, RSE
from rucio.db.sqla.session import transactional_session, read_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_distance(src_rse_id, dest_rse_id, distance=None, *, session: "Session"):
    """
    Add a src-dest distance.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param distance: Distance as an integer.
    :param session: The database session to use.
    """

    try:
        new_distance = Distance(src_rse_id=src_rse_id, dest_rse_id=dest_rse_id, distance=distance)
        new_distance.save(session=session)
    except IntegrityError:
        raise exception.Duplicate()
    except DatabaseError as error:
        raise exception.RucioException(error.args)


@read_session
def get_distances(src_rse_id=None, dest_rse_id=None, *, session: "Session") -> list[dict]:
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
                t2 = t.to_dict()
                t2['ranking'] = t2['distance']  # Compatibility with old clients
                distances.append(t2)
        return distances
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@transactional_session
def delete_distances(src_rse_id=None, dest_rse_id=None, *, session: "Session"):
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
def update_distances(src_rse_id=None, dest_rse_id=None, distance=None, *, session: "Session"):
    """
    Update distances with the given RSE ids.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param distance: The new distance to set
    :param session: The database session to use.
    """
    try:
        query = session.query(Distance)
        if src_rse_id:
            query = query.filter(Distance.src_rse_id == src_rse_id)
        if dest_rse_id:
            query = query.filter(Distance.dest_rse_id == dest_rse_id)
        query.update({Distance.distance: distance})
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@read_session
def list_distances(filter_={}, *, session: "Session"):
    """
    Get distances between all the RSEs.

    :param filter_: dictionary to filter distances.
    :param session: The database session in use.
    """
    return [distance.to_dict() for distance in session.query(Distance).all()]


@read_session
def export_distances(vo='def', *, session: "Session"):
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
            distance = distance.to_dict()
            distance['ranking'] = distance['distance']  # Compatibility with old clients
            distances[src_id][dst_id] = distance
        return distances
    except IntegrityError as error:
        raise exception.RucioException(error.args)
