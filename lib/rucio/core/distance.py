# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015


from sqlalchemy.exc import DatabaseError, IntegrityError

from rucio.common import exception
from rucio.db.sqla.models import Distance
from rucio.db.sqla.session import transactional_session, read_session


@transactional_session
def add_distance(src_rse_id, dest_rse_id, ranking=None, agis_distance=None, geoip_distance=None, session=None):
    """
    Add a src-dest distance.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param ranking: Ranking as an integer.
    :param agis_distance: AGIS Distance as an integer.
    :param geoip_distance: GEOIP Distance as an integer.
    :param session: The database session to use.
    """

    try:
        new_distance = Distance(src_rse_id=src_rse_id, dest_rse_id=dest_rse_id, ranking=ranking, agis_distance=agis_distance, geoip_distance=geoip_distance)
        new_distance.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('Distance from %s to %s already exists!' % (src_rse_id, dest_rse_id))
    except DatabaseError, e:
        raise exception.RucioException(e.args)


@read_session
def get_distances(src_rse_id=None, dest_rse_id=None, session=None):
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
                t2.pop('_sa_instance_state')
                distances.append(t2)
        return distances
    except IntegrityError, e:
        raise exception.RucioException(e.args)


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
    except IntegrityError, e:
        raise exception.RucioException(e.args)


@transactional_session
def update_distances(src_rse_id=None, dest_rse_id=None, ranking=None, agis_distance=None, geoip_distance=None, session=None):
    """
    Update distances with the given RSE ids.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param ranking: Ranking as an integer.
    :param agis_distance: AGIS Distance as an integer.
    :param geoip_distance: GEOIP Distance as an integer.
    :param session: The database session to use.
    """

    try:
        distance = {'ranking': ranking, 'agis_distance': agis_distance, 'geoip_distance': geoip_distance}

        query = session.query(Distance)

        if src_rse_id:
            query = query.filter(Distance.src_rse_id == src_rse_id)
        if dest_rse_id:
            query = query.filter(Distance.dest_rse_id == dest_rse_id)

        query.update(distance)
    except IntegrityError, e:
        raise exception.RucioException(e.args)
