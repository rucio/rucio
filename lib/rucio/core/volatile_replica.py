"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
"""

from datetime import datetime

from sqlalchemy import and_, or_, exists
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import select

from rucio.common import exception
from rucio.db.sqla import models
from rucio.db.sqla.constants import ReplicaState
from rucio.db.sqla.session import transactional_session


@transactional_session
def add_volatile_replicas(rse, replicas, session=None):
    """
    Bulk add volatile replicas.

    :param rse: the rse name.
    :param replicas: the list of volatile replicas.
    :param session: The database session in use.
    :returns: True is successful.
    """
    # first check that the rse is a volatile one
    try:
        rse_id = session.query(models.RSE.id).filter_by(rse=rse, volatile=True).one()[0]
    except NoResultFound:
        raise exception.UnsupportedOperation('No volatile rse found for %(rse)s !' % locals())

    file_clause, replica_clause = [], []
    for replica in replicas:
        file_clause.append(and_(models.DataIdentifier.scope == replica['scope'],
                                models.DataIdentifier.name == replica['name'],
                                ~exists(select([1]).prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle')).where(and_(models.RSEFileAssociation.scope == replica['scope'],
                                                                                                                                    models.RSEFileAssociation.name == replica['name'],
                                                                                                                                    models.RSEFileAssociation.rse_id == rse_id))))
        replica_clause.append(and_(models.RSEFileAssociation.scope == replica['scope'],
                                   models.RSEFileAssociation.name == replica['name'],
                                   models.RSEFileAssociation.rse_id == rse_id))

    if replica_clause:
        now = datetime.utcnow()
        session.query(models.RSEFileAssociation).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            filter(or_(*replica_clause)).\
            update({'updated_at': now, 'tombstone': now}, synchronize_session=False)

    if file_clause:
        file_query = session.query(models.DataIdentifier.scope,
                                   models.DataIdentifier.name,
                                   models.DataIdentifier.bytes,
                                   models.DataIdentifier.md5,
                                   models.DataIdentifier.adler32).\
            filter(or_(*file_clause))

        session.bulk_insert_mappings(
            models.RSEFileAssociation,
            [{'rse_id': rse_id, 'adler32': adler32, 'state': ReplicaState.AVAILABLE,
              'scope': scope, 'name': name, 'lock_cnt': 0, 'tombstone': datetime.utcnow(),
              'bytes': bytes, 'md5': md5} for scope, name, bytes, md5, adler32 in file_query])


@transactional_session
def delete_volatile_replicas(rse, replicas, session=None):
    """
    Bulk delete volatile replicas.

    :param rse: the rse name.
    :param replicas: the list of volatile replicas.
    :param session: The database session in use.
    :returns: True is successful.
    """
    # first check that the rse is a volatile one
    try:
        rse_id = session.query(models.RSE.id).filter_by(rse=rse, volatile=True).one()[0]
    except NoResultFound:
        raise exception.UnsupportedOperation('No volatile rse found for %(rse)s !' % locals())

    conditions = []
    for replica in replicas:
        conditions.append(and_(models.RSEFileAssociation.scope == replica['scope'],
                               models.RSEFileAssociation.name == replica['name']))

    if conditions:
        session.query(models.RSEFileAssociation).\
            filter(models.RSEFileAssociation.rse_id == rse_id).\
            filter(or_(*conditions)).\
            delete(synchronize_session=False)
