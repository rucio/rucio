# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from sqlalchemy import create_engine, update
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.db import models1 as models
from rucio.db.session import get_session

session = get_session()


def add_location(location):
    """ Add a location with the given location name.

    :param location: the name of the new location.
    """

    values = {}
    values['location'] = location
    new_location = models.Location()

    new_location.update(values)

    try:
        new_location.save(session=session)
    except IntegrityError, e:
        session.rollback()
        raise exception.Duplicate('Location \'%s\' already exists!' % values['location'])

    session.commit()


def location_exists(location):
    """ Checks to see if location exists. This procedure does not check its status.

    :param location: Name of the location.
    :returns: True if found, otherwise false.
    """

    return True if session.query(models.Location).filter_by(location=location).first() else False


def del_location(location):
    """ Disable a location with the given location name.

    :param location: the location name.
    """

    old_location = session.query(models.Location).filter_by(location=location).first()

    if location is None:
        raise exception.LocationNotFound('Location \'%s\' cannot be found' % location)

    old_location.delete(session)
    session.commit()


def list_locations():
    """ Returns a list of all location names.

    returns: a list of all location names.
    """

    location_list = []

    for location in session.query(models.Location).order_by(models.Location.location):
        location_list.append(location.location)

    return location_list
