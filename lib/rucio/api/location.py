# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from rucio.core import location as location_core


def add_location(location):
        """
        Creates a new Rucio Location.

        :param Location: The location name.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        return location_core.add_location(location)


def del_location(location):
        """
        Disables a location with the provided location name.

        :param location: The location name.
        """
        return location_core.del_location(location)


def list_locations():
        """
        Lists all the locations.


        :returns: List of all locations.
        """
        return location_core.list_locations()
