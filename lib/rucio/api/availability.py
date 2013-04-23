# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2011
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011


def is_service_available(service_id):
    """
    Checks If a service is available.

    :param service_id: The service identifier.

    :returns: True if the service is available, otherwise False
    """
    raise NotImplementedError


def add_service_downtime(service_id, start_date=None, end_date=None, author=None, comment=None):
    """
    Schedules downtime for a specified service.

    :param service_id: The service identifier.
    :param start_date: The downtime start time.
    :param end_date: The downtime end time.
    :param contact: Service/shifter who manages the downtime.
    :param comment: Comment describing the reason of the service downtime.

    :returns: downtime_id
    """
    raise NotImplementedError


def delete_service_downtime(service_id, downtime_id):
    """
    Deletes a service downtime.

    :param service_id: The service identifier.
    :param downtime_id: The downtime identifier.

    :raises exception.NotFound if service_id/downtime_id is not found

    :returns: True if the service is available, otherwise False
    """
    raise NotImplementedError


def get_service_downtimes(service_id):
    """
    Returns a list of service downtimes for a service.

    :param service_id: The service identifier.

    :raises exception.NotFound if service_id is not found

    :retval Tuple containing (downtime_id,  start_date, end_date, author, comment)
    """
    raise NotImplementedError
