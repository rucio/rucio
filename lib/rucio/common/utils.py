# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

"""
Rucio utilities.
"""

from urllib import urlencode
from uuid import uuid4 as uuid
try:
    # Hack for the client distribution
    from web import HTTPError
except:
    pass


# HTTP code dictionary. Not complete. Can be extended if needed.
codes = {
    # Informational.
    200: '200 OK',
    201: '201 Created',
    202: '202 Accepted',

    # Client Error.
    400: '400 Bad Request',
    401: '401 Unauthorized',
    403: '403 Forbidden',
    404: '404 Not Found',
    405: '405 Method Not Allowed',
    408: '408 Request Timeout',
    409: '409 Conflict',
    410: '410 Gone',

    # Server Error.
    500: '500 Internal Server Error',
    501: '501 Not Implemented',
    502: '502 Bad Gateway',
    503: '503 Service Unavailable',
    504: '504 Gateway Timeout'
}


def build_url(url, path=None, params=None):
    """
    utitily function to build an url for requests to the rucio system.
    """
    complete_url = url

    complete_url += "/"
    if path is not None:
        complete_url += path
    if params is not None:
        complete_url += "?"
        complete_url += urlencode(params)
    return complete_url


def generate_uuid():
    return str(uuid()).replace('-', '').lower()


def generate_uuid_bytes():
    return uuid().bytes


def generate_http_error(status_code, exc_cls, exc_msg):
    """
    utitily function to generate a complete HTTP error response.
    :param status_code: The HTTP status code to generate a response for.
    :param exc_cls: The name of the exception class to send with the response.
    :param exc_msg: The error message.
    :returns: a web.py HTTP response object.
    """

    status = codes[status_code]
    headers = {'Content-Type': 'text/html', 'ExceptionClass': exc_cls, 'ExceptionMessage': exc_msg}
    data = ': '.join([exc_cls, exc_msg])

    return HTTPError(status, headers=headers, data=data)
