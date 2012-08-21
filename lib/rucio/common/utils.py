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
from urlparse import urlparse
from uuid import uuid4 as uuid
try:
    # Hack for the client distribution
    from web import HTTPError
except:
    pass

from rucio.common.exception import ClientProtocolNotSupported

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


def build_url(host, port=None, path=None, params=None, use_ssl=True):
    """
    utitily function to build an url for requests to the rucio system.
    """

    parse = urlparse(host)
    if len(parse.scheme) == 0:
        host = parse.path
    else:
        host = parse.netloc

    if use_ssl:
        url = "https://"
    else:
        url = "http://"
    url += host
    if port is not None:
        url += ":" + str(port)
    url += "/"
    if path is not None:
        url += path
    if params is not None:
        url += "?"
        url += urlencode(params)
    return url


def check_url(url, use_ssl):
    """ utility function to check if scheme in url matches with the use_ssl switch"""
    scheme = urlparse(url).scheme

    if scheme == '':
        return True
    if scheme != 'http' and scheme != 'https':
        raise ClientProtocolNotSupported('\'%s\' not supported' % scheme)

    if scheme == 'http' and use_ssl is True:
        return False
    if scheme == 'https' and use_ssl is False:
        return False

    return True


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
