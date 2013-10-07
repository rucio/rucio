# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

"""
Rucio utilities.
"""

import datetime
import json
import re
import subprocess
import zlib

from itertools import izip_longest
from logging import getLogger, Formatter
from logging.handlers import RotatingFileHandler
from urllib import urlencode
from uuid import uuid4 as uuid

from rucio.common.config import config_get

try:
    # Hack for the client distribution
    from web import HTTPError
    from rucio.db.enum import EnumSymbol
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

# RFC 1123 (ex RFC 822)
DATE_FORMAT = '%a, %d %b %Y %H:%M:%S UTC'


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


def clean_headers(msg):
    invalid_characters = ['\n', '\r']
    for c in invalid_characters:
        msg = str(msg).replace(c, ' ')
    return msg


def generate_http_error(status_code, exc_cls, exc_msg):
    """
    utitily function to generate a complete HTTP error response.
    :param status_code: The HTTP status code to generate a response for.
    :param exc_cls: The name of the exception class to send with the response.
    :param exc_msg: The error message.
    :returns: a web.py HTTP response object.
    """

    status = codes[status_code]
    headers = {'Content-Type': 'application/octet-stream', 'ExceptionClass': exc_cls, 'ExceptionMessage': clean_headers(exc_msg)}
    data = ': '.join([exc_cls, str(exc_msg).strip()])

    try:
        return HTTPError(status, headers=headers, data=data)
    except:
        print {'Content-Type': 'application/octet-stream', 'ExceptionClass': exc_cls, 'ExceptionMessage': str(exc_msg).strip()}
        raise


def adler32(file):
    """
    An Adler-32 checksum is obtained by calculating two 16-bit checksums A and B and concatenating their bits into a 32-bit integer. A is the sum of all bytes in the stream plus one, and B is the sum of the individual values of A from each step.

    :returns: Hexified string, padded to 8 values.
    """

    #adler starting value is _not_ 0
    adler = 1L

    try:
        openFile = open(file, 'rb')
        for line in openFile:
            adler = zlib.adler32(line, adler)
    except:
        raise Exception('FATAL - could not get checksum of file %s' % file)

    #backflip on 32bit
    if adler < 0:
        adler = adler + 2 ** 32

    return str('%08x' % adler)


def str_to_date(string):
    """ Converts a RFC-1123 string to the corresponding datetime value.

    :param string: the RFC-1123 string to convert to datetime value.
    """
    return datetime.strptime(string, DATE_FORMAT) if string else None


def date_to_str(date):
    """ Converts a datetime value to the corresponding RFC-1123 string.

    :param date: the datetime value to convert.
    """
    return datetime.datetime.strftime(date, DATE_FORMAT) if date else None


class APIEncoder(json.JSONEncoder):
    """ Propretary JSONEconder subclass used by the json render function.
    This is needed to address the encoding of special values.
    """
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            # convert any datetime to RFC 1123 format
            return date_to_str(obj)
        elif isinstance(obj, (datetime.time, datetime.date)):
            # should not happen since the only supported date-like format
            # supported at dmain schema level is 'datetime' .
            return obj.isoformat()
        elif isinstance(obj, datetime.timedelta):
            return obj.days * 24 * 60 * 60 + obj.seconds
        elif isinstance(obj, EnumSymbol):
            return obj.description
        return json.JSONEncoder.default(self, obj)


def render_json(**data):
    """ JSON render function
    """
    return json.dumps(data, cls=APIEncoder)


def render_json_list(l):
    """ JSON render function for list
    """
    return json.dumps(l, cls=APIEncoder)


def datetime_parser(dct):
    """ datetime parser
    """
    for k, v in dct.items():
        if isinstance(v, basestring) and re.search(" UTC", v):
            try:
                dct[k] = datetime.datetime.strptime(v, DATE_FORMAT)
            except:
                pass
    return dct


def parse_response(data):
    """ JSON render function
    """
    return json.loads(data, object_hook=datetime_parser)


def execute(cmd):
    """
    Executes a command in a subprocess. Returns a tuple
    of (exitcode, out, err), where out is the string output
    from stdout and err is the string output from stderr when
    executing the command.

    :param cmd: Command string to execute
    """

    process = subprocess.Popen(cmd,
                               shell=True,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out = ''
    err = ''
    exitcode = 0

    result = process.communicate()
    (out, err) = result
    exitcode = process.returncode

    return exitcode, out, err


def rse_supported_protocol_operations():
    """ Returns a list with operations supported by all RSE protocols."""
    return ['read', 'write', 'delete']


def rse_supported_protocol_domains():
    """ Returns a list with all supoorted RSE protocol domains."""
    return ['lan', 'wan']


def grouper(iterable, n, fillvalue=None):
    """ Collect data into fixed-length chunks or blocks """
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return izip_longest(*args, fillvalue=fillvalue)


def get_logger(name):
    logger = getLogger(name)
    hdlr = RotatingFileHandler('%s/%s.log' % (config_get('common', 'logdir'), name), maxBytes=1000000000, backupCount=10)
    formatter = Formatter('%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(config_get('common', 'loglevel').upper())
    return logger
