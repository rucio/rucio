"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2017
 - Martin Barisits, <martin.barisits@cern.ch>, 2017
"""

import datetime
import errno
import json
import os
import pwd
import re
import subprocess
import zlib


from getpass import getuser
from itertools import izip_longest
from logging import getLogger, Formatter
from logging.handlers import RotatingFileHandler
from urllib import urlencode, quote
from uuid import uuid4 as uuid

from rucio.common.config import config_get

try:
    # Hack for the client distribution
    from web import HTTPError
    from rucio.db.sqla.enum import EnumSymbol
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


def build_url(url, path=None, params=None, doseq=False):
    """
    utitily function to build an url for requests to the rucio system.

    If the optional parameter doseq is evaluates to True, individual key=value pairs
    separated by '&' are generated for each element of the value sequence for the key.
    """
    complete_url = url
    complete_url += "/"
    if path is not None:
        complete_url += path
    if params is not None:
        complete_url += "?"
        if isinstance(params, str):
            complete_url += quote(params)
        else:
            complete_url += urlencode(params, doseq=doseq)
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


def adler32(file):
    """
    An Adler-32 checksum is obtained by calculating two 16-bit checksums A and B and concatenating their bits into a 32-bit integer. A is the sum of all bytes in the stream plus one, and B is the sum of the individual values of A from each step.

    :returns: Hexified string, padded to 8 values.
    """

    # adler starting value is _not_ 0
    adler = 1L

    try:
        openFile = open(file, 'rb')
        for line in openFile:
            adler = zlib.adler32(line, adler)
    except:
        raise Exception('FATAL - could not get checksum of file %s' % file)

    # backflip on 32bit
    if adler < 0:
        adler = adler + 2 ** 32

    return str('%08x' % adler)


def str_to_date(string):
    """ Converts a RFC-1123 string to the corresponding datetime value.

    :param string: the RFC-1123 string to convert to datetime value.
    """
    return datetime.datetime.strptime(string, DATE_FORMAT) if string else None


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


def generate_http_error(status_code, exc_cls, exc_msg):
    """
    utitily function to generate a complete HTTP error response.
    :param status_code: The HTTP status code to generate a response for.
    :param exc_cls: The name of the exception class to send with the response.
    :param exc_msg: The error message.
    :returns: a web.py HTTP response object.
    """

    status = codes[status_code]
    data = {'ExceptionClass': exc_cls,
            'ExceptionMessage': exc_msg}
    # Truncate too long exc_msg
    if len(str(exc_msg)) > 15000:
        exc_msg = str(exc_msg)[:15000]
    headers = {'Content-Type': 'application/octet-stream',
               'ExceptionClass': exc_cls,
               'ExceptionMessage': clean_headers(exc_msg)}
    try:
        return HTTPError(status, headers=headers, data=render_json(**data))
    except:
        print {'Content-Type': 'application/octet-stream', 'ExceptionClass': exc_cls, 'ExceptionMessage': str(exc_msg).strip()}
        raise


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


def chunks(l, n):
    """
    Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i + n]


def my_key_generator(namespace, fn, **kw):
    """
    Customyzed key generator for dogpile
    """
    fname = fn.__name__

    def generate_key(*arg, **kw):
        return namespace + "_" + fname + "_".join(str(s) for s in filter(None, arg))

    return generate_key


def get_logger(name):
    logger = getLogger(name)
    hdlr = RotatingFileHandler('%s/%s.log' % (config_get('common', 'logdir'), name), maxBytes=1000000000, backupCount=10)
    formatter = Formatter('%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(config_get('common', 'loglevel').upper())
    return logger


def construct_surl_DQ2(dsn, filename):
    """
    Defines relative SURL for new replicas. This method
    contains DQ2 convention. To be used for non-deterministic sites.
    Method imported from DQ2.

    @return: relative SURL for new replica.
    @rtype: str
    """
    # check how many dots in dsn
    fields = dsn.split('.')
    nfields = len(fields)

    if nfields == 0:
        return '/other/other/%s' % (filename)
    elif nfields == 1:
        stripped_dsn = __strip_dsn(dsn)
        return '/other/%s/%s' % (stripped_dsn, filename)
    elif nfields == 2:
        project = fields[0]
        stripped_dsn = __strip_dsn(dsn)
        return '/%s/%s/%s' % (project, stripped_dsn, filename)
    elif nfields < 5 or re.match('user*|group*', fields[0]):
        project = fields[0]
        f2 = fields[1]
        f3 = fields[2]
        stripped_dsn = __strip_dsn(dsn)
        return '/%s/%s/%s/%s/%s' % (project, f2, f3, stripped_dsn, filename)
    else:
        project = fields[0]
        dataset_type = fields[4]
        if nfields == 5:
            tag = 'other'
        else:
            tag = __strip_tag(fields[-1])
        stripped_dsn = __strip_dsn(dsn)
        return '/%s/%s/%s/%s/%s' % (project, dataset_type, tag, stripped_dsn, filename)


def construct_surl_T0(dsn, filename):
    """
    Defines relative SURL for new replicas. This method
    contains Tier0 convention. To be used for non-deterministic sites.

    @return: relative SURL for new replica.
    @rtype: str
    """
    fields = dsn.split('.')
    nfields = len(fields)
    if nfields >= 3:
        return '/%s/%s/%s/%s/%s' % (fields[0], fields[2], fields[1], dsn, filename)
    elif nfields == 1:
        return '/%s/%s/%s/%s/%s' % (fields[0], 'other', 'other', dsn, filename)
    elif nfields == 2:
        return '/%s/%s/%s/%s/%s' % (fields[0], fields[2], 'other', dsn, filename)
    elif nfields == 0:
        return '/other/other/other/other/%s' % (filename)


def construct_surl(dsn, filename, naming_convention=None):
    if naming_convention == 'T0':
        return construct_surl_T0(dsn, filename)
    elif naming_convention == 'DQ2':
        return construct_surl_DQ2(dsn, filename)
    return construct_surl_DQ2(dsn, filename)


def __strip_dsn(dsn):
    """
    Drop the _sub and _dis suffixes for panda datasets from the lfc path
    they will be registered in.
    Method imported from DQ2.
    """

    suffixes_to_drop = ['_dis', '_sub', '_frag']
    fields = dsn.split('.')
    last_field = fields[-1]
    try:
        for suffix in suffixes_to_drop:
            last_field = re.sub('%s.*$' % suffix, '', last_field)
    except IndexError:
        return dsn
    fields[-1] = last_field
    stripped_dsn = '.'.join(fields)
    return stripped_dsn


def __strip_tag(tag):
    """
    Drop the _sub and _dis suffixes for panda datasets from the lfc path
    they will be registered in
    Method imported from DQ2.
    """
    suffixes_to_drop = ['_dis', '_sub', '_tid']
    stripped_tag = tag
    try:
        for suffix in suffixes_to_drop:
            stripped_tag = re.sub('%s.*$' % suffix, '', stripped_tag)
    except IndexError:
        return stripped_tag
    return stripped_tag


def clean_surls(surls):
    res = []
    for surl in surls:
        if surl.startswith('srm'):
            surl = re.sub(':[0-9]+/', '/', surl)
            surl = re.sub('/srm/managerv1\?SFN=', '', surl)
            surl = re.sub('/srm/v2/server\?SFN=', '', surl)
            surl = re.sub('/srm/managerv2\?SFN=', '', surl)
        res.append(surl)
    res.sort()
    return res


def pid_exists(pid):
    """
    Check whether pid exists in the current process table.
    UNIX only.
    """
    if pid < 0:
        return False
    if pid == 0:
        # According to "man 2 kill" PID 0 refers to every process
        # in the process group of the calling process.
        # On certain systems 0 is a valid PID but we have no way
        # to know that in a portable fashion.
        raise ValueError('invalid PID 0')
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH == No such process
            return False
        elif err.errno == errno.EPERM:
            # EPERM clearly means there's a process to deny access to
            return True
        else:
            # According to "man 2 kill" possible error values are
            # (EINVAL, EPERM, ESRCH)
            raise
    else:
        return True


def sizefmt(num, human=True):
    """
    Print human readable file sizes
    """
    if num is None:
        return '0.0 B'
    try:
        num = int(num)
        if human:
            for unit in ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z']:
                if abs(num) < 1000.0:
                    return "%3.3f %sB" % (num, unit)
                num /= 1000.0
            return "%.1f %sB" % (num, 'Y')
        else:
            return str(num)
    except OverflowError:
        return 'Inf'


def get_tmp_dir():
    """
    Get a path where to store temporary files.

    Rucio searches a standard list of temporary directories. The list is:

        The directory named by the TMP environment variable.
        The directory named by the TMPDIR environment variable.
        The directory named by the TEMP environment variable.

        As a last resort, the /tmp/ directory.

    :return: A path.
    """
    user, tmp_dir = None, None
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except:
        pass

    for env_var in ('TMP', 'TMPDIR', 'TEMP'):
        if env_var in os.environ:
            tmp_dir = os.environ[env_var]
            break

    if not user:
        user = getuser()

    if not tmp_dir:
        return '/tmp/' + user + '/'

    return tmp_dir + '/' + user + '/'


def is_archive(name):
    '''
    Check if a file name is an archive file or not.

    :return: A boolean.
    '''
    regexp = '^.*\.(zip|zipx|tar.gz|tgz|tar.Z|tar.bz2|tbz2)(\.\d+)*$'
    if re.match(regexp, name, re.I):
        return True
    return False


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
