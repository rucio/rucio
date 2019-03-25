# Copyright 2012-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2017
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2015-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2018
# - Frank Berghaus, <frank.berghaus@cern.ch>, 2017
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Tobias Wegner <twegner@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function

import base64
import datetime
import errno
import hashlib
import imp
import json
import os
import pwd
import re
import requests
import socket
import subprocess
import threading
import time
import zlib

from getpass import getuser
from logging import getLogger, Formatter
from logging.handlers import RotatingFileHandler
from uuid import uuid4 as uuid
from six import string_types
from xml.etree import ElementTree

from rucio.common.exception import InputValidationError, MetalinkJsonParsingError

try:
    # Python 2
    from itertools import izip_longest
except ImportError:
    # Python 3
    from itertools import zip_longest as izip_longest
try:
    # Python 2
    from urllib import urlencode, quote
except ImportError:
    # Python 3
    from urllib.parse import urlencode, quote
try:
    # Python 2
    from StringIO import StringIO
except ImportError:
    # Python 3
    from io import StringIO
try:
    # Python 2
    import urlparse
except ImportError:
    # Python 3
    import urllib.parse as urlparse

from rucio.common.config import config_get
from rucio.common.exception import MissingModuleException, InvalidType

# Extra modules: Only imported if available
EXTRA_MODULES = {'web': False,
                 'paramiko': False,
                 'flask': False}

try:
    from rucio.db.sqla.enum import EnumSymbol
    EXTRA_MODULES['rucio.db.sqla.enum'] = True
except ImportError:
    EXTRA_MODULES['rucio.db.sqla.enum'] = False

for extra_module in EXTRA_MODULES:
    try:
        imp.find_module(extra_module)
        EXTRA_MODULES[extra_module] = True
    except ImportError:
        EXTRA_MODULES[extra_module] = False

if EXTRA_MODULES['web']:
    from web import HTTPError

if EXTRA_MODULES['paramiko']:
    try:
        from paramiko import RSAKey
    except Exception:
        EXTRA_MODULES['paramiko'] = False

if EXTRA_MODULES['flask']:
    from flask import Response

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
    406: '406 Not Acceptable',
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
    adler = 1

    try:
        with open(file, 'rb') as openFile:
            for line in openFile:
                adler = zlib.adler32(line, adler)
    except Exception as e:
        raise Exception('FATAL - could not get Adler32 checksum of file %s - %s' % (file, e))

    # backflip on 32bit
    if adler < 0:
        adler = adler + 2 ** 32

    return str('%08x' % adler)


def md5(file):
    """
    Runs the MD5 algorithm (RFC-1321) on the binary content of the file named file and returns the hexadecimal digest

    :param string: file name
    :returns: string of 32 hexadecimal digits
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file, "rb") as f:
            list(map(hash_md5.update, iter(lambda: f.read(4096), b"")))
    except Exception as e:
        raise Exception('FATAL - could not get MD5 checksum of file %s - %s' % (file, e))

    return hash_md5.hexdigest()


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
    def default(self, obj):  # pylint: disable=E0202
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
    for k, v in list(dct.items()):
        if isinstance(v, string_types) and re.search(" UTC", v):
            try:
                dct[k] = datetime.datetime.strptime(v, DATE_FORMAT)
            except Exception:
                pass
    return dct


def parse_response(data):
    """
    JSON render function
    """
    ret_obj = None
    try:
        ret_obj = data.decode('utf-8')
    except AttributeError:
        ret_obj = data

    return json.loads(ret_obj, object_hook=datetime_parser)


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
    except Exception:
        print({'Content-Type': 'application/octet-stream', 'ExceptionClass': exc_cls, 'ExceptionMessage': str(exc_msg).strip()})
        raise


def generate_http_error_flask(status_code, exc_cls, exc_msg):
    """
    utitily function to generate a complete HTTP error response.
    :param status_code: The HTTP status code to generate a response for.
    :param exc_cls: The name of the exception class to send with the response.
    :param exc_msg: The error message.
    :returns: a web.py HTTP response object.
    """
    data = {'ExceptionClass': exc_cls,
            'ExceptionMessage': exc_msg}
    # Truncate too long exc_msg
    if len(str(exc_msg)) > 15000:
        exc_msg = str(exc_msg)[:15000]
    resp = Response(response=render_json(**data), status=status_code, content_type='application/octet-stream')
    resp.headers['ExceptionClass'] = exc_cls
    resp.headers['ExceptionMessage'] = clean_headers(exc_msg)

    try:
        return resp
    except Exception:
        print({'Content-Type': 'application/octet-stream', 'ExceptionClass': exc_cls, 'ExceptionMessage': str(exc_msg).strip()})
        raise


def execute(cmd, blocking=True):
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

    if blocking:
        result = process.communicate()
        (out, err) = result
        exitcode = process.returncode
        return exitcode, out, err
    return process


def rse_supported_protocol_operations():
    """ Returns a list with operations supported by all RSE protocols."""
    return ['read', 'write', 'delete', 'third_party_copy']


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
    for i in range(0, len(l), n):
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


def construct_surl_BelleII(dsn, filename):
    """
    Defines relative SURL for Belle II specific replicas.
    This method contains the Belle II convention.
    To be used for non-deterministic Belle II sites.
    DSN (or datablock in the Belle II naming) contains /

    """

    fields = dsn.split("/")
    nfields = len(fields)
    if nfields == 0:
        return '/other/%s' % (filename)
    else:
        return '%s/%s' % (dsn, filename)


def construct_surl(dsn, filename, naming_convention=None):
    if naming_convention == 'T0':
        return construct_surl_T0(dsn, filename)
    elif naming_convention == 'DQ2':
        return construct_surl_DQ2(dsn, filename)
    elif naming_convention == 'BelleII':
        return construct_surl_BelleII(dsn, filename)

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
    except Exception:
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


def detect_client_location():
    """
    Open a UDP socket to a machine on the internet, to get the local IPv4 and IPv6
    addresses of the requesting client.

    Try to determine the sitename automatically from common environment variables,
    in this order: SITE_NAME, ATLAS_SITE_NAME, OSG_SITE_NAME. If none of these exist
    use the fixed string 'ROAMING'.
    """

    ip = '0.0.0.0'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        pass

    ip6 = '::'
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860:0:0:0:0:8888", 80))
        ip6 = s.getsockname()[0]
    except Exception:
        pass

    site = os.environ.get('SITE_NAME',
                          os.environ.get('ATLAS_SITE_NAME',
                                         os.environ.get('OSG_SITE_NAME',
                                                        'ROAMING')))

    return {'ip': ip,
            'ip6': ip6,
            'fqdn': socket.getfqdn(),
            'site': site}


def ssh_sign(private_key, message):
    """
    Sign a string message using the private key.

    :param private_key: The SSH RSA private key as a string.
    :param message: The message to sign as a string.
    :return: Base64 encoded signature as a string.
    """
    if not EXTRA_MODULES['paramiko']:
        raise MissingModuleException('The paramiko module is not installed or faulty.')
    sio_private_key = StringIO(private_key)
    priv_k = RSAKey.from_private_key(sio_private_key)
    sio_private_key.close()
    signature_stream = priv_k.sign_ssh_data(message)
    signature_stream.rewind()
    return base64.b64encode(signature_stream.get_remainder())


def make_valid_did(lfn_dict):
    """
    When managing information about a LFN (such as in `rucio upload` or
    the RSE manager's upload), we add the `filename` attribute to record
    the name of the file on the local disk in addition to the remainder
    of the DID information.

    This function will take that python dictionary, and strip out the
    additional `filename` key.  If this is not done, then the dictionary
    will not pass the DID JSON schema validation.
    """
    lfn_copy = dict(lfn_dict)
    lfn_copy['name'] = lfn_copy.get('name', lfn_copy['filename'])
    del lfn_copy['filename']
    return lfn_copy


def send_trace(trace, trace_endpoint, user_agent, retries=5):
    """
    Send the given trace to the trace endpoint

    :param trace: the trace dictionary to send
    :param trace_endpoint: the endpoint where the trace should be send
    :param user_agent: the user agent sending the trace
    :param retries: the number of retries if sending fails
    :return: 0 on success, 1 on failure
    """
    if user_agent.startswith('pilot'):
        return 0
    for dummy in range(retries):
        try:
            requests.post(trace_endpoint + '/traces/', verify=False, data=json.dumps(trace))
            return 0
        except Exception:
            pass
    return 1


def add_url_query(url, query):
    """
    Add a new dictionary to URL parameters

    :param url: The existing URL
    :param query: A dictionary containing key/value pairs to be added to the URL
    :return: The expanded URL with the new query parameters
    """

    url_parts = list(urlparse.urlparse(url))
    mod_query = dict(urlparse.parse_qsl(url_parts[4]))
    mod_query.update(query)
    url_parts[4] = urlencode(mod_query)
    return urlparse.urlunparse(url_parts)


def get_bytes_value_from_string(input_string):
    """
    Get bytes from a string that represents a storage value and unit

    :param input_string: String containing a value and an unit
    :return: Integer value representing the value in bytes
    """
    result = re.findall('^([0-9]+)([A-Za-z]+)$', input_string)
    if result:
        value = int(result[0][0])
        unit = result[0][1].lower()
        if unit == 'b':
            value = value
        elif unit == 'kb':
            value = value * 1000
        elif unit == 'mb':
            value = value * 1000000
        elif unit == 'gb':
            value = value * 1000000000
        elif unit == 'tb':
            value = value * 1000000000000
        elif unit == 'pb':
            value = value * 1000000000000000
        else:
            return False
        return value
    else:
        return False


def parse_did_filter_from_string(input_string):
    """
    Parse DID filter options in format 'length<3,type=all' from string.

    :param input_string: String containing the filter options.
    :return: filter dictionary and type as string.
    """
    filters = {}
    type = 'collection'
    if input_string:
        filter_options = input_string.replace(' ', '').split(',')
        for option in filter_options:
            value = None
            key = None

            if '>=' in option:
                key, value = option.split('>=')
                if key == 'length':
                    key = 'length.gte'
            elif '>' in option:
                key, value = option.split('>')
                if key == 'length':
                    key = 'length.gt'
            elif '<=' in option:
                key, value = option.split('<=')
                if key == 'length':
                    key = 'length.lte'
            elif '<' in option:
                key, value = option.split('<')
                if key == 'length':
                    key = 'length.lt'
            elif '=' in option:
                key, value = option.split('=')

            if key == 'type':
                if value.upper() in ['ALL', 'COLLECTION', 'CONTAINER', 'DATASET', 'FILE']:
                    type = value.lower()
                else:
                    raise InvalidType('{0} is not a valid type. Valid types are {1}'.format(value, ['ALL', 'COLLECTION', 'CONTAINER', 'DATASET', 'FILE']))
            elif key in ('length.gt', 'length.lt', 'length.gte', 'length.lte', 'length'):
                try:
                    value = int(value)
                    filters[key] = value
                except ValueError:
                    raise ValueError('Length has to be an integer value.')
                filters[key] = value
            else:
                if value.lower() == 'true':
                    value = '1'
                elif value.lower() == 'false':
                    value = '0'
                filters[key] = value
    return filters, type


def parse_replicas_from_file(path):
    """
    Parses the output of list_replicas from a json or metalink file
    into a dictionary. Metalink parsing is tried first and if it fails
    it tries to parse json.

    :param path: the path to the input file

    :returns: a list with a dictionary for each file
    """
    with open(path) as fp:
        try:
            root = ElementTree.parse(fp).getroot()
            return parse_replicas_metalink(root)
        except ElementTree.ParseError as xml_err:
            try:
                return json.load(fp)
            except ValueError as json_err:
                raise MetalinkJsonParsingError(path, xml_err, json_err)


def parse_replicas_from_string(string):
    """
    Parses the output of list_replicas from a json or metalink string
    into a dictionary. Metalink parsing is tried first and if it fails
    it tries to parse json.

    :param string: the string to parse

    :returns: a list with a dictionary for each file
    """
    try:
        root = ElementTree.fromstring(string)
        return parse_replicas_metalink(root)
    except ElementTree.ParseError as xml_err:
        try:
            return json.loads(string)
        except ValueError as json_err:
            raise MetalinkJsonParsingError(string, xml_err, json_err)


def parse_replicas_metalink(root):
    """
    Transforms the metalink tree into a list of dictionaries where
    each dictionary describes a file with its replicas.
    Will be called by parse_replicas_from_file and parse_replicas_from_string.

    :param root: root node of the metalink tree

    :returns: a list with a dictionary for each file
    """
    files = []

    # metalink namespace
    ns = '{urn:ietf:params:xml:ns:metalink}'
    str_to_bool = {'true': True, 'True': True, 'false': False, 'False': False}

    # loop over all <file> tags of the metalink string
    for file_tag_obj in root.findall(ns + 'file'):
        # search for identity-tag
        identity_tag_obj = file_tag_obj.find(ns + 'identity')
        if not ElementTree.iselement(identity_tag_obj):
            raise InputValidationError('Failed to locate identity-tag inside %s' % ElementTree.tostring(file_tag_obj))

        cur_file = {'did': identity_tag_obj.text,
                    'adler32': None,
                    'md5': None,
                    'sources': []}

        parent_dids = set()
        parent_dids_tag_obj = file_tag_obj.find(ns + 'parents')
        if ElementTree.iselement(parent_dids_tag_obj):
            for did_tag_obj in parent_dids_tag_obj.findall(ns + 'did'):
                parent_dids.add(did_tag_obj.text)
        cur_file['parent_dids'] = parent_dids

        size_tag_obj = file_tag_obj.find(ns + 'size')
        cur_file['bytes'] = int(size_tag_obj.text) if ElementTree.iselement(size_tag_obj) else None

        for hash_tag_obj in file_tag_obj.findall(ns + 'hash'):
            hash_type = hash_tag_obj.get('type')
            if hash_type:
                cur_file[hash_type] = hash_tag_obj.text

        for url_tag_obj in file_tag_obj.findall(ns + 'url'):
            key_rename_map = {'location': 'rse'}
            src = {}
            for k, v in url_tag_obj.items():
                k = key_rename_map.get(k, k)
                src[k] = str_to_bool.get(v, v)
            src['pfn'] = url_tag_obj.text
            cur_file['sources'].append(src)

        files.append(cur_file)

    return files


def get_thread_with_periodic_running_function(interval, action, graceful_stop):
    """
    Get a thread where a function runs periodically.

    :param interval: Interval in seconds when the action fucntion should run.
    :param action: Function, that should run periodically.
    :param graceful_stop: Threading event used to check for graceful stop.
    """
    def start():
        while not graceful_stop.is_set():
            starttime = time.time()
            action()
            time.sleep(interval - ((time.time() - starttime)))
    t = threading.Thread(target=start)
    return t


def run_cmd_process(cmd, timeout=3600):
    """
    shell command parser with timeout

    :param cmd: shell command as a string
    :param timeout: in seconds

    :return: stdout xor stderr, and errorcode
    """

    time_start = datetime.datetime.now().second
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

    running_time = 0
    while process.poll() is None and running_time < timeout:
        time_now = datetime.datetime.now().second
        running_time = int(time_now - time_start)
        time.sleep(3)
    if process.poll() is None:
        process.terminate()
        time.sleep(3)
    if process.poll() is None:
        process.kill()

    stdout, stderr = process.communicate()
    if not stderr:
        stderr = ''
    if not stdout:
        stdout = ''
    if stderr and stderr != '':
        stdout += " Error: " + stderr
    if process:
        returncode = process.returncode
    else:
        returncode = 1
    if returncode != 1 and 'Command time-out' in stdout:
        returncode = 1
    if returncode is None:
        returncode = 0

    return returncode, stdout
