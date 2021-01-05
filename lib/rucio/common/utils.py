# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2020
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2015-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2020
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Tobias Wegner <twegner@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Tomas Javurek <tomas.javurek@cern.ch>, 2019-2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Gabriele Fronze' <gfronze@cern.ch>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

try:
    import importlib
    importlib.util.find_spec('')
except AttributeError:
    import imp

import base64
import copy
import datetime
import errno
import getpass
import hashlib
import json
import logging
import os
import os.path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zlib

from enum import Enum
from logging import getLogger, Formatter  # NOQA: F401
from logging.handlers import RotatingFileHandler
from uuid import uuid4 as uuid
from xml.etree import ElementTree

import requests
from six import string_types, text_type, PY3

from rucio.common.config import config_get
from rucio.common.exception import MissingModuleException, InvalidType, InputValidationError, MetalinkJsonParsingError, RucioException
from rucio.common.types import InternalAccount, InternalScope

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

# Extra modules: Only imported if available
EXTRA_MODULES = {'paramiko': False}

for extra_module in EXTRA_MODULES:
    if 'imp' in sys.modules:
        try:
            imp.find_module(extra_module)
            EXTRA_MODULES[extra_module] = True
        except ImportError:
            EXTRA_MODULES[extra_module] = False
    else:
        if importlib.util.find_spec(extra_module):
            EXTRA_MODULES[extra_module] = True
        else:
            EXTRA_MODULES[extra_module] = False

if EXTRA_MODULES['paramiko']:
    try:
        from paramiko import RSAKey
    except Exception:
        EXTRA_MODULES['paramiko'] = False

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
    if path is not None:
        complete_url += "/" + path
    if params is not None:
        complete_url += "?"
        if isinstance(params, str):
            complete_url += quote(params)
        else:
            complete_url += urlencode(params, doseq=doseq)
    return complete_url


def oidc_identity_string(sub, iss):
    """
    Transform IdP sub claim and issuers url into users identity string.
    :param sub: users SUB claim from the Identity Provider
    :param iss: issuer (IdP) https url

    :returns: OIDC identity string "SUB=<usersid>, ISS=https://iam-test.ch/"
    """
    return 'SUB=' + str(sub) + ', ISS=' + str(iss)


def sqlalchemy_obj_to_dict(sqlalchemyresult):
    """
    Makes dictionary from SQLAlchemy query result object
    :param sqlalchemyresult:
    :returns: dictionary
    """
    res_dict = copy.deepcopy(dict(sqlalchemyresult.__dict__))
    del res_dict['_sa_instance_state']
    return res_dict


def all_oidc_req_claims_present(scope, audience, required_scope, required_audience, sepatator=" "):
    """
    Checks if both of the following statements are true:
    - all items in required_scope are present in scope string
    - all items in required_audience are present in audience
    returns false otherwise. audience and scope must be both strings
    or both lists. Similarly for required_* variables.
    If this condition is satisfied, False is returned.
    :params scope: list of strings or one string where items are separated by a separator input variable
    :params audience: list of strings or one string where items are separated by a separator input variable
    :params required_scope: list of strings or one string where items are separated by a separator input variable
    :params required_audience: list of strings or one string where items are separated by a separator input variable
    :params sepatator: separator string, space by default
    :returns : True or False
    """
    if not scope:
        scope = ""
    if not audience:
        audience = ""
    if not required_scope:
        required_scope = ""
    if not required_audience:
        required_audience = ""
    if (isinstance(scope, list) and isinstance(audience, list) and  # NOQA: W504
        isinstance(required_scope, list) and isinstance(required_audience, list)):
        scope = [str(it) for it in scope]
        audience = [str(it) for it in audience]
        required_scope = [str(it) for it in required_scope]
        required_audience = [str(it) for it in required_audience]
        req_scope_present = all(elem in scope for elem in required_scope)
        req_audience_present = all(elem in audience for elem in required_audience)
        return req_scope_present and req_audience_present
    elif (isinstance(scope, string_types) and isinstance(audience, string_types) and  # NOQA: W504
          isinstance(required_scope, string_types) and isinstance(required_audience, string_types)):
        scope = str(scope)
        audience = str(audience)
        required_scope = str(required_scope)
        required_audience = str(required_audience)
        req_scope_present = all(elem in scope.split(sepatator) for elem in required_scope.split(sepatator))
        req_audience_present = all(elem in audience.split(sepatator) for elem in required_audience.split(sepatator))
        return req_scope_present and req_audience_present
    elif (isinstance(scope, list) and isinstance(audience, list) and  # NOQA: W504
          isinstance(required_scope, string_types) and isinstance(required_audience, string_types)):
        scope = [str(it) for it in scope]
        audience = [str(it) for it in audience]
        required_scope = str(required_scope)
        required_audience = str(required_audience)
        req_scope_present = all(elem in scope for elem in required_scope.split(sepatator))
        req_audience_present = all(elem in audience for elem in required_audience.split(sepatator))
        return req_scope_present and req_audience_present
    elif (isinstance(scope, string_types) and isinstance(audience, string_types) and  # NOQA: W504
          isinstance(required_scope, list) and isinstance(required_audience, list)):
        scope = str(scope)
        audience = str(audience)
        required_scope = [str(it) for it in required_scope]
        required_audience = [str(it) for it in required_audience]
        req_scope_present = all(elem in scope.split(sepatator) for elem in required_scope)
        req_audience_present = all(elem in audience.split(sepatator) for elem in required_audience)
        return req_scope_present and req_audience_present
    else:
        return False


def generate_uuid():
    return str(uuid()).replace('-', '').lower()


def generate_uuid_bytes():
    return uuid().bytes


# GLOBALLY_SUPPORTED_CHECKSUMS = ['adler32', 'md5', 'sha256', 'crc32']
GLOBALLY_SUPPORTED_CHECKSUMS = ['adler32', 'md5']
CHECKSUM_ALGO_DICT = {}
PREFERRED_CHECKSUM = GLOBALLY_SUPPORTED_CHECKSUMS[0]
CHECKSUM_KEY = 'supported_checksums'


def is_checksum_valid(checksum_name):
    """
    A simple function to check wether a checksum algorithm is supported.
    Relies on GLOBALLY_SUPPORTED_CHECKSUMS to allow for expandability.

    :param checksum_name: The name of the checksum to be verified.
    :returns: True if checksum_name is in GLOBALLY_SUPPORTED_CHECKSUMS list, False otherwise.
    """

    return checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS


def set_checksum_value(file, checksum_names_list):
    for checksum_name in checksum_names_list:
        if checksum_name in file['metadata'].keys() and file['metadata'][checksum_name]:
            file['checksum'] = '%s:%s' % (checksum_name.upper(), str(file['metadata'][checksum_name]))
            if checksum_name == PREFERRED_CHECKSUM:
                break


def adler32(file):
    """
    An Adler-32 checksum is obtained by calculating two 16-bit checksums A and B and concatenating their bits into a 32-bit integer. A is the sum of all bytes in the stream plus one, and B is the sum of the individual values of A from each step.

    :param file: file name
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


CHECKSUM_ALGO_DICT['adler32'] = adler32


def md5(file):
    """
    Runs the MD5 algorithm (RFC-1321) on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file, "rb") as f:
            list(map(hash_md5.update, iter(lambda: f.read(4096), b"")))
    except Exception as e:
        raise Exception('FATAL - could not get MD5 checksum of file %s - %s' % (file, e))

    return hash_md5.hexdigest()


CHECKSUM_ALGO_DICT['md5'] = md5


def sha256(file):
    """
    Runs the SHA256 algorithm on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    with open(file, "rb") as f:
        bytes = f.read()  # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest()
        print(readable_hash)
        return readable_hash


CHECKSUM_ALGO_DICT['sha256'] = sha256


def crc32(file):
    """
    Runs the CRC32 algorithm on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    prev = 0
    for eachLine in open(file, "rb"):
        prev = zlib.crc32(eachLine, prev)
    return "%X" % (prev & 0xFFFFFFFF)


CHECKSUM_ALGO_DICT['crc32'] = crc32


def str_to_date(string):
    """ Converts a RFC-1123 string to the corresponding datetime value.

    :param string: the RFC-1123 string to convert to datetime value.
    """
    return datetime.datetime.strptime(string, DATE_FORMAT) if string else None


def val_to_space_sep_str(vallist):
    """ Converts a list of values into a string of space separated values

    :param vallist: the list of values to to convert into string
    :return: the string of space separated values or the value initially passed as parameter
    """
    try:
        if isinstance(vallist, list):
            return text_type(" ".join(vallist))
        else:
            return text_type(vallist)
    except:
        return text_type('')


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
        elif isinstance(obj, Enum):
            return obj.name
        elif isinstance(obj, (InternalAccount, InternalScope)):
            return obj.external
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

    if blocking:
        result = process.communicate()
        (out, err) = result
        exitcode = process.returncode
        return exitcode, out.decode(), err.decode()
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
    logger = logging.getLogger(name)
    hdlr = RotatingFileHandler('%s/%s.log' % (config_get('common', 'logdir'), name), maxBytes=1000000000, backupCount=10)
    formatter = logging.Formatter('%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')
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


_SURL_ALGORITHMS = {}
_DEFAULT_SURL = 'DQ2'


def register_surl_algorithm(surl_callable, name=None):
    if name is None:
        name = surl_callable.__name__
    _SURL_ALGORITHMS[name] = surl_callable


register_surl_algorithm(construct_surl_T0, 'T0')
register_surl_algorithm(construct_surl_DQ2, 'DQ2')
register_surl_algorithm(construct_surl_BelleII, 'BelleII')


def construct_surl(dsn, filename, naming_convention=None):
    # ensure that policy package is loaded in case it registers its own algorithms
    import rucio.common.schema  # noqa: F401

    if naming_convention is None or naming_convention not in _SURL_ALGORITHMS:
        naming_convention = _DEFAULT_SURL
    return _SURL_ALGORITHMS[naming_convention](dsn, filename)


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
            surl = re.sub('/srm/managerv1\?SFN=', '', surl)  # NOQA: W605
            surl = re.sub('/srm/v2/server\?SFN=', '', surl)  # NOQA: W605
            surl = re.sub('/srm/managerv2\?SFN=', '', surl)  # NOQA: W605
        if surl.startswith('https://storage.googleapis.com'):
            surl = surl.split('?GoogleAccessId')[0]
        if '?X-Amz' in surl:
            surl = surl.split('?X-Amz')[0]
        res.append(surl)
    res.sort()
    return res


_EXTRACT_SCOPE_ALGORITHMS = {}
_DEFAULT_EXTRACT = 'atlas'


def extract_scope_atlas(did, scopes):
    # Try to extract the scope from the DSN
    if did.find(':') > -1:
        if len(did.split(':')) > 2:
            raise RucioException('Too many colons. Cannot extract scope and name')
        scope, name = did.split(':')[0], did.split(':')[1]
        if name.endswith('/'):
            name = name[:-1]
        return scope, name
    else:
        scope = did.split('.')[0]
        if did.startswith('user') or did.startswith('group'):
            scope = ".".join(did.split('.')[0:2])
        if did.endswith('/'):
            did = did[:-1]
        return scope, did


def extract_scope_belleii(did, scopes):
    split_did = did.split('/')
    if did.startswith('/belle/MC/'):
        if did.startswith('/belle/MC/BG') or \
           did.startswith('/belle/MC/build') or \
           did.startswith('/belle/MC/generic') or \
           did.startswith('/belle/MC/log') or \
           did.startswith('/belle/MC/mcprod') or \
           did.startswith('/belle/MC/prerelease') or \
           did.startswith('/belle/MC/release'):
            return 'mc', did
        if did.startswith('/belle/MC/cert') or \
           did.startswith('/belle/MC/dirac') or \
           did.startswith('/belle/MC/dr3') or \
           did.startswith('/belle/MC/fab') or \
           did.startswith('/belle/MC/hideki') or \
           did.startswith('/belle/MC/merge') or \
           did.startswith('/belle/MC/migration') or \
           did.startswith('/belle/MC/skim') or \
           did.startswith('/belle/MC/test'):
            return 'mc_tmp', did
        if len(split_did) > 4:
            if split_did[3].find('fab') > -1 or split_did[3].find('merge') > -1 or split_did[3].find('skim') > -1:
                return 'mc_tmp', did
            if split_did[3].find('release') > -1:
                return 'mc', did
        return 'mc_tmp', did
    if did.startswith('/belle/Raw/'):
        return 'raw', did
    if did.startswith('/belle/hRaw'):
        return 'hraw', did
    if did.startswith('/belle/user/'):
        if len(split_did) > 4:
            if len(split_did[3]) == 1 and 'user.%s' % (split_did[4]) in scopes:
                return 'user.%s' % split_did[4], did
        if len(split_did) > 3:
            if 'user.%s' % (split_did[3]) in scopes:
                return 'user.%s' % split_did[3], did
        return 'user', did
    if did.startswith('/belle/group/'):
        if len(split_did) > 4:
            if 'group.%s' % (split_did[4]) in scopes:
                return 'group.%s' % split_did[4], did
        return 'group', did
    if did.startswith('/belle/data/') or did.startswith('/belle/Data/'):
        if len(split_did) > 4:
            if split_did[3] in ['fab', 'skim']:  # /belle/Data/fab --> data_tmp
                return 'data_tmp', did
            if split_did[3].find('release') > -1:  # /belle/Data/release --> data
                return 'data', did
        if len(split_did) > 5:
            if split_did[3] in ['proc']:  # /belle/Data/proc
                if split_did[4].find('release') > -1:  # /belle/Data/proc/release*
                    if len(split_did) > 7 and split_did[6] in ['GCR2c', 'prod00000007', 'prod6b', 'proc7b',
                                                               'proc8b', 'Bucket4', 'Bucket6test', 'bucket6',
                                                               'proc9', 'bucket7', 'SKIMDATAx1', 'proc10Valid',
                                                               'proc10', 'SkimP10x1', 'SkimP11x1', 'SkimB9x1',
                                                               'SkimB10x1', 'SkimB11x1']:  # /belle/Data/proc/release*/*/proc10/* --> data_tmp (Old convention)
                        return 'data_tmp', did
                    else:  # /belle/Data/proc/release*/*/proc11/* --> data (New convention)
                        return 'data', did
                if split_did[4].find('fab') > -1:  # /belle/Data/proc/fab* --> data_tmp
                    return 'data_tmp', did
        return 'data_tmp', did
    if did.startswith('/belle/ddm/functional_tests/') or did.startswith('/belle/ddm/tests/') or did.startswith('/belle/test/ddm_test'):
        return 'test', did
    if did.startswith('/belle/BG/'):
        return 'data', did
    return 'other', did


def register_extract_scope_algorithm(extract_callable, name=[]):
    if name is None:
        name = extract_callable.__name__
    _EXTRACT_SCOPE_ALGORITHMS[name] = extract_callable


register_extract_scope_algorithm(extract_scope_atlas, 'atlas')
register_extract_scope_algorithm(extract_scope_belleii, 'belleii')


def extract_scope(did, scopes=None):
    extract_scope_convention = config_get('common', 'extract_scope', False, None)
    if extract_scope_convention is None or extract_scope_convention not in _EXTRACT_SCOPE_ALGORITHMS:
        extract_scope_convention = _DEFAULT_EXTRACT
    return _EXTRACT_SCOPE_ALGORITHMS[extract_scope_convention](did=did, scopes=scopes)


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
    base_dir = os.path.abspath(tempfile.gettempdir())
    try:
        return os.path.join(base_dir, getpass.getuser())
    except Exception:
        pass

    try:
        return os.path.join(base_dir, str(os.getuid()))
    except Exception:
        pass

    return base_dir


def is_archive(name):
    '''
    Check if a file name is an archive file or not.

    :return: A boolean.
    '''
    regexp = r'^.*\.(zip|zipx|tar.gz|tgz|tar.Z|tar.bz2|tbz2)(\.\d+)*$'
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
    if PY3 and isinstance(message, str):
        message = message.encode()
    if not EXTRA_MODULES['paramiko']:
        raise MissingModuleException('The paramiko module is not installed or faulty.')
    sio_private_key = StringIO(private_key)
    priv_k = RSAKey.from_private_key(sio_private_key)
    sio_private_key.close()
    signature_stream = priv_k.sign_ssh_data(message)
    signature_stream.rewind()
    base64_encoded = base64.b64encode(signature_stream.get_remainder())
    if PY3:
        base64_encoded = base64_encoded.decode()
    return base64_encoded


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
                if key == 'created_after' or key == 'created_before':
                    value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')

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
            elif isinstance(value, string_types):
                if value.lower() == 'true':
                    value = '1'
                elif value.lower() == 'false':
                    value = '0'
                filters[key] = value
            else:
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


def api_update_return_dict(dictionary):
    """
    Ensure that rse is in a dictionary returned from core

    :param dictionary: The dictionary to edit
    :returns dictionary: The edited dictionary
    """
    if not isinstance(dictionary, dict):
        return dictionary

    copied = False  # Avoid side effects from pass by object

    for rse_str in ['rse', 'src_rse', 'source_rse', 'dest_rse', 'destination_rse']:
        rse_id_str = '%s_id' % rse_str
        if rse_id_str in dictionary.keys() and dictionary[rse_id_str] is not None:
            if rse_str not in dictionary.keys():
                if not copied:
                    dictionary = dictionary.copy()
                    copied = True
                import rucio.core.rse
                dictionary[rse_str] = rucio.core.rse.get_rse_name(rse_id=dictionary[rse_id_str])

    if 'account' in dictionary.keys() and dictionary['account'] is not None:
        if not copied:
            dictionary = dictionary.copy()
            copied = True
        dictionary['account'] = dictionary['account'].external

    if 'scope' in dictionary.keys() and dictionary['scope'] is not None:
        if not copied:
            dictionary = dictionary.copy()
            copied = True
        dictionary['scope'] = dictionary['scope'].external

    return dictionary


def get_parsed_throttler_mode(throttler_mode):
    """ Parse the conveyor-throttler mode string. """
    direction = None
    all_activities = None
    if throttler_mode == 'DEST_PER_ACT':
        direction = 'destination'
        all_activities = False
    elif throttler_mode == 'DEST_PER_ALL_ACT':
        direction = 'destination'
        all_activities = True
    elif throttler_mode == 'SRC_PER_ACT':
        direction = 'source'
        all_activities = False
    elif throttler_mode == 'SRC_PER_ALL_ACT':
        direction = 'source'
        all_activities = True
    return (direction, all_activities)


def query_bunches(query, bunch_by):
    """
    Queries output by yield_per sqlalchemy function
    (which in a for loop returns rows one by one).
    Groups the query rows in bunches of bunch_by
    elements and returns list of bunches.
    :param query: sqlalchemy session query
    :param bunch_by: integer number
    :returns: [[bunch_of_tuples_1],[bunch_of_tuples_2],...]

    """
    filtered_bunches = []
    item_bunch = []
    for i in query.yield_per(bunch_by):
        # i is either tuple of one element (token/model object etc.)
        if not isinstance(i, tuple) and not isinstance(i, list):
            item_bunch.append(i)
        # or i is a tuple with the column elements per row
        else:
            item_bunch += i
        if len(item_bunch) % bunch_by == 0:
            filtered_bunches.append(item_bunch)
            item_bunch = []
    if item_bunch:
        filtered_bunches.append(item_bunch)
    return filtered_bunches


def setup_logger(module_name=None, logger_name=None, logger_level=None, verbose=False):
    '''
    Factory method to set logger with handlers.
    :param module_name: __name__ of the module that is calling this method
    :param logger_name: name of the logger, typically name of the module.
    :param logger_level: if not given, fetched from config.
    :param verbose: verbose option set in bin/rucio
    '''
    # helper method for cfg check
    def _force_cfg_log_level(cfg_option):
        cfg_forced_modules = config_get('logging', cfg_option, raise_exception=False, default=None, clean_cached=True)
        if cfg_forced_modules:
            if re.match(str(cfg_forced_modules), module_name):
                return True
        return False

    # creating log
    if not logger_name:
        if not module_name:
            logger_name = 'usr'
        else:
            logger_name = module_name.split('.')[-1]
    logger = logging.getLogger(logger_name)

    # extracting the log level
    if not logger_level:
        logger_level = logging.WARNING
        if verbose:
            logger_level = logging.DEBUG

        # overriding by the config
        cfg_levels = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR)
        for level in cfg_levels:
            cfg_opt = 'forceloglevel' + logging.getLevelName(level)
            if _force_cfg_log_level(cfg_opt):
                logger_level = level

    # setting the log level
    logger.setLevel(logger_level)

    # preferred logger handling
    def add_handler(logger):
        hdlr = logging.StreamHandler()

        def emit_decorator(fnc):
            def func(*args):
                if 'RUCIO_LOGGING_FORMAT' not in os.environ:
                    levelno = args[0].levelno
                    format_str = '%(asctime)s\t%(levelname)s\t%(message)s\033[0m'
                    if levelno >= logging.CRITICAL:
                        color = '\033[31;1m'
                    elif levelno >= logging.ERROR:
                        color = '\033[31;1m'
                    elif levelno >= logging.WARNING:
                        color = '\033[33;1m'
                    elif levelno >= logging.INFO:
                        color = '\033[32;1m'
                    elif levelno >= logging.DEBUG:
                        color = '\033[36;1m'
                        format_str = '%(asctime)s\t%(levelname)s\t%(filename)s\t%(message)s\033[0m'
                    else:
                        color = '\033[0m'
                    formatter = logging.Formatter('{0}{1}'.format(color, format_str))
                else:
                    formatter = logging.Formatter(os.environ['RUCIO_LOGGING_FORMAT'])
                hdlr.setFormatter(formatter)
                return fnc(*args)
            return func
        hdlr.emit = emit_decorator(hdlr.emit)
        logger.addHandler(hdlr)

    # setting handler and formatter
    if not logger.handlers:
        add_handler(logger)

    return logger


class retry:
    """Retry callable object with configuragle number of attempts"""

    def __init__(self, func, *args, **kwargs):
        '''
        :param func: a method that should be executed with retries
        :param args parametres of the func
        :param kwargs: key word arguments of the func
        '''
        self.func, self.args, self.kwargs = func, args, kwargs

    def __call__(self, mtries=3, logger=None):
        '''
        :param mtries: maximum number of attempts to execute the function
        :param logger: preferred logger
        '''
        attempt = mtries
        while attempt > 1:
            try:
                if logger:
                    logger.debug('{}: Attempt {}'.format(self.func.__name__, mtries - attempt + 1))
                return self.func(*self.args, **self.kwargs)
            except Exception as e:
                if logger:
                    logger.debug('{}: Attempt failed {}'.format(self.func.__name__, mtries - attempt + 1))
                    logger.debug(str(e))
                attempt -= 1
        return self.func(*self.args, **self.kwargs)
