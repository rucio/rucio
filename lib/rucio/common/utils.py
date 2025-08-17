# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import argparse
import base64
import copy
import datetime
import errno
import getpass
import ipaddress
import itertools
import json
import logging
import os
import os.path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import types
from collections import OrderedDict
from enum import Enum
from functools import cache, update_wrapper, wraps
from io import StringIO
from itertools import zip_longest
from typing import TYPE_CHECKING, Any, Optional, TypeVar, Union, cast
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from uuid import uuid4 as uuid
from xml.etree import ElementTree

import requests
from typing_extensions import ParamSpec

from rucio.common.config import config_get, config_get_bool
from rucio.common.constants import BASE_SCHEME_MAP, DEFAULT_VO
from rucio.common.exception import DIDFilterSyntaxError, DuplicateCriteriaInDIDFilter, InputValidationError, InvalidType, MetalinkJsonParsingError, MissingModuleException, RucioException
from rucio.common.extra import import_extras
from rucio.common.plugins import PolicyPackageAlgorithms
from rucio.common.types import InternalAccount, InternalScope, LFNDict, TraceDict

EXTRA_MODULES = import_extras(['paramiko'])

if EXTRA_MODULES['paramiko']:
    try:
        from paramiko import RSAKey
    except Exception:
        EXTRA_MODULES['paramiko'] = None

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence

    T = TypeVar('T')
    HashableKT = TypeVar('HashableKT')
    HashableVT = TypeVar('HashableVT')
    from _typeshed import FileDescriptorOrPath
    from sqlalchemy.orm import Session

    from rucio.common.types import LoggerFunction


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


def invert_dict(d: "Mapping[HashableKT, HashableVT]") -> "Mapping[HashableVT, HashableKT]":
    """
    Invert the dictionary.
    CAUTION: this function is not deterministic unless the input dictionary is one-to-one mapping.

    :param d: source dictionary
    :returns: dictionary {value: key for key, value in d.items()}
    """
    return {value: key for key, value in d.items()}


def build_url(
        url: str,
        path: Optional[str] = None,
        params: Optional[Union[str, dict[Any, Any], list[tuple[Any, Any]]]] = None,
        doseq: bool = False
) -> str:
    """
    utitily function to build an url for requests to the rucio system.

    If the optional parameter doseq is evaluates to True, individual key=value pairs
    separated by '&' are generated for each element of the value sequence for the key.
    """
    complete_url = url
    if path is not None:
        complete_url += "/" + path
    if params is not None:
        complete_url += _encode_params_as_url_query_string(params, doseq)
    return complete_url


def _encode_params_as_url_query_string(
        params: Union[str, dict[Any, Any], list[tuple[Any, Any]]],
        doseq: bool
) -> str:
    """
    Encode params into a URL query string.

    :param params: the parameters to encode
    :param doseq: if True, individual key=value pairs separated by '&' are generated for each element of the value sequence for the key

    :returns: params as a URL query string
    """
    complete_url = "?"
    if isinstance(params, str):
        complete_url += quote(params)
    else:
        complete_url += urlencode(params, doseq=doseq)
    return complete_url


def all_oidc_req_claims_present(
        scope: Optional[Union[str, list[str]]],
        audience: Optional[Union[str, list[str]]],
        required_scope: Optional[Union[str, list[str]]],
        required_audience: Optional[Union[str, list[str]]],
        separator: str = " "
) -> bool:
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
    :params separator: separator string, space by default
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
    if (isinstance(scope, list) and isinstance(audience, list) and isinstance(required_scope, list) and isinstance(required_audience, list)):
        scope = [str(it) for it in scope]
        audience = [str(it) for it in audience]
        required_scope = [str(it) for it in required_scope]
        required_audience = [str(it) for it in required_audience]
        req_scope_present = all(elem in scope for elem in required_scope)
        req_audience_present = all(elem in audience for elem in required_audience)
        return req_scope_present and req_audience_present
    elif (isinstance(scope, str) and isinstance(audience, str) and isinstance(required_scope, str) and isinstance(required_audience, str)):
        scope = str(scope)
        audience = str(audience)
        required_scope = str(required_scope)
        required_audience = str(required_audience)
        req_scope_present = all(elem in scope.split(separator) for elem in required_scope.split(separator))
        req_audience_present = all(elem in audience.split(separator) for elem in required_audience.split(separator))
        return req_scope_present and req_audience_present
    elif (isinstance(scope, list) and isinstance(audience, list) and isinstance(required_scope, str) and isinstance(required_audience, str)):
        scope = [str(it) for it in scope]
        audience = [str(it) for it in audience]
        required_scope = str(required_scope)
        required_audience = str(required_audience)
        req_scope_present = all(elem in scope for elem in required_scope.split(separator))
        req_audience_present = all(elem in audience for elem in required_audience.split(separator))
        return req_scope_present and req_audience_present
    elif (isinstance(scope, str) and isinstance(audience, str) and isinstance(required_scope, list) and isinstance(required_audience, list)):
        scope = str(scope)
        audience = str(audience)
        required_scope = [str(it) for it in required_scope]
        required_audience = [str(it) for it in required_audience]
        req_scope_present = all(elem in scope.split(separator) for elem in required_scope)
        req_audience_present = all(elem in audience.split(separator) for elem in required_audience)
        return req_scope_present and req_audience_present
    else:
        return False


def generate_uuid() -> str:
    return str(uuid()).replace('-', '').lower()


def generate_uuid_bytes() -> bytes:
    return uuid().bytes


def str_to_date(string: str) -> Optional[datetime.datetime]:
    """ Converts a RFC-1123 string to the corresponding datetime value.

    :param string: the RFC-1123 string to convert to datetime value.
    """
    return datetime.datetime.strptime(string, DATE_FORMAT) if string else None


def val_to_space_sep_str(vallist: list[str]) -> str:
    """ Converts a list of values into a string of space separated values

    :param vallist: the list of values to convert into string
    :return: the string of space separated values or the value initially passed as parameter
    """
    try:
        if isinstance(vallist, list):
            return str(" ".join(vallist))
        else:
            return str(vallist)
    except Exception:
        return ''


def date_to_str(date: datetime.datetime) -> Optional[str]:
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


def render_json(*args, **kwargs) -> str:
    """ Render a list or a dict as a JSON-formatted string. """
    if args and isinstance(args[0], list):
        data = args[0]
    elif isinstance(kwargs, dict):
        data = kwargs
    else:
        raise ValueError("Error while serializing object to JSON-formatted string: supported input types are list or dict.")
    return json.dumps(data, cls=APIEncoder)


def datetime_parser(dct: dict[Any, Any]) -> dict[Any, Any]:
    """ datetime parser
    """
    for k, v in list(dct.items()):
        if isinstance(v, str) and re.search(" UTC", v):
            try:
                dct[k] = datetime.datetime.strptime(v, DATE_FORMAT)
            except Exception:
                pass
    return dct


def parse_response(data: Union[str, bytes, bytearray]) -> Any:
    """
    JSON render function
    """
    if isinstance(data, (bytes, bytearray)):
        data = data.decode('utf-8')

    return json.loads(data, object_hook=datetime_parser)


def execute(cmd: str) -> tuple[int, str, str]:
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

    result = process.communicate()
    (out, err) = result
    exitcode = process.returncode
    return exitcode, out.decode(encoding='utf-8'), err.decode(encoding='utf-8')


def rse_supported_protocol_domains() -> list[str]:
    """ Returns a list with all supported RSE protocol domains."""
    return ['lan', 'wan']


def grouper(iterable: 'Iterable[Any]', n: int, fillvalue: Optional[object] = None) -> zip_longest:
    """ Collect data into fixed-length chunks or blocks """
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def chunks(iterable, n):
    """
    Yield successive n-sized chunks from l.
    """
    if isinstance(iterable, list):
        for i in range(0, len(iterable), n):
            yield iterable[i:i + n]
    else:
        it = iter(iterable)
        while True:
            chunk = list(itertools.islice(it, n))
            if not chunk:
                return
            yield chunk


def dict_chunks(dict_: dict[Any, Any], n: int) -> 'Iterator[dict[Any, Any]]':
    """
    Iterate over the dictionary in groups of the requested size
    """
    it = iter(dict_)
    for _ in range(0, len(dict_), n):
        yield {k: dict_[k] for k in itertools.islice(it, n)}


def my_key_generator(namespace: str, fn: 'Callable', **kw) -> 'Callable[..., str]':
    """
    Customized key generator for dogpile
    """
    fname = fn.__name__

    def generate_key(*arg, **kw) -> str:
        return namespace + "_" + fname + "_".join(str(s) for s in filter(None, arg))

    return generate_key


NonDeterministicPFNAlgorithmsT = TypeVar('NonDeterministicPFNAlgorithmsT', bound='NonDeterministicPFNAlgorithms')


class NonDeterministicPFNAlgorithms(PolicyPackageAlgorithms):
    """
    Handle PFN construction for non-deterministic RSEs, including registration of algorithms
    from policy packages
    """

    _algorithm_type = 'non_deterministic_pfn'

    def __init__(self, vo: str = DEFAULT_VO) -> None:
        """
        Initialises a non-deterministic PFN construction object
        """
        super().__init__()

        self.vo = vo

    def construct_non_deterministic_pfn(self, dsn: str, scope: Optional[str], filename: str, naming_convention: str) -> str:
        """
        Calls the correct algorithm to generate a non-deterministic PFN
        """
        fn = None
        if naming_convention == 'def':
            fn = super()._get_default_algorithm(NonDeterministicPFNAlgorithms._algorithm_type, self.vo)
        if fn is None:
            fn = self.get_algorithm(naming_convention)
        return fn(dsn, scope, filename)

    @classmethod
    def supports(cls: type[NonDeterministicPFNAlgorithmsT], naming_convention: str) -> bool:
        """
        Checks whether a non-deterministic PFN algorithm is supported
        """
        return super()._supports(cls._algorithm_type, naming_convention)

    @classmethod
    def _module_init_(cls: type[NonDeterministicPFNAlgorithmsT]) -> None:
        """
        Registers the included non-deterministic PFN algorithms
        """
        cls.register('def', cls.construct_non_deterministic_pfn_default)

    @classmethod
    def get_algorithm(cls: type[NonDeterministicPFNAlgorithmsT], naming_convention: str) -> 'Callable[[str, Optional[str], str], str]':
        """
        Looks up a non-deterministic PFN algorithm by name
        """
        return super()._get_one_algorithm(cls._algorithm_type, naming_convention)

    @classmethod
    def register(cls: type[NonDeterministicPFNAlgorithmsT], name: str, fn_construct_non_deterministic_pfn: 'Callable[[str, Optional[str], str], Optional[str]]') -> None:
        """
        Register a new non-deterministic PFN algorithm
        """
        algorithm_dict = {name: fn_construct_non_deterministic_pfn}
        super()._register(cls._algorithm_type, algorithm_dict)

    @staticmethod
    def __strip_dsn(dsn: str) -> str:
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

    @staticmethod
    def __strip_tag(tag: str) -> str:
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

    @staticmethod
    def construct_non_deterministic_pfn_default(dsn: str, scope: Optional[str], filename: str) -> str:
        """
        Defines relative PFN for new replicas. This method
        contains DQ2 convention. To be used for non-deterministic sites.
        Method imported from DQ2.

        @return: relative PFN for new replica.
        @rtype: str
        """
        # check how many dots in dsn
        fields = dsn.split('.')
        nfields = len(fields)

        if nfields == 0:
            return '/other/other/%s' % (filename)
        elif nfields == 1:
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/other/%s/%s' % (stripped_dsn, filename)
        elif nfields == 2:
            project = fields[0]
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s' % (project, stripped_dsn, filename)
        elif nfields < 5 or re.match('user*|group*', fields[0]):
            project = fields[0]
            f2 = fields[1]
            f3 = fields[2]
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s/%s/%s' % (project, f2, f3, stripped_dsn, filename)
        else:
            project = fields[0]
            dataset_type = fields[4]
            if nfields == 5:
                tag = 'other'
            else:
                tag = NonDeterministicPFNAlgorithms.__strip_tag(fields[-1])
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s/%s/%s' % (project, dataset_type, tag, stripped_dsn, filename)


NonDeterministicPFNAlgorithms._module_init_()


def construct_non_deterministic_pfn(dsn: str, scope: Optional[str], filename: str, naming_convention: Optional[str] = None, vo: str = DEFAULT_VO) -> str:
    """
    Applies non-deterministic PFN convention to the given replica.
    use the naming_convention to call the actual function which will do the job.
    Rucio administrators can potentially register additional PFN generation algorithms,
    which are not implemented inside this main rucio repository, so changing the
    argument list must be done with caution.
    """
    pfn_algorithms = NonDeterministicPFNAlgorithms(vo)
    if naming_convention is None or not NonDeterministicPFNAlgorithms.supports(naming_convention):
        naming_convention = 'def'
    return pfn_algorithms.construct_non_deterministic_pfn(dsn, scope, filename, naming_convention)


def clean_pfns(pfns: 'Iterable[str]') -> list[str]:
    res = []
    for pfn in pfns:
        if pfn.startswith('srm'):
            pfn = re.sub(':[0-9]+/', '/', pfn)
            pfn = re.sub(r'/srm/managerv1\?SFN=', '', pfn)
            pfn = re.sub(r'/srm/v2/server\?SFN=', '', pfn)
            pfn = re.sub(r'/srm/managerv2\?SFN=', '', pfn)
        if '?GoogleAccessId' in pfn:
            pfn = pfn.split('?GoogleAccessId')[0]
        if '?X-Amz' in pfn:
            pfn = pfn.split('?X-Amz')[0]
        res.append(pfn)
    res.sort()
    return res


ScopeExtractionAlgorithmsT = TypeVar('ScopeExtractionAlgorithmsT', bound='ScopeExtractionAlgorithms')


class ScopeExtractionAlgorithms(PolicyPackageAlgorithms):
    """
    Handle scope extraction algorithms
    """

    _algorithm_type = 'scope'

    def __init__(self, vo: str = DEFAULT_VO) -> None:
        """
        Initialises scope extraction algorithms object
        """
        super().__init__()

        self.vo = vo

    def extract_scope(self, did: str, scopes: Optional['Sequence[str]'], extract_scope_convention: str) -> 'Sequence[str]':
        """
        Calls the correct algorithm for scope extraction
        """
        fn = None
        if extract_scope_convention == 'def':
            fn = super()._get_default_algorithm(ScopeExtractionAlgorithms._algorithm_type, self.vo)
        if fn is None:
            fn = self.get_algorithm(extract_scope_convention)
        return fn(did, scopes)

    @classmethod
    def supports(cls: type[ScopeExtractionAlgorithmsT], extract_scope_convention: str) -> bool:
        """
        Checks whether the specified scope extraction algorithm is supported
        """
        return super()._supports(cls._algorithm_type, extract_scope_convention)

    @classmethod
    def _module_init_(cls: type[ScopeExtractionAlgorithmsT]) -> None:
        """
        Registers the included scope extraction algorithms
        """
        cls.register('def', cls.extract_scope_default)
        cls.register('dirac', cls.extract_scope_dirac)

    @classmethod
    def get_algorithm(cls: type[ScopeExtractionAlgorithmsT], extract_scope_convention: str) -> 'Callable[[str, Optional[Sequence[str]]], Sequence[str]]':
        """
        Looks up a scope extraction algorithm by name
        """
        return super()._get_one_algorithm(cls._algorithm_type, extract_scope_convention)

    @classmethod
    def register(cls: type[ScopeExtractionAlgorithmsT], name: str, fn_extract_scope: 'Callable[[str, Optional[Sequence[str]]], Sequence[str]]') -> None:
        """
        Registers a new scope extraction algorithm
        """
        algorithm_dict = {name: fn_extract_scope}
        super()._register(cls._algorithm_type, algorithm_dict)

    @staticmethod
    def extract_scope_default(did: str, scopes: Optional['Sequence[str]']) -> 'Sequence[str]':
        """
        Default scope extraction algorithm. Extracts the scope from the DID.

        :param did: The DID to extract the scope from.
        :param scopes: Not used in the default algorithm.

        :returns: A tuple containing the extracted scope and the name.
        """

        # This block is ATLAS specific, to be removed in the future.
        # More info at https://github.com/rucio/rucio/pull/7521
        if did.find(':') == -1:
            scope = did.split('.')[0]
            if did.startswith('user') or did.startswith('group'):
                scope = ".".join(did.split('.')[0:2])
            if did.endswith('/'):
                did = did[:-1]
            return scope, did

        parts = did.split(':')
        if len(parts) != 2:
            msg = f"Cannot extract scope and name from DID {did}. The DID should have exactly one colon but found {len(parts)} colons."
            raise RucioException(msg)
        scope, name = parts
        if not scope or not name:
            msg = f"Cannot extract scope and name from DID {did}. Found empty scope or name."
            raise RucioException(msg)
        return scope, name

    @staticmethod
    def extract_scope_dirac(did: str, scopes: Optional['Sequence[str]']) -> 'Sequence[str]':
        # Default dirac scope extract algorithm. Scope is the second element in the LFN or the first one (VO name)
        # if only one element is the result of a split.
        elem = did.rstrip('/').split('/')
        if len(elem) > 2:
            scope = elem[2]
        else:
            scope = elem[1]
        return scope, did


ScopeExtractionAlgorithms._module_init_()


def extract_scope(
        did: str,
        scopes: Optional['Sequence[str]'] = None,
        default_extract: str = 'def',
        vo: str = DEFAULT_VO
) -> 'Sequence[str]':
    scope_extraction_algorithms = ScopeExtractionAlgorithms(vo)
    extract_scope_convention = config_get('common', 'extract_scope', False, None) or config_get('policy', 'extract_scope', False, None)
    if extract_scope_convention is None or not ScopeExtractionAlgorithms.supports(extract_scope_convention):
        extract_scope_convention = default_extract
    return scope_extraction_algorithms.extract_scope(did, scopes, extract_scope_convention)


def pid_exists(pid: int) -> bool:
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


def sizefmt(num: Union[int, float, None], human: bool = True) -> str:
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


def get_tmp_dir() -> str:
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


def is_archive(name: str) -> bool:
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


def resolve_ips(hostname: str) -> list[str]:
    try:
        ipaddress.ip_address(hostname)
        return [hostname]
    except ValueError:
        pass
    try:
        addrinfo = socket.getaddrinfo(hostname, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        return [ai[4][0] for ai in addrinfo]
    except socket.gaierror:
        pass
    return []


def resolve_ip(hostname: str) -> str:
    ips = resolve_ips(hostname)
    if ips:
        return ips[0]
    return hostname


def ssh_sign(private_key: str, message: str) -> str:
    """
    Sign a string message using the private key.

    :param private_key: The SSH RSA private key as a string.
    :param message: The message to sign as a string.
    :return: Base64 encoded signature as a string.
    """
    encoded_message = message.encode()
    if not EXTRA_MODULES['paramiko']:
        raise MissingModuleException('The paramiko module is not installed or faulty.')
    sio_private_key = StringIO(private_key)
    priv_k = RSAKey.from_private_key(sio_private_key)
    sio_private_key.close()
    signature_stream = priv_k.sign_ssh_data(encoded_message)
    signature_stream.rewind()
    base64_encoded = base64.b64encode(signature_stream.get_remainder())
    base64_encoded = base64_encoded.decode()
    return base64_encoded


def make_valid_did(lfn_dict: LFNDict) -> LFNDict:
    """
    When managing information about a LFN (such as in `rucio upload` or
    the RSE manager's upload), we add the `filename` attribute to record
    the name of the file on the local disk in addition to the remainder
    of the DID information.

    This function will take that python dictionary, and strip out the
    additional `filename` key.  If this is not done, then the dictionary
    will not pass the DID JSON schema validation.
    """
    if 'filename' not in lfn_dict:
        return lfn_dict

    lfn_copy = dict(lfn_dict)
    lfn_copy['name'] = lfn_copy.get('name', lfn_copy['filename'])
    del lfn_copy['filename']
    return lfn_copy  # type: ignore


def send_trace(trace: TraceDict, trace_endpoint: str, user_agent: str, retries: int = 5) -> int:
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


def add_url_query(url: str, query: dict[str, str]) -> str:
    """
    Add a new dictionary to URL parameters

    :param url: The existing URL
    :param query: A dictionary containing key/value pairs to be added to the URL
    :return: The expanded URL with the new query parameters
    """

    url_parts = list(urlparse(url))
    mod_query = dict(parse_qsl(url_parts[4]))
    mod_query.update(query)
    url_parts[4] = urlencode(mod_query)
    return urlunparse(url_parts)


def get_bytes_value_from_string(input_string: str) -> Union[bool, int]:
    """
    Get bytes from a string that represents a storage value and unit

    :param input_string: String containing a value and an unit
    :return: Integer value representing the value in bytes
    """
    unit_multipliers = {
        'b': 1,
        'kb': 10**3,
        'mb': 10**6,
        'gb': 10**9,
        'tb': 10**12,
        'pb': 10**15,
    }

    result = re.findall(r'^([0-9]+)([A-Za-z]+)$', input_string)
    if result:
        value = int(result[0][0])
        unit = result[0][1].lower()
        multiplier = unit_multipliers.get(unit)
        if multiplier is None:
            return False
        return value * multiplier
    return False


def parse_did_filter_from_string(input_string: str) -> tuple[dict[str, Any], str]:
    """
    Parse DID filter options in format 'length<3,type=all' from string.

    :param input_string: String containing the filter options.
    :return: filter dictionary and type as string.
    """
    filters = {}
    type_ = 'collection'
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
                if value.upper() in ['ALL', 'COLLECTION', 'CONTAINER', 'DATASET', 'FILE']:  # type: ignore
                    type_ = value.lower()  # type: ignore
                else:
                    raise InvalidType('{0} is not a valid type. Valid types are {1}'.format(value, ['ALL', 'COLLECTION', 'CONTAINER', 'DATASET', 'FILE']))
            elif key in ('length.gt', 'length.lt', 'length.gte', 'length.lte', 'length'):
                try:
                    value = int(value)  # type: ignore
                    filters[key] = value
                except ValueError:
                    raise ValueError('Length has to be an integer value.')
                filters[key] = value
            elif isinstance(value, str):
                if value.lower() == 'true':
                    value = '1'
                elif value.lower() == 'false':
                    value = '0'
                filters[key] = value
            else:
                filters[key] = value

    return filters, type_


def parse_did_filter_from_string_fe(
        input_string: str,
        name: str = '*',
        type: str = 'collection',
        omit_name: bool = False
) -> tuple[list[dict[str, Any]], str]:
    """
    Parse DID filter string for the filter engine (fe).

    Should adhere to the following conventions:
    - ';' represents the logical OR operator
    - ',' represents the logical AND operator
    - all operators belong to set of (<=, >=, ==, !=, >, <, =)
    - there should be no duplicate key+operator criteria.

    One sided and compound inequalities are supported.

    Sanity checking of input is left to the filter engine.

    :param input_string: String containing the filter options.
    :param name: DID name.
    :param type: The type of the DID: all(container, dataset, file), collection(dataset or container), dataset, container.
    :param omit_name: omit addition of name to filters.
    :return: list of dictionaries with each dictionary as a separate OR expression.
    """
    # lookup table unifying all comprehended operators to a nominal suffix.
    # note that the order matters as the regex engine is eager, e.g. don't want to evaluate '<=' as '<' and '='.
    operators_suffix_lut = OrderedDict({
        '<=': 'lte',
        '>=': 'gte',
        '==': '',
        '!=': 'ne',
        '>': 'gt',
        '<': 'lt',
        '=': ''
    })

    # lookup table mapping operator opposites, used to reverse compound inequalities.
    operator_opposites_lut = {
        'lt': 'gt',
        'lte': 'gte'
    }
    operator_opposites_lut.update({op2: op1 for op1, op2 in operator_opposites_lut.items()})

    filters = []
    if input_string:
        or_groups = list(filter(None, input_string.split(';')))     # split <input_string> into OR clauses
        for or_group in or_groups:
            or_group = or_group.strip()
            and_groups = list(filter(None, or_group.split(',')))    # split <or_group> into AND clauses
            and_group_filters = {}
            for and_group in and_groups:
                and_group = and_group.strip()
                # tokenise this AND clause using operators as delimiters.
                tokenisation_regex = "({})".format('|'.join(operators_suffix_lut.keys()))
                and_group_split_by_operator = list(filter(None, re.split(tokenisation_regex, and_group)))
                if len(and_group_split_by_operator) == 3:       # this is a one-sided inequality or expression
                    key, operator, value = [token.strip() for token in and_group_split_by_operator]

                    # substitute input operator with the nominal operator defined by the LUT, <operators_suffix_LUT>.
                    operator_mapped = operators_suffix_lut.get(operator)

                    filter_key_full = key
                    if operator_mapped is not None:
                        if operator_mapped:
                            filter_key_full = "{}.{}".format(key, operator_mapped)
                    else:
                        raise DIDFilterSyntaxError("{} operator not understood.".format(operator_mapped))

                    if filter_key_full in and_group_filters:
                        raise DuplicateCriteriaInDIDFilter(filter_key_full)
                    else:
                        and_group_filters[filter_key_full] = value
                elif len(and_group_split_by_operator) == 5:     # this is a compound inequality
                    value1, operator1, key, operator2, value2 = [token.strip() for token in and_group_split_by_operator]

                    # substitute input operator with the nominal operator defined by the LUT, <operators_suffix_LUT>.
                    operator1_mapped = operator_opposites_lut.get(operators_suffix_lut.get(operator1))
                    operator2_mapped = operators_suffix_lut.get(operator2)

                    filter_key1_full = filter_key2_full = key
                    if operator1_mapped is not None and operator2_mapped is not None:
                        if operator1_mapped:    # ignore '' operator (maps from equals)
                            filter_key1_full = "{}.{}".format(key, operator1_mapped)
                        if operator2_mapped:    # ignore '' operator (maps from equals)
                            filter_key2_full = "{}.{}".format(key, operator2_mapped)
                    else:
                        raise DIDFilterSyntaxError("{} operator not understood.".format(operator_mapped))

                    if filter_key1_full in and_group_filters:
                        raise DuplicateCriteriaInDIDFilter(filter_key1_full)
                    else:
                        and_group_filters[filter_key1_full] = value1
                    if filter_key2_full in and_group_filters:
                        raise DuplicateCriteriaInDIDFilter(filter_key2_full)
                    else:
                        and_group_filters[filter_key2_full] = value2
                else:
                    raise DIDFilterSyntaxError(and_group)

            # add name key to each AND clause if it hasn't already been populated from the filter and <omit_name> not set.
            if not omit_name and 'name' not in and_group_filters:
                and_group_filters['name'] = name

            filters.append(and_group_filters)
    else:
        if not omit_name:
            filters.append({
                'name': name
            })
    return filters, type


def parse_replicas_from_file(path: "FileDescriptorOrPath") -> Any:
    """
    Parses the output of list_replicas from a json or metalink file
    into a dictionary. Metalink parsing is tried first and if it fails
    it tries to parse json.

    :param path: the path to the input file

    :returns: a list with a dictionary for each file
    """
    with open(path) as fp:
        try:
            root = ElementTree.parse(fp).getroot()  # noqa: S314
            return parse_replicas_metalink(root)
        except ElementTree.ParseError as xml_err:
            try:
                return json.load(fp)
            except ValueError as json_err:
                raise MetalinkJsonParsingError(path, xml_err, json_err)


def parse_replicas_from_string(string: str) -> Any:
    """
    Parses the output of list_replicas from a json or metalink string
    into a dictionary. Metalink parsing is tried first and if it fails
    it tries to parse json.

    :param string: the string to parse

    :returns: a list with a dictionary for each file
    """
    try:
        root = ElementTree.fromstring(string)  # noqa: S314
        return parse_replicas_metalink(root)
    except ElementTree.ParseError as xml_err:
        try:
            return json.loads(string)
        except ValueError as json_err:
            raise MetalinkJsonParsingError(string, xml_err, json_err)


def parse_replicas_metalink(root: ElementTree.Element) -> list[dict[str, Any]]:
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


def get_thread_with_periodic_running_function(
        interval: Union[int, float],
        action: 'Callable[..., Any]',
        graceful_stop: threading.Event
) -> threading.Thread:
    """
    Get a thread where a function runs periodically.

    :param interval: Interval in seconds when the action function should run.
    :param action: Function, that should run periodically.
    :param graceful_stop: Threading event used to check for graceful stop.
    """
    def start():
        while not graceful_stop.is_set():
            starttime = time.time()
            action()
            time.sleep(interval - (time.time() - starttime))
    t = threading.Thread(target=start)
    return t


def run_cmd_process(cmd: str, timeout: int = 3600) -> tuple[int, str]:
    """
    shell command parser with timeout

    :param cmd: shell command as a string
    :param timeout: in seconds

    :return: stdout xor stderr, and errorcode
    """

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid, universal_newlines=True)

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            # Kill the whole process group since we're using shell=True.
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
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


def gateway_update_return_dict(
        dictionary: dict[str, Any],
        session: Optional["Session"] = None
) -> dict[str, Any]:
    """
    Ensure that rse is in a dictionary returned from core

    :param dictionary: The dictionary to edit
    :param session: The DB session to use
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
                dictionary[rse_str] = rucio.core.rse.get_rse_name(rse_id=dictionary[rse_id_str], session=session)

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


def setup_logger(
        module_name: Optional[str] = None,
        logger_name: Optional[str] = None,
        logger_level: Optional[int] = None,
        verbose: bool = False
) -> logging.Logger:
    '''
    Factory method to set logger with handlers.
    :param module_name: __name__ of the module that is calling this method
    :param logger_name: name of the logger, typically name of the module.
    :param logger_level: if not given, fetched from config.
    :param verbose: verbose option set in bin/rucio
    '''
    # helper method for cfg check
    def _force_cfg_log_level(cfg_option: str) -> bool:
        cfg_forced_modules = config_get('logging', cfg_option, raise_exception=False, default=None, clean_cached=True,
                                        check_config_table=False)
        if cfg_forced_modules and module_name is not None:
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
        logger_level = logging.INFO
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
    def add_handler(logger: logging.Logger) -> None:
        hdlr = logging.StreamHandler()

        def emit_decorator(fnc: 'Callable[..., Any]') -> 'Callable[..., Any]':
            def func(*args) -> 'Callable[..., Any]':
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


def daemon_sleep(
        start_time: float,
        sleep_time: float,
        graceful_stop: threading.Event,
        logger: "LoggerFunction" = logging.log
) -> None:
    """Sleeps a daemon the time provided by sleep_time"""
    end_time = time.time()
    time_diff = end_time - start_time
    if time_diff < sleep_time:
        logger(logging.INFO, 'Sleeping for a while :  %s seconds', (sleep_time - time_diff))
        graceful_stop.wait(sleep_time - time_diff)


class retry:  # noqa: N801
    """Retry callable object with configuragle number of attempts"""

    def __init__(self, func: 'Callable[..., Any]', *args, **kwargs):
        '''
        :param func: a method that should be executed with retries
        :param args: parameters of the func
        :param kwargs: key word arguments of the func
        '''
        self.func, self.args, self.kwargs = func, args, kwargs

    def __call__(self, mtries: int = 3, logger: "LoggerFunction" = logging.log) -> 'Callable[..., Any]':
        '''
        :param mtries: maximum number of attempts to execute the function
        :param logger: preferred logger
        '''
        attempt = mtries
        while attempt > 1:
            try:
                if logger:
                    logger(logging.DEBUG, '{}: Attempt {}'.format(self.func.__name__, mtries - attempt + 1))
                return self.func(*self.args, **self.kwargs)
            except Exception as e:
                if logger:
                    logger(logging.DEBUG, '{}: Attempt failed {}'.format(self.func.__name__, mtries - attempt + 1))
                    logger(logging.DEBUG, str(e))
                attempt -= 1
        return self.func(*self.args, **self.kwargs)


class StoreAndDeprecateWarningAction(argparse.Action):
    '''
    StoreAndDeprecateWarningAction is a descendant of :class:`argparse.Action`
    and represents a store action with a deprecated argument name.
    '''

    def __init__(self,
                 option_strings: 'Sequence[str]',
                 new_option_string: str,
                 dest: str,
                 **kwargs):
        """
        :param option_strings: all possible argument name strings
        :param new_option_string: the new option string which replaces the old
        :param dest: name of variable to store the value in
        :param kwargs: everything else
        """
        super(StoreAndDeprecateWarningAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            **kwargs)
        if new_option_string not in option_strings:
            raise ValueError("%s not supported as a string option." % new_option_string)
        self.new_option_string = new_option_string

    def __call__(self, parser, namespace, values, option_string: Optional[str] = None):
        if option_string and option_string != self.new_option_string:
            # The logger gets typically initialized after the argument parser
            # to set the verbosity of the logger. Thus using simple print to console.
            print("Warning: The commandline argument {} is deprecated! Please use {} in the future.".format(option_string, self.new_option_string))

        setattr(namespace, self.dest, values)


class StoreTrueAndDeprecateWarningAction(argparse._StoreConstAction):
    '''
    StoreAndDeprecateWarningAction is a descendant of :class:`argparse.Action`
    and represents a store action with a deprecated argument name.
    '''

    def __init__(self,
                 option_strings: 'Sequence[str]',
                 new_option_string: str,
                 dest: str,
                 default: bool = False,
                 required: bool = False,
                 help: Optional[str] = None):
        """
        :param option_strings: all possible argument name strings
        :param new_option_string: the new option string which replaces the old
        :param dest: name of variable to store the value in
        :param kwargs: everything else
        """
        super(StoreTrueAndDeprecateWarningAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            const=True,
            default=default,
            required=required,
            help=help)
        if new_option_string not in option_strings:
            raise ValueError("%s not supported as a string option." % new_option_string)
        self.new_option_string = new_option_string

    def __call__(self, parser, namespace, values, option_string: Optional[str] = None):
        super(StoreTrueAndDeprecateWarningAction, self).__call__(parser, namespace, values, option_string=option_string)
        if option_string and option_string != self.new_option_string:
            # The logger gets typically initialized after the argument parser
            # to set the verbosity of the logger. Thus using simple print to console.
            print("Warning: The commandline argument {} is deprecated! Please use {} in the future.".format(option_string, self.new_option_string))


class PriorityQueue:
    """
    Heap-based [1] priority queue which supports priority update operations

    It is used as a dictionary: pq['element'] = priority
    The element with the highest priority can be accessed with pq.top() or pq.pop(),
    depending on the desire to keep it in the heap or not.

    [1] https://en.wikipedia.org/wiki/Heap_(data_structure)
    """
    class ContainerSlot:
        def __init__(self, position: int, priority: int):
            self.pos = position
            self.prio = priority

    def __init__(self):
        self.heap = []
        self.container = {}

    def __len__(self):
        return len(self.heap)

    def __getitem__(self, item):
        return self.container[item].prio

    def __setitem__(self, key, value):
        if key in self.container:
            existing_prio = self.container[key].prio
            self.container[key].prio = value
            if value < existing_prio:
                self._priority_decreased(key)
            elif existing_prio < value:
                self._priority_increased(key)
        else:
            self.heap.append(key)
            self.container[key] = self.ContainerSlot(position=len(self.heap) - 1, priority=value)
            self._priority_decreased(key)

    def __contains__(self, item):
        return item in self.container

    def top(self):
        return self.heap[0]

    def pop(self):
        item = self.heap[0]
        self.container.pop(item)

        tmp_item = self.heap.pop()
        if self.heap:
            self.heap[0] = tmp_item
            self.container[tmp_item].pos = 0
            self._priority_increased(tmp_item)
        return item

    def _priority_decreased(self, item):
        heap_changed = False

        pos = self.container[item].pos
        pos_parent = (pos - 1) // 2
        while pos > 0 and self.container[self.heap[pos]].prio < self.container[self.heap[pos_parent]].prio:
            tmp_item, parent = self.heap[pos], self.heap[pos_parent] = self.heap[pos_parent], self.heap[pos]
            self.container[tmp_item].pos, self.container[parent].pos = self.container[parent].pos, self.container[tmp_item].pos

            pos = pos_parent
            pos_parent = (pos - 1) // 2

            heap_changed = True
        return heap_changed

    def _priority_increased(self, item):
        heap_changed = False
        heap_len = len(self.heap)
        pos = self.container[item].pos
        pos_child1 = 2 * pos + 1
        pos_child2 = 2 * pos + 2

        heap_restored = False
        while not heap_restored:
            # find minimum between item, child1, and child2
            if pos_child1 < heap_len and self.container[self.heap[pos_child1]].prio < self.container[self.heap[pos]].prio:
                pos_min = pos_child1
            else:
                pos_min = pos
            if pos_child2 < heap_len and self.container[self.heap[pos_child2]].prio < self.container[self.heap[pos_min]].prio:
                pos_min = pos_child2

            if pos_min != pos:
                _, tmp_item = self.heap[pos_min], self.heap[pos] = self.heap[pos], self.heap[pos_min]
                self.container[tmp_item].pos = pos

                pos = pos_min
                pos_child1 = 2 * pos + 1
                pos_child2 = 2 * pos + 2

                heap_changed = True
            else:
                heap_restored = True

        self.container[self.heap[pos]].pos = pos
        return heap_changed


class Availability:
    """
    This util class acts as a translator between the availability stored as
    integer and as boolean values.

    `None` represents a missing value. This lets a user update a specific value
    without altering the other ones. If it needs to be evaluated, it will
    correspond to `True`.
    """

    read = None
    write = None
    delete = None

    def __init__(
            self,
            read: Optional[bool] = None,
            write: Optional[bool] = None,
            delete: Optional[bool] = None
    ):
        self.read = read
        self.write = write
        self.delete = delete

    def __iter__(self):
        """
        The iterator provides the feature to unpack the values of this class.

        e.g. `read, write, delete = Availability(True, False, True)`

        :returns: An iterator over the values `read`, `write`, `delete`.
        """
        return iter((self.read, self.write, self.delete))

    def __repr__(self):
        return "Availability({}, {}, {})".format(self.read, self.write, self.delete)

    def __eq__(self, other):
        return self.read == other.read and self.write == other.write and self.delete == other.delete

    def __hash__(self):
        return hash(self.integer)

    @classmethod
    def from_integer(cls, n):
        """
        Returns a new Availability instance where the values are set to the
        corresponding bit values in the integer.

        :param n: The integer value to get the availabilities from.
        :returns: The corresponding Availability instance.
        """
        if n is None:
            return cls(None, None, None)

        return cls(
            (n >> 2) % 2 == 1,
            (n >> 1) % 2 == 1,
            (n >> 0) % 2 == 1
        )

    @property
    def integer(self):
        """
        Returns the corresponding integer for the instance values. The three
        least-significant bits correspond to the availability values.

        :returns: An integer corresponding to the availability values. `None`
            gets treated as `True`.
        """
        read_value = (self.read or self.read is None) * 4
        write_value = (self.write or self.write is None) * 2
        delete_value = (self.delete or self.delete is None) * 1

        return read_value + write_value + delete_value


def retrying(
        retry_on_exception: "Callable[[Exception], bool]",
        wait_fixed: int,
        stop_max_attempt_number: int
) -> "Callable[[Callable[..., T]], Callable[..., T]]":
    """
    Decorator which retries a function multiple times on certain types of exceptions.
    :param retry_on_exception: Function which takes an exception as argument and returns True if we must retry on this exception
    :param wait_fixed: the amount of time to wait in-between two tries
    :param stop_max_attempt_number: maximum number of allowed attempts
    """
    def _decorator(fn):
        @wraps(fn)
        def _wrapper(*args, **kwargs):
            attempt = 0
            while True:
                attempt += 1
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt >= stop_max_attempt_number:
                        raise
                    if not retry_on_exception(e):
                        raise
                time.sleep(wait_fixed / 1000.0)
        return _wrapper
    return _decorator


def deep_merge_dict(source: dict, destination: dict) -> dict:
    """Merge two dictionaries together recursively"""
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            deep_merge_dict(value, node)
        else:
            destination[key] = value

    return destination


def is_method_overridden(obj, base_cls, method_name):
    """
    Return True if `obj` (an instance of a subclass of `base_cls`) has overridden the given method_name from base_cls.
    That is, `type(obj).<method_name>` is not the same function object as `base_cls.<method_name>`.

    :param obj:         An instance of (a subclass of) base_cls.
    :param base_cls:    The base class which may define the method.
    :param method_name: Name of the method (str) to check.
    :returns:           Boolean, True if the subclass provides a real override.
    """
    if not hasattr(obj, method_name):
        return False
    if getattr(type(obj), method_name, None) is getattr(base_cls, method_name, None):  # Caring for bound/unbound cases
        return False
    return True


@cache
def get_transfer_schemas() -> dict[str, list[str]]:
    """
    Extend base schema map based on SRM HTTPS compatibility.
    """
    scheme_map = BASE_SCHEME_MAP
    if config_get_bool('transfers', 'srm_https_compatibility', raise_exception=False, default=False):
        scheme_map['srm'].append('https')
        scheme_map['https'].append('srm')
        scheme_map['srm'].append('davs')
        scheme_map['davs'].append('srm')

    return scheme_map


def wlcg_token_discovery() -> Optional[str]:
    """
    Discovers a WLCG bearer token from the environment, following the specified precedence.
    Specs: https://zenodo.org/records/3937438

    :returns: The discovered token (string), or None if no valid token is found.
    """
    user_id = os.geteuid()
    token = None

    # 1. Check BEARER_TOKEN environment variable
    token = os.environ.get('BEARER_TOKEN')
    if token is not None:
        token = token.strip()
        if token:
            return token

    # 2. Check BEARER_TOKEN_FILE environment variable
    token_file = os.environ.get('BEARER_TOKEN_FILE')
    if token_file:
        try:
            with open(token_file, 'r') as f:
                token = f.read().strip()
            if token:
                return token
        except FileNotFoundError:
            pass
        except Exception:
            return None

    # 3. Check $XDG_RUNTIME_DIR/bt_u$ID
    xdg_runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
    if xdg_runtime_dir:
        token_path = os.path.join(xdg_runtime_dir, f'bt_u{user_id}')
        try:
            with open(token_path, 'r') as f:
                token = f.read().strip()
            if token:
                return token
        except FileNotFoundError:
            pass
        except Exception:
            return None

    # 4. Check /tmp/bt_u$ID
    token_path = f'/tmp/bt_u{user_id}'
    try:
        with open(token_path, 'r') as f:
            token = f.read().strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    except Exception:
        return None

    # No valid token found
    return None


P = ParamSpec('P')
R = TypeVar('R')


def clone_function(
        func: 'Callable[P, R]',
        *,
        keep_wrapped: bool = False
) -> 'Callable[P, R]':
    """
    Create and return an **independent** copy of *func*.

    The copy shares the original code object and global namespace but has
    its **own** identity, making it safe to mutate attributes such as
    ``__doc__``, ``__name__`` or custom flags without affecting the source
    function.  Closure cells, default arguments and keyword‑only defaults
    are preserved.

    Parameters
    ----------
    func
        The function to duplicate.
    keep_wrapped
        If *True* retains the ``__wrapped__`` pointer that ``update_wrapper`` adds
        (useful when we *do* want wrapper semantics).  The default *False* removes
        it so that introspection treats the clone as a stand‑alone function.

    Returns
    -------
    Callable[P, R]
        A new callable that behaves exactly like *func*.  At runtime the
        object is a concrete ``types.FunctionType`` instance, but its static
        type mirrors the original callable’s *parameter list* and *return type*.

    Examples
    --------
    >>> def greet(name: str) -> str:
    ...     \"\"\"Return a greeting.\"\"\"
    ...     return f"Hello {name}"
    ...
    >>> new_greet = clone_function(greet)
    >>> new_greet.__doc__ = "An altered docstring."
    >>> greet.__doc__
    'Return a greeting.'
    >>> new_greet("world")
    'Hello world'
    """
    orig = cast('types.FunctionType', func)

    # 1. Re‑create the bare function object.
    new = types.FunctionType(
        orig.__code__,
        orig.__globals__,
        name=orig.__name__,
        argdefs=orig.__defaults__,
        closure=orig.__closure__,
    )

    # 2. Copy metadata such as ``__name__``, ``__qualname__``, ``__module__`` and ``__doc__``.
    update_wrapper(
        new,
        orig,
        assigned=(
            "__module__",
            "__name__",
            "__qualname__",
            "__doc__",
            "__annotations__",
        ),
        updated=(),
    )

    # 3. Shallow‑copy the attribute dict so later mutations are independent.
    new.__dict__.update(copy.copy(orig.__dict__))

    # 4. Copy the (kw‑only) default values if present.
    if orig.__kwdefaults__:
        new.__kwdefaults__ = orig.__kwdefaults__.copy()

    # 5. Detach from the original wrapper chain unless explicitly requested.
    if not keep_wrapped and hasattr(new, "__wrapped__"):
        delattr(new, "__wrapped__")

    return cast('Callable[P, R]', new)
