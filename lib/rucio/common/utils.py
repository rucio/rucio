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
import hashlib
import io
import ipaddress
import itertools
import json
import logging
import math
import mmap
import os
import os.path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import zlib
from collections import OrderedDict
from collections.abc import Callable, Sequence
from enum import Enum
from functools import partial, wraps
from io import StringIO
from itertools import zip_longest
from typing import TYPE_CHECKING, Optional, TypeVar
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from uuid import uuid4 as uuid
from xml.etree import ElementTree

import requests

from rucio.common.config import config_get, config_has_section
from rucio.common.exception import ConfigNotFound, DIDFilterSyntaxError, DuplicateCriteriaInDIDFilter, InputValidationError, InvalidType, MetalinkJsonParsingError, MissingModuleException, PolicyPackageVersionError, RucioException
from rucio.common.extra import import_extras
from rucio.common.plugins import PolicyPackageAlgorithms
from rucio.common.types import InternalAccount, InternalScope

EXTRA_MODULES = import_extras(['paramiko'])

if EXTRA_MODULES['paramiko']:
    try:
        from paramiko import RSAKey
    except Exception:
        EXTRA_MODULES['paramiko'] = False

if TYPE_CHECKING:
    T = TypeVar('T')


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


def invert_dict(d):
    """
    Invert the dictionary.
    CAUTION: this function is not deterministic unless the input dictionary is one-to-one mapping.

    :param d: source dictionary
    :returns: dictionary {value: key for key, value in d.items()}
    """
    return {value: key for key, value in d.items()}


def dids_as_dicts(did_list):
    """
    Converts list of DIDs to list of dictionaries
    :param did_list: list of DIDs as either "scope:name" or {"scope":"scope", "name","name"}
    :returns: list of dictionaries {"scope":"scope", "name","name"}
    """
    out = []
    for did in did_list:
        if isinstance(did, str):
            scope, name = did.split(":", 1)
            did = dict(scope=scope, name=name)
        if isinstance(did, dict):
            if not ("name" in did and "scope" in did):
                raise ValueError("Scope or name missing in: %s" % (did,))
        else:
            raise ValueError("Can not convert item %s (%s) to a DID" % (did, type(did)))
        out.append(did)
    return out


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


def all_oidc_req_claims_present(scope, audience, required_scope, required_audience, separator=" "):
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
    A simple function to check whether a checksum algorithm is supported.
    Relies on GLOBALLY_SUPPORTED_CHECKSUMS to allow for expandability.

    :param checksum_name: The name of the checksum to be verified.
    :returns: True if checksum_name is in GLOBALLY_SUPPORTED_CHECKSUMS list, False otherwise.
    """

    return checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS


def set_preferred_checksum(checksum_name):
    """
    A simple function to check whether a checksum algorithm is supported.
    Relies on GLOBALLY_SUPPORTED_CHECKSUMS to allow for expandability.

    :param checksum_name: The name of the checksum to be verified.
    :returns: True if checksum_name is in GLOBALLY_SUPPORTED_CHECKSUMS list, False otherwise.
    """
    if is_checksum_valid(checksum_name):
        global PREFERRED_CHECKSUM
        PREFERRED_CHECKSUM = checksum_name


def adler32(file):
    """
    An Adler-32 checksum is obtained by calculating two 16-bit checksums A and B
    and concatenating their bits into a 32-bit integer. A is the sum of all bytes in the
    stream plus one, and B is the sum of the individual values of A from each step.

    :param file: file name
    :returns: Hexified string, padded to 8 values.
    """

    # adler starting value is _not_ 0
    adler = 1

    can_mmap = False
    # try:
    #    with open(file, 'r+b') as f:
    #        can_mmap = True
    # except:
    #    pass

    try:
        # use mmap if possible
        if can_mmap:
            with open(file, 'r+b') as f:
                m = mmap.mmap(f.fileno(), 0)
                # partial block reads at slightly increased buffer sizes
                for block in iter(partial(m.read, io.DEFAULT_BUFFER_SIZE * 8), b''):
                    adler = zlib.adler32(block, adler)
        else:
            with open(file, 'rb') as f:
                # partial block reads at slightly increased buffer sizes
                for block in iter(partial(f.read, io.DEFAULT_BUFFER_SIZE * 8), b''):
                    adler = zlib.adler32(block, adler)

    except Exception as e:
        raise Exception('FATAL - could not get Adler-32 checksum of file %s: %s' % (file, e))

    # backflip on 32bit -- can be removed once everything is fully migrated to 64bit
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
        bytes_ = f.read()  # read entire file as bytes
        readable_hash = hashlib.sha256(bytes_).hexdigest()
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


def _next_pow2(num):
    if not num:
        return 0
    return math.ceil(math.log2(num))


def _bittorrent_v2_piece_length_pow2(file_size: int) -> int:
    """
    Automatically chooses the `piece size` so that `piece layers`
    is kept small(er) than usually. This is a balancing act:
    having a big piece_length requires more work on bittorrent client
    side to validate hashes, but having it small requires more
    place to store the `piece layers` in the database.

    Returns the result as the exponent 'x' for power of 2.
    To get the actual length in bytes, the caller should compute 2^x.
    """

    # by the bittorrent v2 specification, the piece size is equal to block size = 16KiB
    min_piece_len_pow2 = 14  # 2 ** 14 == 16 KiB
    if not file_size:
        return min_piece_len_pow2
    # Limit the maximum size of pieces_layers hash chain for bittorrent v2,
    # because we'll have to store it in the database
    max_pieces_layers_size_pow2 = 20  # 2 ** 20 == 1 MiB
    # sha256 requires 2 ** 5 == 32 Bytes == 256 bits
    hash_size_pow2 = 5

    # The closest power of two bigger than the file size
    file_size_pow2 = _next_pow2(file_size)

    # Compute the target size for the 'pieces layers' in the torrent
    # (as power of two: the closest power-of-two smaller than the number)
    # Will cap at max_pieces_layers_size for files larger than 1TB.
    target_pieces_layers_size = math.sqrt(file_size)
    target_pieces_layers_size_pow2 = min(math.floor(math.log2(target_pieces_layers_size)), max_pieces_layers_size_pow2)
    target_piece_num_pow2 = max(target_pieces_layers_size_pow2 - hash_size_pow2, 0)

    piece_length_pow2 = max(file_size_pow2 - target_piece_num_pow2, min_piece_len_pow2)
    return piece_length_pow2


def bittorrent_v2_piece_length(file_size: int) -> int:
    return 2 ** _bittorrent_v2_piece_length_pow2(file_size)


def bittorrent_v2_merkle_sha256(file) -> tuple[bytes, bytes, int]:
    """
    Compute the .torrent v2 hash tree for the given file.
    (http://www.bittorrent.org/beps/bep_0052.html)
    In particular, it will return the root of the merkle hash
    tree of the file, the 'piece layers' as described in the
    previous BEP, and the chosen `piece size`

    This function will read the file in chunks of 16KiB
    (which is the imposed block size by bittorrent v2) and compute
    the sha256 hash of each block. When enough blocks are read
    to form a `piece`, will compute the merkle hash root of the
    piece from the hashes of its blocks. At the end, the hashes
    of pieces are combined to create the global pieces_root.
    """

    # by the bittorrent v2 specification, the block size and the
    # minimum piece size are both fixed to 16KiB
    block_size = 16384
    block_size_pow2 = 14  # 2 ** 14 == 16 KiB
    # sha256 requires 2 ** 5 == 32 Bytes == 256 bits
    hash_size = 32

    def _merkle_root(leafs: list[bytes], nb_levels: int, padding: bytes) -> bytes:
        """
        Build the root of the merkle hash tree from the (possibly incomplete) leafs layer.
        If len(leafs) < 2 ** nb_levels, it will be padded with the padding repeated as many times
        as needed to have 2 ** nb_levels leafs in total.
        """
        nodes = copy.copy(leafs)
        level = nb_levels

        while level > 0:
            for i in range(2 ** (level - 1)):
                node1 = nodes[2 * i] if 2 * i < len(nodes) else padding
                node2 = nodes[2 * i + 1] if 2 * i + 1 < len(nodes) else padding
                h = hashlib.sha256(node1)
                h.update(node2)
                if i < len(nodes):
                    nodes[i] = h.digest()
                else:
                    nodes.append(h.digest())
            level -= 1
        return nodes[0] if nodes else padding

    file_size = os.stat(file).st_size
    piece_length_pow2 = _bittorrent_v2_piece_length_pow2(file_size)

    block_per_piece_pow2 = piece_length_pow2 - block_size_pow2
    piece_length = 2 ** piece_length_pow2
    block_per_piece = 2 ** block_per_piece_pow2
    piece_num = math.ceil(file_size / piece_length)

    remaining = file_size
    remaining_in_block = min(file_size, block_size)
    block_hashes = []
    piece_hashes = []
    current_hash = hashlib.sha256()
    block_padding = bytes(hash_size)
    with open(file, 'rb') as f:
        while True:
            data = f.read(remaining_in_block)
            if not data:
                break

            current_hash.update(data)

            remaining_in_block -= len(data)
            remaining -= len(data)

            if not remaining_in_block:
                block_hashes.append(current_hash.digest())
                if len(block_hashes) == block_per_piece or not remaining:
                    piece_hashes.append(_merkle_root(block_hashes, nb_levels=block_per_piece_pow2, padding=block_padding))
                    block_hashes = []
                current_hash = hashlib.sha256()
                remaining_in_block = min(block_size, remaining)

            if not remaining:
                break

    if remaining or remaining_in_block or len(piece_hashes) != piece_num:
        raise RucioException(f'Error while computing merkle sha256 of {file}')

    piece_padding = _merkle_root([], nb_levels=block_per_piece_pow2, padding=block_padding)
    pieces_root = _merkle_root(piece_hashes, nb_levels=_next_pow2(piece_num), padding=piece_padding)
    pieces_layers = b''.join(piece_hashes) if len(piece_hashes) > 1 else b''

    return pieces_root, pieces_layers, piece_length


def merkle_sha256(file) -> str:
    """
    The root of the sha256 merkle hash tree with leaf size of 16 KiB.
    """
    pieces_root, _, _ = bittorrent_v2_merkle_sha256(file)
    return pieces_root.hex()


CHECKSUM_ALGO_DICT['merkle_sha256'] = merkle_sha256


def bencode(obj) -> bytes:
    """
    Copied from the reference implementation of v2 bittorrent:
    http://bittorrent.org/beps/bep_0052_torrent_creator.py
    """

    if isinstance(obj, int):
        return b"i" + str(obj).encode() + b"e"
    elif isinstance(obj, bytes):
        return str(len(obj)).encode() + b":" + obj
    elif isinstance(obj, str):
        return bencode(obj.encode("utf-8"))
    elif isinstance(obj, list):
        return b"l" + b"".join(map(bencode, obj)) + b"e"
    elif isinstance(obj, dict):
        if all(isinstance(i, bytes) for i in obj.keys()):
            items = list(obj.items())
            items.sort()
            return b"d" + b"".join(map(bencode, itertools.chain(*items))) + b"e"
        else:
            raise ValueError("dict keys should be bytes " + str(obj.keys()))
    raise ValueError("Allowed types: int, bytes, list, dict; not %s", type(obj))


def construct_torrent(
        scope: str,
        name: str,
        length: int,
        piece_length: int,
        pieces_root: bytes,
        pieces_layers: "Optional[bytes]" = None,
        trackers: "Optional[list[str]]" = None,
) -> "tuple[str, bytes]":

    torrent_dict = {
        b'creation date': int(time.time()),
        b'info': {
            b'meta version': 2,
            b'private': 1,
            b'name': f'{scope}:{name}'.encode(),
            b'piece length': piece_length,
            b'file tree': {
                name.encode(): {
                    b'': {
                        b'length': length,
                        b'pieces root': pieces_root,
                    }
                }
            }
        },
        b'piece layers': {},
    }
    if trackers:
        torrent_dict[b'announce'] = trackers[0].encode()
        if len(trackers) > 1:
            torrent_dict[b'announce-list'] = [t.encode() for t in trackers]
    if pieces_layers:
        torrent_dict[b'piece layers'][pieces_root] = pieces_layers

    torrent_id = hashlib.sha256(bencode(torrent_dict[b'info'])).hexdigest()[:40]
    torrent = bencode(torrent_dict)
    return torrent_id, torrent


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
            return str(" ".join(vallist))
        else:
            return str(vallist)
    except:
        return ''


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


def render_json_list(list_):
    """ JSON render function for list
    """
    return json.dumps(list_, cls=APIEncoder)


def datetime_parser(dct):
    """ datetime parser
    """
    for k, v in list(dct.items()):
        if isinstance(v, str) and re.search(" UTC", v):
            try:
                dct[k] = datetime.datetime.strptime(v, DATE_FORMAT)
            except Exception:
                pass
    return dct


def parse_response(data):
    """
    JSON render function
    """
    if hasattr(data, 'decode'):
        data = data.decode('utf-8')

    return json.loads(data, object_hook=datetime_parser)


def execute(cmd) -> tuple[int, str, str]:
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


def rse_supported_protocol_operations():
    """ Returns a list with operations supported by all RSE protocols."""
    return ['read', 'write', 'delete', 'third_party_copy_read', 'third_party_copy_write']


def rse_supported_protocol_domains():
    """ Returns a list with all supported RSE protocol domains."""
    return ['lan', 'wan']


def grouper(iterable, n, fillvalue=None):
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


def dict_chunks(dict_, n):
    """
    Iterate over the dictionary in groups of the requested size
    """
    it = iter(dict_)
    for _ in range(0, len(dict_), n):
        yield {k: dict_[k] for k in itertools.islice(it, n)}


def my_key_generator(namespace, fn, **kw):
    """
    Customyzed key generator for dogpile
    """
    fname = fn.__name__

    def generate_key(*arg, **kw):
        return namespace + "_" + fname + "_".join(str(s) for s in filter(None, arg))

    return generate_key


SurlAlgorithmsT = TypeVar('SurlAlgorithmsT', bound='SurlAlgorithms')


class SurlAlgorithms(PolicyPackageAlgorithms):
    """
    Handle SURL construction, including registration of SURL algorithms from policy packages
    """

    _algorithm_type = 'surl'

    def __init__(self) -> None:
        """
        Initialises a SURL construction object
        """
        super().__init__()

    def construct_surl(self, dsn: str, scope: str, filename: str, naming_convention: str) -> str:
        """
        Calls the correct algorithm to generate a SURL
        """
        return self.get_algorithm(naming_convention)(dsn, scope, filename)

    @classmethod
    def supports(cls: type[SurlAlgorithmsT], naming_convention: str) -> bool:
        """
        Checks whether a SURL algorithm is supported
        """
        return super()._supports(cls._algorithm_type, naming_convention)

    @classmethod
    def _module_init_(cls: type[SurlAlgorithmsT]) -> None:
        """
        Registers the included SURL algorithms
        """
        cls.register('T0', cls.construct_surl_T0)
        cls.register('DQ2', cls.construct_surl_DQ2)
        cls.register('BelleII', cls.construct_surl_BelleII)

    @classmethod
    def get_algorithm(cls: type[SurlAlgorithmsT], naming_convention: str) -> Callable[[str, str, str], str]:
        """
        Looks up a SURL algorithm by name
        """
        return super()._get_one_algorithm(cls._algorithm_type, naming_convention)

    @classmethod
    def register(cls: type[SurlAlgorithmsT], name: str, fn_construct_surl: Callable[[str, str, str], str]) -> None:
        """
        Register a new SURL algorithm
        """
        algorithm_dict = {name: fn_construct_surl}
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
    def construct_surl_DQ2(dsn: str, scope: str, filename: str) -> str:
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
            stripped_dsn = SurlAlgorithms.__strip_dsn(dsn)
            return '/other/%s/%s' % (stripped_dsn, filename)
        elif nfields == 2:
            project = fields[0]
            stripped_dsn = SurlAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s' % (project, stripped_dsn, filename)
        elif nfields < 5 or re.match('user*|group*', fields[0]):
            project = fields[0]
            f2 = fields[1]
            f3 = fields[2]
            stripped_dsn = SurlAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s/%s/%s' % (project, f2, f3, stripped_dsn, filename)
        else:
            project = fields[0]
            dataset_type = fields[4]
            if nfields == 5:
                tag = 'other'
            else:
                tag = SurlAlgorithms.__strip_tag(fields[-1])
            stripped_dsn = SurlAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s/%s/%s' % (project, dataset_type, tag, stripped_dsn, filename)

    @staticmethod
    def construct_surl_T0(dsn: str, scope: str, filename: str) -> str:
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

    @staticmethod
    def construct_surl_BelleII(dsn: str, scope: str, filename: str) -> str:
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


_DEFAULT_SURL = 'DQ2'
SurlAlgorithms._module_init_()


def construct_surl(dsn: str, scope: str, filename: str, naming_convention: str = None) -> str:
    """
    Applies non-deterministic source url convention to the given replica.
    use the naming_convention to call the actual function which will do the job.
    Rucio administrators can potentially register additional surl generation algorithms,
    which are not implemented inside this main rucio repository, so changing the
    argument list must be done with caution.
    """
    surl_algorithms = SurlAlgorithms()
    if naming_convention is None or not SurlAlgorithms.supports(naming_convention):
        naming_convention = _DEFAULT_SURL
    return surl_algorithms.construct_surl(dsn, scope, filename, naming_convention)


def clean_surls(surls):
    res = []
    for surl in surls:
        if surl.startswith('srm'):
            surl = re.sub(':[0-9]+/', '/', surl)
            surl = re.sub(r'/srm/managerv1\?SFN=', '', surl)
            surl = re.sub(r'/srm/v2/server\?SFN=', '', surl)
            surl = re.sub(r'/srm/managerv2\?SFN=', '', surl)
        if '?GoogleAccessId' in surl:
            surl = surl.split('?GoogleAccessId')[0]
        if '?X-Amz' in surl:
            surl = surl.split('?X-Amz')[0]
        res.append(surl)
    res.sort()
    return res


ScopeExtractionAlgorithmsT = TypeVar('ScopeExtractionAlgorithmsT', bound='ScopeExtractionAlgorithms')


class ScopeExtractionAlgorithms(PolicyPackageAlgorithms):
    """
    Handle scope extraction algorithms
    """

    _algorithm_type = 'scope'

    def __init__(self) -> None:
        """
        Initialises scope extraction algorithms object
        """
        super().__init__()

    def extract_scope(self, did: str, scopes: Optional[Sequence[str]], extract_scope_convention: str) -> Sequence[str]:
        """
        Calls the correct algorithm for scope extraction
        """
        return self.get_algorithm(extract_scope_convention)(did, scopes)

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
        cls.register('atlas', cls.extract_scope_atlas)
        cls.register('belleii', cls.extract_scope_belleii)
        cls.register('dirac', cls.extract_scope_dirac)

    @classmethod
    def get_algorithm(cls: type[ScopeExtractionAlgorithmsT], extract_scope_convention: str) -> Callable[[str, Optional[Sequence[str]]], Sequence[str]]:
        """
        Looks up a scope extraction algorithm by name
        """
        return super()._get_one_algorithm(cls._algorithm_type, extract_scope_convention)

    @classmethod
    def register(cls: type[ScopeExtractionAlgorithmsT], name: str, fn_extract_scope: Callable[[str, Optional[Sequence[str]]], Sequence[str]]) -> None:
        """
        Registers a new scope extraction algorithm
        """
        algorithm_dict = {name: fn_extract_scope}
        super()._register(cls._algorithm_type, algorithm_dict)

    @staticmethod
    def extract_scope_atlas(did: str, scopes: Optional[Sequence[str]]) -> Sequence[str]:
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

    @staticmethod
    def extract_scope_dirac(did: str, scopes: Optional[Sequence[str]]) -> Sequence[str]:
        # Default dirac scope extract algorithm. Scope is the second element in the LFN or the first one (VO name)
        # if only one element is the result of a split.
        elem = did.rstrip('/').split('/')
        if len(elem) > 2:
            scope = elem[2]
        else:
            scope = elem[1]
        return scope, did

    @staticmethod
    def extract_scope_belleii(did: str, scopes: Optional[Sequence[str]]) -> Sequence[str]:
        split_did = did.split('/')
        if did.startswith('/belle/mock/'):
            return 'mock', did
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
                if len(split_did[3]) == 1 and scopes is not None and 'user.%s' % (split_did[4]) in scopes:
                    return 'user.%s' % split_did[4], did
            if len(split_did) > 3:
                if scopes is not None and 'user.%s' % (split_did[3]) in scopes:
                    return 'user.%s' % split_did[3], did
            return 'user', did
        if did.startswith('/belle/group/'):
            if len(split_did) > 4:
                if scopes is not None and 'group.%s' % (split_did[4]) in scopes:
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
        if did.startswith('/belle/collection'):
            return 'collection', did
        return 'other', did


_DEFAULT_EXTRACT = 'atlas'
ScopeExtractionAlgorithms._module_init_()


def extract_scope(did, scopes=None, default_extract=_DEFAULT_EXTRACT):
    scope_extraction_algorithms = ScopeExtractionAlgorithms()
    extract_scope_convention = config_get('common', 'extract_scope', False, None) or config_get('policy', 'extract_scope', False, None)
    if extract_scope_convention is None or not ScopeExtractionAlgorithms.supports(extract_scope_convention):
        extract_scope_convention = default_extract
    return scope_extraction_algorithms.extract_scope(did, scopes, extract_scope_convention)


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


def detect_client_location():
    """
    Normally client IP will be set on the server side (request.remote_addr)
    Here setting ip on the one seen by the host itself. There is no connection
    to Google DNS servers.
    Try to determine the sitename automatically from common environment variables,
    in this order: SITE_NAME, ATLAS_SITE_NAME, OSG_SITE_NAME. If none of these exist
    use the fixed string 'ROAMING'.

    If environment variables sets location, it uses it.
    """

    ip = None

    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860:0:0:0:0:8888", 80))
        ip = s.getsockname()[0]
    except Exception:
        pass

    if not ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            pass

    if not ip:
        ip = '0.0.0.0'

    site = os.environ.get('SITE_NAME',
                          os.environ.get('ATLAS_SITE_NAME',
                                         os.environ.get('OSG_SITE_NAME',
                                                        'ROAMING')))

    latitude = os.environ.get('RUCIO_LATITUDE')
    longitude = os.environ.get('RUCIO_LONGITUDE')
    if latitude and longitude:
        try:
            latitude = float(latitude)
            longitude = float(longitude)
        except ValueError:
            latitude = longitude = 0
            print('Client set latitude and longitude are not valid.')
    else:
        latitude = longitude = None

    return {'ip': ip,
            'fqdn': socket.getfqdn(),
            'site': site,
            'latitude': latitude,
            'longitude': longitude}


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
    if 'filename' not in lfn_dict:
        return lfn_dict

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

    url_parts = list(urlparse(url))
    mod_query = dict(parse_qsl(url_parts[4]))
    mod_query.update(query)
    url_parts[4] = urlencode(mod_query)
    return urlunparse(url_parts)


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
                if value.upper() in ['ALL', 'COLLECTION', 'CONTAINER', 'DATASET', 'FILE']:
                    type_ = value.lower()
                else:
                    raise InvalidType('{0} is not a valid type. Valid types are {1}'.format(value, ['ALL', 'COLLECTION', 'CONTAINER', 'DATASET', 'FILE']))
            elif key in ('length.gt', 'length.lt', 'length.gte', 'length.lte', 'length'):
                try:
                    value = int(value)
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


def parse_did_filter_from_string_fe(input_string, name='*', type='collection', omit_name=False):
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
    :param type: The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container.
    :param omit_name: omit addition of name to filters.
    :return: list of dictionaries with each dictionary as a separate OR expression.
    """
    # lookup table unifying all comprehended operators to a nominal suffix.
    # note that the order matters as the regex engine is eager, e.g. don't want to evaluate '<=' as '<' and '='.
    operators_suffix_LUT = OrderedDict({
        '<=': 'lte',
        '>=': 'gte',
        '==': '',
        '!=': 'ne',
        '>': 'gt',
        '<': 'lt',
        '=': ''
    })

    # lookup table mapping operator opposites, used to reverse compound inequalities.
    operator_opposites_LUT = {
        'lt': 'gt',
        'lte': 'gte'
    }
    operator_opposites_LUT.update({op2: op1 for op1, op2 in operator_opposites_LUT.items()})

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
                tokenisation_regex = "({})".format('|'.join(operators_suffix_LUT.keys()))
                and_group_split_by_operator = list(filter(None, re.split(tokenisation_regex, and_group)))
                if len(and_group_split_by_operator) == 3:       # this is a one-sided inequality or expression
                    key, operator, value = [token.strip() for token in and_group_split_by_operator]

                    # substitute input operator with the nominal operator defined by the LUT, <operators_suffix_LUT>.
                    operator_mapped = operators_suffix_LUT.get(operator)

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
                    operator1_mapped = operator_opposites_LUT.get(operators_suffix_LUT.get(operator1))
                    operator2_mapped = operators_suffix_LUT.get(operator2)

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


def run_cmd_process(cmd, timeout=3600):
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


def api_update_return_dict(dictionary, session=None):
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
        cfg_forced_modules = config_get('logging', cfg_option, raise_exception=False, default=None, clean_cached=True,
                                        check_config_table=False)
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


def daemon_sleep(start_time, sleep_time, graceful_stop, logger=logging.log):
    """Sleeps a daemon the time provided by sleep_time"""
    end_time = time.time()
    time_diff = end_time - start_time
    if time_diff < sleep_time:
        logger(logging.INFO, 'Sleeping for a while :  %s seconds', (sleep_time - time_diff))
        graceful_stop.wait(sleep_time - time_diff)


def is_client():
    """"
    Checks if the function is called from a client or from a server/daemon

    :returns client_mode: True if is called from a client, False if it is called from a server/daemon
    """
    if 'RUCIO_CLIENT_MODE' not in os.environ:
        try:
            if config_has_section('database'):
                client_mode = False
            elif config_has_section('client'):
                client_mode = True
            else:
                client_mode = False
        except (RuntimeError, ConfigNotFound):
            # If no configuration file is found the default value should be True
            client_mode = True
    else:
        if os.environ['RUCIO_CLIENT_MODE']:
            client_mode = True
        else:
            client_mode = False

    return client_mode


class retry:
    """Retry callable object with configuragle number of attempts"""

    def __init__(self, func, *args, **kwargs):
        '''
        :param func: a method that should be executed with retries
        :param args: parameters of the func
        :param kwargs: key word arguments of the func
        '''
        self.func, self.args, self.kwargs = func, args, kwargs

    def __call__(self, mtries=3, logger=logging.log):
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
                 option_strings,
                 new_option_string,
                 dest,
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
        assert new_option_string in option_strings
        self.new_option_string = new_option_string

    def __call__(self, parser, namespace, values, option_string=None):
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
                 option_strings,
                 new_option_string,
                 dest,
                 default=False,
                 required=False,
                 help=None):
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
        assert new_option_string in option_strings
        self.new_option_string = new_option_string

    def __call__(self, parser, namespace, values, option_string=None):
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
        def __init__(self, position, priority):
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


def check_policy_package_version(package):
    import importlib

    from rucio.version import version_string
    '''
    Checks that the Rucio version supported by the policy package is compatible
    with this version. Raises an exception if not.
    :param package: the fully qualified name of the policy package
    '''
    try:
        module = importlib.import_module(package)
    except ImportError:
        # package not found. Will be picked up elsewhere
        return
    if not hasattr(module, 'SUPPORTED_VERSION'):
        # package is not versioned
        return
    supported_version = module.SUPPORTED_VERSION if isinstance(module.SUPPORTED_VERSION, list) else [module.SUPPORTED_VERSION]
    components = 2 if version_string().startswith("1.") else 1
    current_version = ".".join(version_string().split(".")[:components])
    if current_version not in supported_version:
        raise PolicyPackageVersionError(package)


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

    def __init__(self, read=None, write=None, delete=None):
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
