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

import bz2
import contextlib
import datetime
import gzip
import logging
import os
import re
import sys
import tempfile
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

import gfal2
import magic
import requests

from rucio.common import config
from rucio.core.rse import get_rse_id, get_rse_protocols

if TYPE_CHECKING:
    from collections.abc import Iterator
    from multiprocessing.connection import Connection
    from types import ModuleType
    from typing import IO, TextIO

    from _typeshed import FileDescriptorOrPath, GenericPath, StrOrBytesPath

    from rucio.common.types import RSEProtocolDict


class HTTPDownloadFailed(Exception):
    def __init__(self, msg: str = '', code: Optional[str] = None):
        self.code = code
        if code is not None:
            msg = '{0} (Status {1})'.format(msg, code)
        super(HTTPDownloadFailed, self).__init__(msg)


class LogPipeHandler(logging.Handler):
    def __init__(self, pipe: "Connection"):
        super(LogPipeHandler, self).__init__()
        self.pipe = pipe

    def emit(self, record: logging.LogRecord) -> None:
        self.pipe.send(self.format(record))

    def close(self) -> None:
        super(LogPipeHandler, self).close()
        self.pipe.close()


def error(text: str, exit_code: int = 1) -> None:
    '''
    Log and print `text` error. This function ends the execution of the program with exit code
    `exit_code` (defaults to 1).
    '''
    logger = logging.getLogger('dumper.__init__')
    logger.error(text)
    sys.stderr.write(text + '\n')
    exit(1)


def mkdir(dir_: "StrOrBytesPath") -> None:
    '''
    This functions creates the `dir_` directory if it doesn't exist. If `dir_`
    already exists this function does nothing.
    '''
    try:
        os.mkdir(dir_)
    except OSError as error:
        assert error.errno == 17


def cacert_config(config: "ModuleType", rucio_home: str) -> Optional[Union["FileDescriptorOrPath", Literal[False]]]:
    logger = logging.getLogger('dumper.__init__')
    try:
        cacert = config.config_get('client', 'ca_cert').replace('$RUCIO_HOME', rucio_home)
    except KeyError:
        cacert = None

    if cacert is None or not os.path.exists(cacert):
        logger.warning('Configured CA Certificate file "%s" not found: Host certificate verification disabled', cacert)
        cacert = False

    return cacert


def rucio_home() -> str:
    return os.environ.get('RUCIO_HOME', '/opt/rucio')


def get_requests_session() -> requests.Session:
    requests_session = requests.Session()
    requests_session.verify = cacert_config(config, rucio_home())  # type: ignore
    requests_session.stream = True
    return requests_session


DUMPS_CACHE_DIR = 'cache'
RESULTS_DIR = 'results'
CHUNK_SIZE = 4194304  # 4MiB


# There are two Python modules with the name `magic`, luckily both do
# the same thing.
# pylint: disable=no-member
if 'open' in dir(magic):
    _mime = magic.open(magic.MAGIC_MIME)
    _mime.load()
    mimetype = _mime.file
else:
    mimetype = lambda filename: magic.from_file(filename, mime=True)  # NOQA
# pylint: enable=no-member


def isplaintext(filename: "GenericPath") -> bool:
    '''
    Returns True if `filename` has mimetype == 'text/plain'.
    '''
    if os.path.islink(filename):
        filename = os.readlink(filename)
    return mimetype(filename).split(';')[0] == 'text/plain'


def smart_open(filename: "GenericPath") -> Optional[Union["TextIO", gzip.GzipFile]]:
    '''
    Returns an open file object if `filename` is plain text, else assumes
    it is a bzip2 compressed file and returns a file-like object to
    handle it.
    '''
    f = None
    if isplaintext(filename):
        f = open(filename, 'rt')
    else:
        file_type = mimetype(filename)
        if file_type.find('gzip') > -1:
            f = gzip.GzipFile(filename, 'rt')
        elif file_type.find('bzip2') > -1:
            f = bz2.open(filename, 'rt')
        else:
            pass  # Not supported format
    return f


@contextlib.contextmanager
def temp_file(
    directory: str,
    final_name: Optional[str] = None,
    binary: bool = False
) -> "Iterator[tuple[IO[Any], StrOrBytesPath]]":
    '''
    Allows to create a temporal file to store partial results, when the
    file is complete it is renamed to `final_name`.

    - `directory`: working path to create the temporal and the final file.
    - `final_name`: Path of the final file, relative to `directory`.
       If the `final_name` is omitted or None the renaming step is omitted,
       leaving the temporal file with the results.
    - `binary`: whether to open the file in binary mode (default: False).

    Important: `directory` and `final_name` must be in the same filesystem as
    a hardlink is used to rename the temporal file.

    Example:
    >>> with temp_file('/tmp', final_name='b') as (f, fname):
    >>>     print('The temporary file is named', fname)
    >>>     f.write('x')
    >>> assert not os.path.exist('/tmp/' + fname)
    >>> assert os.path.exist('/tmp/b')
    '''
    logger = logging.getLogger('dumper.__init__')

    fd, tpath = tempfile.mkstemp(dir=directory)
    tmp = os.fdopen(fd, 'wb' if binary else 'w')

    try:
        yield tmp, os.path.basename(tpath)
    except:
        # Close and remove temporal file on failure
        tmp.close()
        os.unlink(tpath)
        raise

    tmp.close()
    if final_name is not None:
        dst_path = os.path.join(directory, final_name)
        logger.debug('Renaming "%s" to "%s"', tpath, dst_path)
        os.link(tpath, dst_path)
        os.unlink(tpath)


DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DATETIME_FORMAT_FULL = '%Y-%m-%dT%H:%M:%S'
MILLISECONDS_RE = re.compile(r'\.(\d{3})Z$')


def to_datetime(str_or_datetime: Union[datetime.datetime, str]) -> Optional[datetime.datetime]:
    """
    Convert string to datetime. The format is somewhat flexible.
    Timezone information is ignored.
    """
    logger = logging.getLogger('dumper.__init__')
    if isinstance(str_or_datetime, datetime.datetime):
        return str_or_datetime
    elif str_or_datetime.strip() == '':
        return None

    str_or_datetime = str_or_datetime.replace('T', ' ')
    try:
        logger.debug(
            'Trying to parse "%s" date with '
            'resolution of seconds or tenths of seconds',
            str_or_datetime,
        )
        str_or_datetime = re.sub(r'\.\d$', '', str_or_datetime)
        date = datetime.datetime.strptime(
            str_or_datetime,
            DATETIME_FORMAT,
        )
    except ValueError:
        logger.debug(
            'Trying to parse "%s" date with resolution of milliseconds',
            str_or_datetime,
        )
        milliseconds = int(MILLISECONDS_RE.search(str_or_datetime).group(1))
        str_or_datetime = MILLISECONDS_RE.sub('', str_or_datetime)
        date = datetime.datetime.strptime(
            str_or_datetime,
            DATETIME_FORMAT,
        )
        date = date + datetime.timedelta(microseconds=milliseconds * 1000)
    return date


def ddmendpoint_preferred_protocol(ddmendpoint: str) -> "RSEProtocolDict":
    return next(p for p in get_rse_protocols(get_rse_id(ddmendpoint))['protocols'] if p['domains']['wan']['read'] == 1)


def ddmendpoint_url(ddmendpoint: str) -> str:
    preferred_protocol = ddmendpoint_preferred_protocol(ddmendpoint)
    prefix = re.sub(r'rucio/$', '', preferred_protocol['prefix'])
    return '{scheme}://{hostname}:{port}'.format(**preferred_protocol) + prefix


def http_download_to_file(url: str, file_: "IO", session: Optional[requests.Session] = None) -> None:
    '''
    Download the file in `url` storing it in the `file_` file-like
    object.
    If given `session` must be a requests.Session instance, and will be
    used to download the file, otherwise requests.get() will be used.
    '''
    def _do_download(url, file_, session, try_decode=False):
        if session is None:
            response = requests.get(url, stream=True)
        else:
            response = session.get(url)

        if response.status_code != 200:
            logging.error(
                'Retrieving %s returned %d status code',
                url,
                response.status_code,
            )
            raise HTTPDownloadFailed('Error downloading ' + url, str(response.status_code))

        if try_decode:
            if response.encoding is None:
                response.encoding = 'utf-8'
            for chunk in response.iter_content(CHUNK_SIZE, decode_unicode=True):
                file_.write(chunk)
        else:
            for chunk in response.iter_content(CHUNK_SIZE):
                file_.write(chunk)

    try:
        # try without decoding first
        _do_download(url, file_, session, False)
    except TypeError:
        # if that fails due to writing binary data to text file, try to force decode
        _do_download(url, file_, session, True)


def http_download(url: str, filename: "FileDescriptorOrPath") -> None:
    '''
    Download the file in `url` storing it in the path given by `filename`.
    '''
    with open(filename, 'w') as f:
        http_download_to_file(url, f)


def gfal_download_to_file(url: str, file_: "IO") -> None:
    '''
    Download the file in `url` storing it in the `file_` file-like
    object.
    '''
    logger = logging.getLogger('dumper.__init__')
    ctx = gfal2.creat_context()  # pylint: disable=no-member
    infile = ctx.open(url, 'r')

    try:
        chunk = infile.read(CHUNK_SIZE)
    except gfal2.GError as e:
        if e.code == 70:
            logger.debug('GError(70) raised, using GRIDFTP PLUGIN:STAT_ON_OPEN=False workaround to download %s', url)
            ctx.set_opt_boolean('GRIDFTP PLUGIN', 'STAT_ON_OPEN', False)
            infile = ctx.open(url, 'r')
            chunk = infile.read(CHUNK_SIZE)
        else:
            raise

    while chunk:
        file_.write(chunk)
        chunk = infile.read(CHUNK_SIZE)


def gfal_download(url: str, filename: "FileDescriptorOrPath") -> None:
    '''
    Download the file in `url` storing it in the path given by `filename`.
    '''
    with open(filename, 'w') as f:
        gfal_download_to_file(url, f)
