# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Fernando Lopez, <felopez@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2016

from rucio.common import config
import contextlib
import datetime
import gzip
import json
import logging
import magic
import os
import re
import requests
import sys
import tempfile

try:
    import gfal2
    from gfal2 import GError
except ImportError as e:
    if 'nose' not in sys.modules and 'py.test' not in sys.modules:
        raise e

# bz2 module doesn't support multi-stream files in Python < 3.3
# https://bugs.python.org/issue1625
# using bz2file (a backport from the lastest CPython bz2 implementation)
# fixes this problem
import bz2file


class HTTPDownloadFailed(Exception):
    def __init__(self, msg='', code=None):
        self.code = code
        if code is not None:
            msg = '{0} (Status {1})'.format(msg, code)
        super(HTTPDownloadFailed, self).__init__(msg)


class LogPipeHandler(logging.Handler, object):
    def __init__(self, pipe):
        super(LogPipeHandler, self).__init__()
        self.pipe = pipe

    def emit(self, record):
        self.pipe.send(self.format(record))

    def close(self):
        super(LogPipeHandler, self).close()
        self.pipe.close()


def error(text, exit_code=1):
    '''
    Log and print `text` error. This function ends the execution of the program with exit code
    `exit_code` (defaults to 1).
    '''
    logger = logging.getLogger('dumper.__init__')
    logger.error(text)
    sys.stderr.write(text + '\n')
    exit(1)


def mkdir(dir):
    '''
    This functions creates the `dir` directory if it doesn't exist. If `dir`
    already exists this function does nothing.
    '''
    try:
        os.mkdir(dir)
    except OSError, error:
        assert error.errno == 17


def cacert_config(config, rucio_home):
    logger = logging.getLogger('dumper.__init__')
    try:
        cacert = config.config_get('client', 'ca_cert').replace('$RUCIO_HOME', rucio_home)
    except KeyError:
        cacert = None

    if cacert is None or not os.path.exists(cacert):
        logger.warn('Configured CA Certificate file "%s" not found: Host certificate verification disabled', cacert)
        cacert = False

    return cacert


def rucio_home():
    return os.environ.get('RUCIO_HOME', '/opt/rucio')


def get_requests_session():
    requests_session = requests.Session()
    requests_session.verify = cacert_config(config, rucio_home())
    requests_session.stream = True
    return requests_session


DUMPS_CACHE_DIR = 'cache'
RESULTS_DIR = 'results'
CHUNK_SIZE = 4194304  # 4MiB


# There are two Python modules with the name `magic`, luckily both do
# the same thing.
if 'open' in dir(magic):
    _mime = magic.open(magic.MAGIC_MIME)
    _mime.load()
    mimetype = _mime.file
else:
    mimetype = lambda filename: magic.from_file(filename, mime=True)


def isplaintext(filename):
    '''
    Returns True if `filename` has mimetype == 'text/plain'.
    '''
    if os.path.islink(filename):
        filename = os.readlink(filename)
    return mimetype(filename).split(';')[0] == 'text/plain'


def smart_open(filename):
    '''
    Returns an open file object if `filename` is plain text, else assumes
    it is a bzip2 compressed file and returns a file-like object to
    handle it.
    '''
    if isplaintext(filename):
        f = open(filename, 'rt')
    else:
        file_type = mimetype(filename)
        if file_type.find('gzip') > -1:
            f = gzip.GzipFile(filename, 'rt')
        elif file_type.find('bzip2') > -1:
            f = bz2file.open(filename, 'rt')
        else:
            pass  # Not supported format
    return f


@contextlib.contextmanager
def temp_file(directory, final_name=None):
    '''
    Allows to create a temporal file to store partial results, when the
    file is complete it is renamed to `final_name`.

    - `directory`: working path to create the temporal and the final file.
    - `final_name`: Path of the final file, relative to `directory`.
       If the `final_name` is omitted or None the renaming step is ommited,
       leaving the temporal file with the results.

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
    tmp = os.fdopen(fd, 'w')

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


def to_datetime(str_or_datetime):
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
        miliseconds = int(MILLISECONDS_RE.search(str_or_datetime).group(1))
        str_or_datetime = MILLISECONDS_RE.sub('', str_or_datetime)
        date = datetime.datetime.strptime(
            str_or_datetime,
            DATETIME_FORMAT,
        )
        date = date + datetime.timedelta(microseconds=miliseconds * 1000)
    return date


def agis_endpoints_data(cache=True):
    '''
    Returns the result of querying the ddmendpoints list from AGIS
    and parsing the results with json.lads().

    :param cache: If True only makes one query to AGIS and returns
    the same result for subsequent invocations. Consider the effects
    of the cache when testing code which uses this function.
    :returns: a list of dicts with the information returned by AGIS.
    '''
    if cache:
        agis_data = getattr(agis_endpoints_data, '__agis_data', None)
    else:
        agis_data = None

    if agis_data is None:
        ddmendpoints_data_url = ('http://atlas-agis-api.cern.ch/request/ddmendpoint'
                                 '/query/list/?json')

        r = requests.get(ddmendpoints_data_url)
        assert r.status_code == 200
        agis_data = json.loads(r.text)
        agis_endpoints_data.__agis_data = agis_data
    return agis_data


def ddmendpoint_url(ddmendpoint):
    agisdata = agis_endpoints_data()
    endpointdata = next(entry for entry in agisdata if entry['name'] == ddmendpoint)
    return str(''.join((endpointdata['se'], endpointdata['endpoint'])))

# Using AGIS is better to avoid the use of ATLAS credentials, but using
# rucio.client for the same task is also possible:
# def ddmendpoint_url(ddmendpoint):
#     protocols = rucio.client.RSEClient().get_rse(ddmendpoint)['protocols']
#     pdata = next(proto for proto in protocols if proto['scheme'] == 'srm')
#     pdata['prefix'] = '/'.join(pdata['prefix'].split('/')[:-1])
#     return 'srm://{hostname}:{port}/{prefix}'.format(pdata)


def http_download_to_file(url, file_, session=None):
    '''
    Download the file in `url` storing it in the `file_` file-like
    object.
    If given `session` must be a requests.Session instance, and will be
    used to download the file, otherwise requests.get() will be used.
    '''
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
        raise HTTPDownloadFailed('Error downloading ' + url, response.status_code)

    for chunk in response.iter_content(CHUNK_SIZE):
        file_.write(chunk)


def http_download(url, filename):
    '''
    Download the file in `url` storing it in the path given by `filename`.
    '''
    with open(filename, 'w') as f:
        http_download_to_file(url, f)


def srm_download_to_file(url, file_):
    '''
    Download the file in `url` storing it in the `file_` file-like
    object.
    '''
    logger = logging.getLogger('dumper.__init__')
    ctx = gfal2.creat_context()
    infile = ctx.open(url, 'r')

    try:
        chunk = infile.read(CHUNK_SIZE)
    except GError as e:
        if e[1] == 70:
            logger.debug('GError(70) raised, using GRIDFTP PLUGIN:STAT_ON_OPEN=False workarround to download %s', url)
            ctx.set_opt_boolean('GRIDFTP PLUGIN', 'STAT_ON_OPEN', False)
            infile = ctx.open(url, 'r')
            chunk = infile.read(CHUNK_SIZE)
        else:
            raise

    while chunk:
        file_.write(chunk)
        chunk = infile.read(CHUNK_SIZE)


def srm_download(url, filename):
    '''
    Download the file in `url` storing it in the path given by `filename`.
    '''
    with open(filename, 'w') as f:
        srm_download_to_file(url, f)
