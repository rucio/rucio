# -*- coding: utf-8 -*-
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
import glob
import logging
import os
import queue as Queue
from datetime import datetime
from datetime import timedelta

import select

from rucio.common import config
from rucio.common.dumper import LogPipeHandler
from rucio.common.dumper import mkdir
from rucio.common.dumper import temp_file
from rucio.common.dumper.consistency import Consistency
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import chunks
from rucio.core.quarantined_replica import add_quarantined_replicas
from rucio.core.replica import declare_bad_file_replicas, list_replicas
from rucio.core.rse import get_rse_usage, get_rse_id
from rucio.daemons.auditor import srmdumps
from rucio.daemons.auditor.hdfs import ReplicaFromHDFS
from rucio.db.sqla.constants import BadFilesStatus


def consistency(rse, delta, configuration, cache_dir, results_dir):
    logger = logging.getLogger('auditor-worker')
    rsedump, rsedate = srmdumps.download_rse_dump(rse, configuration, destdir=cache_dir)
    results_path = os.path.join(results_dir, '{0}_{1}'.format(rse, rsedate.strftime('%Y%m%d')))  # pylint: disable=no-member

    if os.path.exists(results_path + '.bz2') or os.path.exists(results_path):
        logger.warning('Consistency check for "%s" (dump dated %s) already done, skipping check', rse, rsedate.strftime('%Y%m%d'))  # pylint: disable=no-member
        return None

    rrdump_prev = ReplicaFromHDFS.download(rse, rsedate - delta, cache_dir=cache_dir)
    rrdump_next = ReplicaFromHDFS.download(rse, rsedate + delta, cache_dir=cache_dir)
    results = Consistency.dump(
        'consistency-manual',
        rse,
        rsedump,
        rrdump_prev,
        rrdump_next,
        date=rsedate,
        cache_dir=cache_dir,
    )
    mkdir(results_dir)
    with temp_file(results_dir, results_path) as (output, _):
        for result in results:
            output.write('{0}\n'.format(result.csv()))

    return results_path


def guess_replica_info(path):
    """Try to extract the scope and name from a path.

    ``path`` should be an ``str`` with the relative path to the file on
    the RSE.

    Returns a ``tuple`` of which the first element is the scope of the
    replica and the second element is its name.
    """
    items = path.split('/')
    if len(items) == 1:
        return None, path
    elif len(items) > 2 and items[0] in ['group', 'user']:
        return '.'.join(items[0:2]), items[-1]
    else:
        return items[0], items[-1]


def bz2_compress_file(source, chunk_size=65000):
    """Compress a file with bzip2.

    The destination is the path passed through ``source`` extended with
    '.bz2'.  The original file is deleted.

    Errors are deliberately not handled gracefully.  Any exceptions
    should be propagated to the caller.

    ``source`` should be an ``str`` with the absolute path to the file
    to compress.

    ``chunk_size`` should be an ``int`` with the size (in bytes) of the
    chunks by which to read the file.

    Returns an ``str`` with the destination path.
    """
    destination = '{}.bz2'.format(source)
    with open(source) as plain, bz2.BZ2File(destination, 'w') as compressed:
        while True:
            chunk = plain.read(chunk_size)
            if not chunk:
                break
            compressed.write(chunk.encode())
    os.remove(source)
    return destination


def process_output(output, sanity_check=True, compress=True):
    """Perform post-consistency-check actions.

    DARK files are put in the quarantined-replica table so that they
    may be deleted by the Dark Reaper.  LOST files are reported as
    suspicious so that they may be further checked by the cloud squads.

    ``output`` should be an ``str`` with the absolute path to the file
    produced by ``consistency()``.  It must maintain its naming
    convention.

    If ``sanity_check`` is ``True`` (default) and the number of entries
    in the output file is deemed excessive, the actions are aborted.

    If ``compress`` is ``True`` (default), the file is compressed with
    bzip2 after the actions are successfully performed.
    """
    logger = logging.getLogger('auditor-worker')
    dark_replicas = []
    lost_replicas = []
    try:
        with open(output) as f:
            for line in f:
                label, path = line.rstrip().split(',', 1)
                scope, name = guess_replica_info(path)
                if label == 'DARK':
                    dark_replicas.append({'path': path,
                                          'scope': InternalScope(scope),
                                          'name': name})
                elif label == 'LOST':
                    lost_replicas.append({'scope': InternalScope(scope),
                                          'name': name})
                else:
                    raise ValueError('unexpected label')
    # Since the file is read immediately after its creation, any error
    # exposes a bug in the Auditor.
    except Exception as error:
        logger.critical('Error processing "%s"', output, exc_info=True)
        raise error

    rse = os.path.basename(output[:output.rfind('_')])
    rse_id = get_rse_id(rse=rse)
    usage = get_rse_usage(rse_id=rse_id, source='rucio')[0]
    threshold = config.config_get_float('auditor', 'threshold', False, 0.1)

    # Perform a basic sanity check by comparing the number of entries
    # with the total number of files on the RSE.  If the percentage is
    # significant, there is most likely an issue with the site dump.
    found_error = False
    if len(dark_replicas) > threshold * usage['files']:
        logger.warning('Number of DARK files is exceeding threshold: "%s"',
                       output)
        found_error = True
    if len(lost_replicas) > threshold * usage['files']:
        logger.warning('Number of LOST files is exceeding threshold: "%s"',
                       output)
        found_error = True
    if found_error and sanity_check:
        raise AssertionError('sanity check failed')

    # While converting LOST replicas to PFNs, entries that do not
    # correspond to a replica registered in Rucio are silently dropped.
    lost_pfns = [r['rses'][rse_id][0] for chunk in chunks(lost_replicas, 1000) for r in list_replicas(chunk) if rse_id in r['rses']]

    for chunk in chunks(dark_replicas, 1000):
        add_quarantined_replicas(rse_id=rse_id, replicas=chunk)
    logger.debug('Processed %d DARK files from "%s"', len(dark_replicas),
                 output)
    declare_bad_file_replicas(lost_pfns, reason='Reported by Auditor',
                              issuer=InternalAccount('root'), status=BadFilesStatus.SUSPICIOUS)
    logger.debug('Processed %d LOST files from "%s"', len(lost_replicas),
                 output)

    if compress:
        destination = bz2_compress_file(output)
        logger.debug('Compressed "%s"', destination)


def check(queue, retry, terminate, logpipe, cache_dir, results_dir, keep_dumps, delta_in_days):
    logger = logging.getLogger('auditor-worker')
    lib_logger = logging.getLogger('dumper')

    loglevel = logging.getLevelName(config.config_get('common', 'loglevel', False, 'DEBUG'))
    logger.setLevel(loglevel)
    lib_logger.setLevel(loglevel)

    handler = LogPipeHandler(logpipe)
    logger.addHandler(handler)
    lib_logger.addHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s  %(name)-22s  %(levelname)-8s [PID %(process)8d] %(message)s"
    )
    handler.setFormatter(formatter)

    delta = timedelta(days=delta_in_days)

    configuration = srmdumps.parse_configuration()

    while not terminate.is_set():
        try:
            rse, attemps = queue.get(timeout=30)
        except Queue.Empty:
            continue
        start = datetime.now()
        try:
            logger.debug('Checking "%s"', rse)
            output = consistency(rse, delta, configuration, cache_dir,
                                 results_dir)
            if output:
                process_output(output)
        except:
            elapsed = (datetime.now() - start).total_seconds() / 60
            logger.error('Check of "%s" failed in %d minutes, %d remaining attemps', rse, elapsed, attemps, exc_info=True)
            success = False
        else:
            elapsed = (datetime.now() - start).total_seconds() / 60
            logger.info('SUCCESS checking "%s" in %d minutes', rse, elapsed)
            success = True

        if not keep_dumps:
            remove = glob.glob(os.path.join(cache_dir, 'replicafromhdfs_{0}_*'.format(rse)))
            remove.extend(glob.glob(os.path.join(cache_dir, 'ddmendpoint_{0}_*'.format(rse))))
            logger.debug('Removing: %s', remove)
            for fil in remove:
                os.remove(fil)

        if not success and attemps > 0:
            retry.put((rse, attemps - 1))


def activity_logger(logpipes, logfilename, terminate):
    handler = logging.handlers.RotatingFileHandler(
        logfilename,
        maxBytes=20971520,
        backupCount=10,
    )
    handler.setFormatter(logging.Formatter(fmt=None))
    logger = logging.getLogger('auditor-logger-raw')
    logger.addHandler(handler)
    logger.setLevel(logging.CRITICAL)  # The level of this logger is irrelevant

    while not terminate.is_set():
        ready, _, _ = select.select(logpipes, tuple(), tuple(), 30)
        if ready:
            for logpipe in ready:
                logger.critical(logpipe.recv())
