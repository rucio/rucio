# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Fernando Lopez, <felopez@cern.ch>, 2015

import Queue
import glob
import logging
import os.path
import select
import sys

from datetime import datetime
from datetime import timedelta
from rucio.common import config
from rucio.common.dumper import LogPipeHandler
from rucio.common.dumper import mkdir
from rucio.common.dumper import temp_file
from rucio.common.dumper.consistency import Consistency
from rucio.daemons.auditor.hdfs import ReplicaFromHDFS
from rucio.daemons.auditor import srmdumps


def total_seconds(td):
    '''timedelta.total_seconds() for Python < 2.7'''
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * (10 ** 6)) / float(10 ** 6)


def consistency(rse, delta, configuration, cache_dir, results_dir):
    logger = logging.getLogger('auditor-worker')
    rsedump, rsedate = srmdumps.download_rse_dump(rse, configuration, destdir=cache_dir)
    results_path = '{0}/{1}_{2}'.format(results_dir, rse, rsedate.strftime('%Y%m%d'))  # pylint: disable=no-member

    if os.path.exists(results_path):
        logger.warn('Consistency check for "%s" (dump dated %s) already done, skipping check', rse, rsedate.strftime('%Y%m%d'))  # pylint: disable=no-member
        return

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


def check(queue, retry, terminate, logpipe, cache_dir, results_dir, keep_dumps, delta_in_days):
    logger = logging.getLogger('auditor-worker')
    lib_logger = logging.getLogger('dumper')

    loglevel = logging.getLevelName(config.config_get('common', 'loglevel'))
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
            consistency(rse, delta, configuration, cache_dir, results_dir)
        except:
            success = False
        else:
            success = True
        finally:
            elapsed = total_seconds(datetime.now() - start) / 60
            if success:
                logger.info('SUCCESS checking "%s" in %d minutes', rse, elapsed)
            else:
                class_, desc = sys.exc_info()[0:2]
                logger.error('Check of "%s" failed in %d minutes, %d remaining attemps: (%s: %s)', rse, elapsed, attemps, class_.__name__, desc)

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
