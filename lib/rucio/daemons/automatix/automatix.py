# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2020
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Tomas Kouba <tomas.kouba@cern.ch>, 2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import division

import logging
import random
import socket
import tempfile
import threading
from datetime import datetime
from json import load
from math import exp
from os import remove, rmdir, stat, getpid
from time import sleep, time

import rucio.db.sqla.util
from rucio.client import Client
from rucio.common import exception
from rucio.common.exception import FileReplicaAlreadyExists, ConfigNotFound
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.types import InternalScope
from rucio.common.utils import adler32
from rucio.common.utils import execute, generate_uuid
from rucio.core import monitor, heartbeat
from rucio.core.config import get
from rucio.core.scope import list_scopes
from rucio.rse import rsemanager as rsemgr

SUCCESS = 0
FAILURE = 1


GRACEFUL_STOP = threading.Event()


def upload(files, scope, metadata, rse, account, source_dir, dataset_lifetime, did=None, set_metadata=False, logger=logging.log):
    logger(logging.DEBUG, 'In upload')
    dsn = None
    if did:
        dsn = {'scope': did.split(':')[0], 'name': did.split(':')[1]}
    client = Client()

    list_files = []
    lfns = []
    for filename in files:
        physical_fname = filename
        if physical_fname.find('/') > -1:
            physical_fname = "".join(filename.split('/'))
        fullpath = '%s/%s' % (source_dir, physical_fname)
        size = stat(fullpath).st_size
        checksum = adler32(fullpath)
        logger(logging.INFO, 'File %s : Size %s , adler32 %s', fullpath, str(size), checksum)
        list_files.append({'scope': scope, 'name': filename, 'bytes': size, 'adler32': checksum, 'meta': {'guid': generate_uuid()}})
        lfns.append({'name': filename, 'scope': scope, 'filesize': size, 'adler32': checksum, 'filename': physical_fname})

    # Physical upload
    logger(logging.INFO, 'Uploading physically the files %s on %s', str(lfns), rse)
    rse_info = rsemgr.get_rse_info(rse, vo=client.vo)
    try:
        success_upload = True
        for cnt in range(0, 3):
            rows = rsemgr.upload(rse_info, lfns=lfns, source_dir=source_dir, logger=logger)
            # temporary hack
            global_status, ret = rows['success'], rows[1]
            logger(logging.INFO, 'Returned global status : %s, Returned : %s', str(global_status), str(ret))
            if not global_status:
                for item in ret:
                    if (not isinstance(ret[item], FileReplicaAlreadyExists)) and ret[item] is not True:
                        sleep(exp(cnt))
                        success_upload = False
                        logger(logging.ERROR, 'Problem to upload file %s with error %s', item, str(ret[item]))
                        break
            else:
                break
        if not success_upload:
            logger(logging.ERROR, 'Upload operation to %s failed, removing leftovers', rse)
            rsemgr.delete(rse_info, lfns=lfns)
            return False
    except Exception as error:
        logger(logging.DEBUG, "Exception", exc_info=True)
        logger(logging.ERROR, '%s', str(error))
        return False
    logger(logging.INFO, 'Files successfully copied on %s', rse)

    # Registering DIDs and replicas in Rucio
    logger(logging.INFO, 'Registering DIDs and replicas in Rucio')
    meta = metadata
    if not set_metadata:
        meta = None
    if dsn:
        try:
            client.add_dataset(scope=dsn['scope'], name=dsn['name'], rules=[{'account': account, 'copies': 1, 'rse_expression': rse, 'grouping': 'DATASET', 'activity': 'Functional Test'}], meta=meta, lifetime=dataset_lifetime)
            client.add_files_to_dataset(scope=dsn['scope'], name=dsn['name'], files=list_files, rse=rse)
            logger(logging.INFO, 'Upload operation for %s:%s done', dsn['scope'], dsn['name'])
        except Exception as error:
            logger(logging.DEBUG, "Exception", exc_info=True)
            logger(logging.ERROR, 'Failed to upload %s', str(list_files))
            logger(logging.ERROR, '%s', str(error))
            logger(logging.ERROR, 'removing files from the Storage')
            rsemgr.delete(rse_info, lfns=lfns)
            return False
    else:
        logger(logging.WARNING, 'No dsn is specified')
        try:
            client.add_replicas(files=list_files, rse=rse)
            client.add_replication_rule(list_files, copies=1, rse_expression=rse, activity='Functional Test')
            logger(logging.INFO, 'Upload operation for %s done', str(list_files))
        except Exception as error:
            logger(logging.DEBUG, "Exception", exc_info=True)
            logger(logging.ERROR, 'Failed to upload %s', str(list_files))
            logger(logging.ERROR, '%s', str(error))
            logger(logging.ERROR, 'Removing files from the Storage')
            rsemgr.delete(rse_info, lfns=lfns)
            return False
    return True


def get_data_distribution(inputfile):
    with open(inputfile) as data_file:
        data = load(data_file)
    probabilities = {}
    probability = 0
    for key in data:
        probability += data[key]['probability']
        probabilities[key] = probability
    for key in probabilities:
        probabilities[key] = float(probabilities[key]) / probability
    return probabilities, data


def choose_element(probabilities, data):
    rnd = random.uniform(0, 1)
    prob = 0
    for key in probabilities:
        prob = probabilities[key]
        if prob >= rnd:
            return data[key]
    return data[key]


def generate_file(fname, size, logger=logging.log):
    cmd = '/bin/dd if=/dev/urandom of=%s bs=%s count=1' % (fname, size)
    exitcode, out, err = execute(cmd)
    logger(logging.DEBUG, out)
    logger(logging.DEBUG, err)
    return exitcode


def generate_didname(metadata, dsn, did_type):
    try:
        did_prefix = get('automatix', 'did_prefix')
    except ConfigNotFound:
        did_prefix = ''
    try:
        pattern = get('automatix', '%s_pattern' % did_type)
        separator = get('automatix', 'separator')
    except ConfigNotFound:
        return generate_uuid()
    fields = pattern.split(separator)
    file_name = ''
    for field in fields:
        if field == 'date':
            field_str = str(datetime.now().date())
        elif field == 'did_prefix':
            field_str = did_prefix
        elif field == 'dsn':
            field_str = dsn
        elif field == 'uuid':
            field_str = generate_uuid()
        elif field == 'randint':
            field_str = str(random.randint(0, 100000))
        else:
            field_str = metadata.get(field, None)
            if not field_str:
                field_str = str(random.randint(0, 100000))
        file_name = '%s%s%s' % (file_name, separator, field_str)
    len_separator = len(separator)
    return file_name[len_separator:]


def automatix(sites, inputfile, sleep_time, account, worker_number=1, total_workers=1, scope='tests', once=False, dataset_lifetime=None, set_metadata=False):
    sleep(sleep_time * (total_workers - worker_number) / total_workers)

    executable = 'automatix'
    hostname = socket.getfqdn()
    pid = getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    prefix = 'automatix[%i/%i] : ' % (worker_number, total_workers)
    logger = formatted_logger(logging.log, prefix + '%s')
    while not GRACEFUL_STOP.is_set():
        heartbeat.live(executable, hostname, pid, hb_thread)
        starttime = time()
        prefix = 'automatix[%i/%i] : ' % (worker_number, total_workers)
        logger = formatted_logger(logging.log, prefix + '%s')
        logger(logging.INFO, 'Getting data distribution')
        probabilities, data = get_data_distribution(inputfile)
        logger(logging.DEBUG, 'Probabilities %s', probabilities)
        totretries = 3
        status = False

        for site in sites:

            for retry in range(0, totretries):
                start_time = time()
                tmpdir = tempfile.mkdtemp()
                logger(logging.INFO, 'Running on site %s', site)
                dic = choose_element(probabilities, data)
                metadata = dic['metadata']
                try:
                    nbfiles = dic['nbfiles']
                except KeyError:
                    nbfiles = 2
                    logger(logging.WARNING, 'No nbfiles defined in the configuration, will use 2')
                try:
                    filesize = dic['filesize']
                except KeyError:
                    filesize = 1000000
                    logger(logging.WARNING, 'No filesize defined in the configuration, will use 1M files')
                dsn = generate_didname(metadata, None, 'dataset')
                fnames = []
                lfns = []
                physical_fnames = []
                for _ in range(nbfiles):
                    fname = generate_didname(metadata=metadata, dsn=dsn, did_type='file')
                    lfns.append(fname)
                    logger(logging.INFO, 'Generating file %s in dataset %s', fname, dsn)
                    physical_fname = '%s/%s' % (tmpdir, "".join(fname.split('/')))
                    physical_fnames.append(physical_fname)
                    generate_file(physical_fname, filesize, logger=logger)
                    fnames.append(fname)
                logger(logging.INFO, 'Upload %s to %s', dsn, site)
                dsn = '%s:%s' % (scope, dsn)
                status = upload(files=lfns, scope=scope, metadata=metadata, rse=site, account=account, source_dir=tmpdir, dataset_lifetime=dataset_lifetime, did=dsn, set_metadata=set_metadata, logger=logger)
                for physical_fname in physical_fnames:
                    remove(physical_fname)
                rmdir(tmpdir)
                if status:
                    monitor.record_counter(counters='automatix.addnewdataset.done', delta=1)
                    monitor.record_counter(counters='automatix.addnewfile.done', delta=nbfiles)
                    monitor.record_timer('automatix.datasetinjection', (time() - start_time) * 1000)
                    break
                else:
                    logger(logging.INFO, 'Failed to upload files. Will retry another time (attempt %s/%s)', str(retry + 1), str(totretries))
        if once is True:
            logger(logging.INFO, 'Run with once mode. Exiting')
            break
        tottime = time() - starttime
        if status:
            logger(logging.INFO, 'It took %s seconds to upload one dataset on %s', str(tottime), str(sites))
            if sleep_time > tottime:
                logger(logging.INFO, 'Will sleep for %s seconds', str(sleep_time - tottime))
                sleep(sleep_time - tottime)
        else:
            logger(logging.INFO, 'Retrying a new upload')
    heartbeat.die(executable, hostname, pid, hb_thread)
    logger(logging.INFO, 'Graceful stop requested')
    logger(logging.INFO, 'Graceful stop done')


def run(total_workers=1, once=False, inputfile=None):
    """
    Starts up the automatix threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    try:
        sites = [s.strip() for s in get('automatix', 'sites').split(',')]
    except Exception:
        raise Exception('Could not load sites from configuration')
    if not inputfile:
        inputfile = '/opt/rucio/etc/automatix.json'
    try:
        sleep_time = get('automatix', 'sleep_time')
    except Exception:
        sleep_time = 30
    try:
        account = get('automatix', 'account')
    except Exception:
        account = 'root'
    try:
        dataset_lifetime = get('automatix', 'dataset_lifetime')
    except Exception:
        dataset_lifetime = None
    try:
        set_metadata = get('automatix', 'set_metadata')
    except Exception:
        set_metadata = False

    try:
        scope = get('automatix', 'scope')
        client = Client()
        filters = {'scope': InternalScope('*', vo=client.vo)}
        if InternalScope(scope, vo=client.vo) not in list_scopes(filter=filters):
            logging.log(logging.ERROR, 'Scope %s does not exist. Exiting', scope)
            GRACEFUL_STOP.set()
    except Exception:
        scope = False

    threads = list()
    for worker_number in range(0, total_workers):
        kwargs = {'worker_number': worker_number,
                  'total_workers': total_workers,
                  'once': once,
                  'sites': sites,
                  'sleep_time': sleep_time,
                  'account': account,
                  'inputfile': inputfile,
                  'set_metadata': set_metadata,
                  'scope': scope,
                  'dataset_lifetime': dataset_lifetime}
        threads.append(threading.Thread(target=automatix, kwargs=kwargs))
    [thread.start() for thread in threads]
    while threads[0].is_alive():
        logging.log(logging.DEBUG, 'Still %i active threads', len(threads))
        [thread.join(timeout=3.14) for thread in threads]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
