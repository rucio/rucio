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

import logging
import random
import socket
import tempfile
import threading
from configparser import NoOptionError, NoSectionError
from datetime import datetime
from json import load
from os import remove, rmdir, getpid
from time import sleep, time

import rucio.db.sqla.util
from rucio.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.types import InternalScope
from rucio.common.utils import daemon_sleep
from rucio.common.utils import execute, generate_uuid
from rucio.core import monitor, heartbeat
from rucio.core.scope import list_scopes

SUCCESS = 0
FAILURE = 1


GRACEFUL_STOP = threading.Event()


def get_data_distribution(inputfile: str):
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


def choose_element(probabilities: dict, data: str) -> float:
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
        did_prefix = config_get('automatix', 'did_prefix')
    except (NoOptionError, NoSectionError, RuntimeError):
        did_prefix = ''
    try:
        pattern = config_get('automatix', '%s_pattern' % did_type)
        separator = config_get('automatix', 'separator')
    except (NoOptionError, NoSectionError, RuntimeError):
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


def automatix(rses: list, inputfile: str, sleep_time: int, account: str, worker_number: int = 1, total_workers: int = 1, scope: str = 'tests', once: bool = False, dataset_lifetime: int = None, set_metadata: bool = False) -> None:
    """
    Creates an automatix Worker that uploads datasets to a list of rses.

    :param rses: The list of RSEs to upload data
    :param inputfile: The input file where the parameters of the distribution is set
    :param sleep_time: Thread sleep time after each chunk of work.
    :param account: The account to be used for the upload
    :param worker_number: The worker number of the current thread
    :param total_worker: The total number of workers
    :param scope: The scope to be used for the upload
    :param once: Run only once.
    :param dataset_lifetime: The lifetime of the dataset created in seconds
    """
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
        status = False
        for rse in rses:
            timer = monitor.Timer()
            tmpdir = tempfile.mkdtemp()
            logger(logging.INFO, 'Running on RSE %s', rse)
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
            files = []
            for _ in range(nbfiles):
                fname = generate_didname(metadata=metadata, dsn=dsn, did_type='file')
                lfns.append(fname)
                logger(logging.INFO, 'Generating file %s in dataset %s', fname, dsn)
                physical_fname = '%s/%s' % (tmpdir, "".join(fname.split('/')))
                physical_fnames.append(physical_fname)
                generate_file(physical_fname, filesize, logger=logger)
                fnames.append(fname)
                file_ = {'did_scope': scope, 'did_name': fname, 'dataset_scope': scope, 'dataset_name': dsn, 'rse': rse, 'path': physical_fname}
                files.append(file_)
            logger(logging.INFO, 'Upload %s:%s to %s', scope, dsn, rse)
            upload_client = UploadClient()
            ret = upload_client.upload(files)
            if ret == 0:
                logger(logging.INFO, '%s sucessfully registered' % dsn)
                client = Client()
                if set_metadata:
                    client.set_metadata_bulk(scope=scope, name=dsn, meta=metadata, recursive=False)
                    monitor.record_counter(name='automatix.addnewdataset.done', delta=1)
                    monitor.record_counter(name='automatix.addnewfile.done', delta=nbfiles)
                    timer.record('automatix.datasetinjection')
            else:
                logger(logging.INFO, 'Error uploading files')
            for physical_fname in physical_fnames:
                remove(physical_fname)
            rmdir(tmpdir)
        if once is True:
            logger(logging.INFO, 'Run with once mode. Exiting')
            break
        tottime = time() - starttime
        if status:
            logger(logging.INFO, 'It took %s seconds to upload one dataset on %s', str(tottime), str(rses))
            daemon_sleep(start_time=starttime, sleep_time=sleep_time, graceful_stop=GRACEFUL_STOP, logger=logger)
        else:
            logger(logging.INFO, 'Retrying a new upload')
    heartbeat.die(executable, hostname, pid, hb_thread)
    logger(logging.INFO, 'Graceful stop requested')
    logger(logging.INFO, 'Graceful stop done')


def run(total_workers=1, once=False, inputfile=None, sleep_time=-1):
    """
    Starts up the automatix threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    try:
        rses = [s.strip() for s in config_get('automatix', 'rses').split(',')]  # TODO use config_get_list
    except (NoOptionError, NoSectionError, RuntimeError):
        logging.log(logging.ERROR, 'Option rses not found in automatix section. Trying the legacy sites option')
        try:
            rses = [s.strip() for s in config_get('automatix', 'sites').split(',')]  # TODO use config_get_list
            logging.log(logging.WARNING, 'Option sites found in automatix section. This option will be deprecated soon. Please update your config to use rses.')
        except (NoOptionError, NoSectionError, RuntimeError):
            raise Exception('Could not load sites from configuration')

    if not inputfile:
        inputfile = '/opt/rucio/etc/automatix.json'
    if sleep_time == -1:
        try:
            sleep_time = config_get('automatix', 'sleep_time')
        except (NoOptionError, NoSectionError, RuntimeError):
            sleep_time = 30
    try:
        account = config_get('automatix', 'account')
    except (NoOptionError, NoSectionError, RuntimeError):
        account = 'root'
    try:
        dataset_lifetime = config_get('automatix', 'dataset_lifetime')
    except (NoOptionError, NoSectionError, RuntimeError):
        dataset_lifetime = None
    try:
        set_metadata = config_get('automatix', 'set_metadata')
    except (NoOptionError, NoSectionError, RuntimeError):
        set_metadata = False

    try:
        scope = config_get('automatix', 'scope')
        client = Client()
        filters = {'scope': InternalScope('*', vo=client.vo)}
        if InternalScope(scope, vo=client.vo) not in list_scopes(filter_=filters):
            logging.log(logging.ERROR, 'Scope %s does not exist. Exiting', scope)
            GRACEFUL_STOP.set()
    except Exception:
        scope = False

    threads = list()
    for worker_number in range(0, total_workers):
        kwargs = {'worker_number': worker_number,
                  'total_workers': total_workers,
                  'once': once,
                  'rses': rses,
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
