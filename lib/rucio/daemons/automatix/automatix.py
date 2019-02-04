# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014
# - Tomas Kouba <tomas.kouba@cern.ch>, 2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import division

import logging
import socket
import random
import tempfile
import threading
import traceback

from json import load
from math import exp
from os import remove, rmdir, stat, getpid
from sys import stdout, argv
from time import sleep, time

from rucio.client import Client
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.utils import adler32
from rucio.core import monitor, heartbeat
from rucio.rse import rsemanager as rsemgr

from rucio.common.utils import execute, generate_uuid
from rucio.common.exception import FileReplicaAlreadyExists


logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


SUCCESS = 0
FAILURE = 1


graceful_stop = threading.Event()


def upload(files, scope, metadata, rse, account, source_dir, worker_number, total_workers, dataset_lifetime, did=None, set_metadata=False):
    logging.debug('In upload')
    dsn = None
    if did:
        dsn = {'scope': did.split(':')[0], 'name': did.split(':')[1]}
    client = Client()

    list_files = []
    lfns = []
    prepend_str = 'Thread [%i/%i] : ' % (worker_number, total_workers)
    logging.debug(prepend_str + 'Looping over the files')
    for filename in files:
        fullpath = '%s/%s' % (source_dir, filename)
        size = stat(fullpath).st_size
        checksum = adler32(fullpath)
        logging.info(prepend_str + 'File %s : Size %s , adler32 %s' % (fullpath, str(size), checksum))
        list_files.append({'scope': scope, 'name': filename, 'bytes': size, 'adler32': checksum, 'meta': {'guid': generate_uuid()}})
        lfns.append({'name': filename, 'scope': scope, 'filesize': size, 'adler32': checksum, 'filename': filename})

    # Physical upload
    logging.info(prepend_str + 'Uploading physically the files %s on %s' % (str(lfns), rse))
    rse_info = rsemgr.get_rse_info(rse)
    try:
        success_upload = True
        for cnt in range(0, 3):
            rows = rsemgr.upload(rse_info, lfns=lfns, source_dir=source_dir)
            # temporary hack
            global_status, ret = rows['success'], rows[1]
            logging.info(prepend_str + 'Returned global status : %s, Returned : %s' % (str(global_status), str(ret)))
            if not global_status:
                for item in ret:
                    if (not isinstance(ret[item], FileReplicaAlreadyExists)) and ret[item] is not True:
                        sleep(exp(cnt))
                        success_upload = False
                        logging.error(prepend_str + 'Problem to upload file %s with error %s' % (item, str(ret[item])))
                        break
            else:
                break
        if not success_upload:
            logging.error(prepend_str + 'Upload operation to %s failed, removing leftovers' % (rse))
            rsemgr.delete(rse_info, lfns=lfns)
            return False
    except Exception as error:
        logging.debug(traceback.format_exc())
        logging.error(prepend_str + '%s' % (str(error)))
        return False
    logging.info(prepend_str + 'Files successfully copied on %s' % (rse))

    # Registering DIDs and replicas in Rucio
    logging.info(prepend_str + 'Registering DIDs and replicas in Rucio')
    meta = metadata
    if not set_metadata:
        meta = None
    if dsn:
        try:
            client.add_dataset(scope=dsn['scope'], name=dsn['name'], rules=[{'account': account, 'copies': 1, 'rse_expression': rse, 'grouping': 'DATASET', 'activity': 'Functional Test'}], meta=meta, lifetime=dataset_lifetime)
            client.add_files_to_dataset(scope=dsn['scope'], name=dsn['name'], files=list_files, rse=rse)
            logging.info(prepend_str + 'Upload operation for %s:%s done' % (dsn['scope'], dsn['name']))
        except Exception as error:
            logging.debug(traceback.format_exc())
            logging.error(prepend_str + 'Failed to upload %(files)s' % locals())
            logging.error(prepend_str + '%s' % (str(error)))
            logging.error(prepend_str + 'Removing files from the Storage')
            rsemgr.delete(rse_info, lfns=lfns)
            return False
    else:
        logging.warning(prepend_str + 'No dsn is specified')
        try:
            client.add_replicas(files=list_files, rse=rse)
            client.add_replication_rule(list_files, copies=1, rse_expression=rse, activity='Functional Test')
            logging.info(prepend_str + 'Upload operation for %s done' % (str(list_files)))
        except Exception as error:
            logging.debug(traceback.format_exc())
            logging.error(prepend_str + 'Failed to upload %(files)s' % locals())
            logging.error(prepend_str + '%s' % (str(error)))
            logging.error(prepend_str + 'Removing files from the Storage')
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


def generate_file(fname, size):
    cmd = '/bin/dd if=/dev/urandom of=%(fname)s bs=%(size)s count=1' % locals()
    exitcode, out, err = execute(cmd)
    logging.debug(out)
    logging.debug(err)
    return exitcode


def automatix(sites, inputfile, sleep_time, account, worker_number=1, total_workers=1, once=False, dataset_lifetime=None, set_metadata=False):
    sleep(sleep_time * (total_workers - worker_number) / total_workers)

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    while not graceful_stop.is_set():
        heartbeat.live(executable, hostname, pid, hb_thread)
        starttime = time()
        prepend_str = 'Thread [%i/%i] : ' % (worker_number, total_workers)
        logging.info(prepend_str + 'Getting data distribution')
        probabilities, data = get_data_distribution(inputfile)
        logging.debug(prepend_str + 'Probabilities %s' % (probabilities))
        account = 'root'
        scope = 'tests'
        totretries = 3
        status = False

        for site in sites:

            for retry in range(0, totretries):
                start_time = time()
                tmpdir = tempfile.mkdtemp()
                logging.info(prepend_str + 'Running on site %s' % (site))
                dic = choose_element(probabilities, data)
                metadata = dic['metadata']
                metadata['version'] = str(random.randint(0, 1000))
                metadata['run_number'] = str(random.randint(0, 100000))
                metadata['stream_name'] = 'automatix_stream'
                metadata['campaign'] = 'automatix_campaign'
                try:
                    nbfiles = dic['nbfiles']
                except KeyError:
                    nbfiles = 2
                    logging.warning(prepend_str + 'No nbfiles defined in the configuration, will use 2')
                try:
                    filesize = dic['filesize']
                except KeyError:
                    filesize = 1000000
                    logging.warning(prepend_str + 'No filesize defined in the configuration, will use 1M files')
                dsn = 'tests:%s.%s.%s.%s.%s.%s' % (metadata['project'], metadata['run_number'], metadata['stream_name'], metadata['prod_step'], metadata['datatype'], metadata['version'])
                fnames = []
                lfns = []
                for dummy_nbfile in range(nbfiles):
                    fname = '%s.%s' % (metadata['datatype'], generate_uuid())
                    lfns.append(fname)
                    fname = '%s/%s' % (tmpdir, fname)
                    logging.info(prepend_str + 'Generating file %(fname)s in dataset %(dsn)s' % locals())
                    generate_file(fname, filesize)
                    fnames.append(fname)
                logging.info(prepend_str + 'Upload %s to %s' % (dsn, site))
                status = upload(files=lfns, scope=scope, metadata=metadata, rse=site, account=account, source_dir=tmpdir, worker_number=worker_number, total_workers=total_workers, dataset_lifetime=dataset_lifetime, did=dsn, set_metadata=set_metadata)
                for fname in fnames:
                    remove(fname)
                rmdir(tmpdir)
                if status:
                    monitor.record_counter(counters='automatix.addnewdataset.done', delta=1)
                    monitor.record_counter(counters='automatix.addnewfile.done', delta=nbfiles)
                    monitor.record_timer('automatix.datasetinjection', (time() - start_time) * 1000)
                    break
                else:
                    logging.info(prepend_str + 'Failed to upload files. Will retry another time (attempt %s/%s)' % (str(retry + 1), str(totretries)))
        if once is True:
            logging.info(prepend_str + 'Run with once mode. Exiting')
            break
        tottime = time() - starttime
        if status:
            logging.info(prepend_str + 'It took %s seconds to upload one dataset on %s' % (str(tottime), str(sites)))
            if sleep_time > tottime:
                logging.info(prepend_str + 'Will sleep for %s seconds' % (str(sleep_time - tottime)))
                sleep(sleep_time - tottime)
        else:
            logging.info(prepend_str + 'Retrying a new upload')
    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info(prepend_str + 'Graceful stop requested')
    logging.info(prepend_str + 'Graceful stop done')


def run(total_workers=1, once=False, inputfile=None):
    """
    Starts up the automatix threads.
    """
    try:
        sites = [s.strip() for s in config_get('automatix', 'sites').split(',')]
    except Exception:
        raise Exception('Could not load sites from configuration')
    if not inputfile:
        inputfile = '/opt/rucio/etc/automatix.json'
    try:
        sleep_time = config_get_int('automatix', 'sleep_time')
    except Exception:
        sleep_time = 3600
    try:
        account = config_get_int('automatix', 'account')
    except Exception:
        account = 'root'
    try:
        dataset_lifetime = config_get_int('automatix', 'dataset_lifetime')
    except Exception:
        dataset_lifetime = None
    try:
        set_metadata = config_get_bool('automatix', 'set_metadata')
    except Exception:
        set_metadata = False

    threads = list()
    for worker_number in range(0, total_workers):
        kwargs = {'worker_number': worker_number + 1,
                  'total_workers': total_workers,
                  'once': once,
                  'sites': sites,
                  'sleep_time': sleep_time,
                  'account': account,
                  'inputfile': inputfile,
                  'set_metadata': set_metadata,
                  'dataset_lifetime': dataset_lifetime}
        threads.append(threading.Thread(target=automatix, kwargs=kwargs))
    [thread.start() for thread in threads]
    while threads[0].is_alive():
        logging.debug('Still %i active threads' % len(threads))
        [thread.join(timeout=3.14) for thread in threads]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
