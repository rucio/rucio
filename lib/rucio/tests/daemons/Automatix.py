#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014

'''
Automatix is a Data Generator daemon to generate fake data and upload it on a RSE.
'''

import logging
import random
import tempfile
import threading

from datetime import datetime
from json import load
from os import remove, rmdir, stat
from sys import stdout
from time import sleep

from rucio.client import Client
from rucio.common.config import config_get, config_get_int
from rucio.common.utils import adler32
from rucio.rse import rsemanager as rsemgr

from rucio.common.utils import execute, generate_uuid

logging.getLogger("automatix").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


SUCCESS = 0
FAILURE = 1


graceful_stop = threading.Event()


def upload(files, scope, metadata, rse, account, source_dir, did=None):
    logging.debug('In upload')
    dsn = None
    if did:
        dsn = {'scope': did.split(':')[0], 'name': did.split(':')[1]}
    client = Client()

    list_files = []
    lfns = []
    logging.debug('Looping over the files')
    for filename in files:
        fullpath = '%s/%s' % (source_dir, filename)
        size = stat(fullpath).st_size
        checksum = adler32(fullpath)
        logging.info('File %s : Size %s , adler32 %s' % (fullpath, str(size), checksum))
        list_files.append({'scope': scope, 'name': filename, 'bytes': size, 'adler32': checksum, 'meta': {'guid': generate_uuid()}})
        lfns.append({'name': filename, 'scope': scope})

    rse_info = rsemgr.get_rse_info(rse)
    if dsn:
        try:
            client.add_dataset(scope=dsn['scope'], name=dsn['name'], rules=[{'account': account, 'copies': 1, 'rse_expression': rse, 'grouping': 'DATASET'}], meta=metadata)
            client.add_files_to_dataset(scope=dsn['scope'], name=dsn['name'], files=list_files, rse=rse)
            rsemgr.upload(rse_info, lfns=lfns, source_dir=source_dir)
            logging.info('Upload operation for %s done' % filename)
        except Exception, e:
            logging.error('Failed to upload %(files)s' % locals())
            logging.error(e)
    else:
        logging.debug('No dsn is specified')
        try:
            client.add_replicas(files=list_files, rse=rse)
            client.add_replication_rule(list_files, copies=1, rse_expression=rse)
            rsemgr.upload(rse_info, lfns=lfns)
            logging.info('Upload operation for %s done' % filename)
        except Exception, e:
            logging.error('Failed to upload %(files)s' % locals())
            logging(e)


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
    r = random.uniform(0, 1)
    prob = 0
    for key in probabilities:
        prob = probabilities[key]
        if prob >= r:
            return data[key]
    return data[key]


def generate_file(fname, size):
    cmd = '/bin/dd if=/dev/urandom of=%(fname)s bs=1k count=%(size)s' % locals()
    exitcode, out, err = execute(cmd)
    logging.debug(out)
    logging.debug(err)
    return exitcode


def automatix(sites, inputfile, sleep_time, worker_number=1, total_workers=1, once=False):
    while not graceful_stop.is_set():
        nbfiles = 3
        size = 1000
        logging.info('Getting data distribution')
        probabilities, data = get_data_distribution(inputfile)
        logging.debug(probabilities)
        account = 'root'
        scope = 'tests'
        now = datetime.now()
        dsn_extension = '%s.%s.%s.%s' % (now.year, now.month, now.day, generate_uuid())
        for site in sites:
            tmpdir = tempfile.mkdtemp()
            logging.info('Running on site %s' % (site))
            d = choose_element(probabilities, data)
            metadata = d['metadata']
            metadata['version'] = str(random.randint(0, 1000))
            metadata['run_number'] = str(random.randint(0, 100000))
            uuid = generate_uuid()
            metadata['stream_name'] = uuid[:8]
            metadata['campaign'] = uuid[8:12]
            nbfiles = d['nbfiles']
            dsn = 'tests:%s.%s.%s.%s.%s.%s' % (metadata['project'], metadata['run_number'], metadata['stream_name'], metadata['prod_step'], metadata['datatype'], metadata['version'])
            fnames = []
            lfns = []
            for nb in xrange(nbfiles):
                fname = '1k-file-' + generate_uuid()
                lfns.append(fname)
                fname = '%s/%s' % (tmpdir, fname)
                logging.info('Generating file %(fname)s in dataset %(dsn)s' % locals())
                generate_file(fname, size)
                fnames.append(fname)
            logging.info('Upload %s to %s' % (dsn, site))
            upload(files=lfns, scope=scope, metadata=metadata, rse=site, account=account, source_dir=tmpdir, did=dsn)
            for fname in fnames:
                remove(fname)
            rmdir(tmpdir)
        if once is True:
            logging.info('Run with once mode. Exiting')
            break
        logging.info('Will sleep for %s seconds' % str(sleep_time))
        sleep(sleep_time)


def run(total_workers=1, once=False):
    """
    Starts up the automatix threads.
    """
    try:
        sites = [s.strip() for s in config_get('automatix', 'sites').split(',')]
    except:
        raise Exception('Could not load sites from configuration')
    try:
        inputfile = config_get('automatix', 'inputfile')
    except:
        inputfile = '/opt/rucio/etc/automatix.json'
    try:
        sleep_time = config_get_int('automatix', 'sleep_time')
    except:
        sleep_time = 3600
    threads = list()
    for worker_number in xrange(0, total_workers):
        kwargs = {'worker_number': worker_number + 1,
                  'total_workers': total_workers,
                  'once': once,
                  'sites': sites,
                  'sleep_time': sleep_time,
                  'inputfile': inputfile}
        threads.append(threading.Thread(target=automatix, kwargs=kwargs))
    [t.start() for t in threads]
    while threads[0].is_alive():
        logging.info('Still %i active threads' % len(threads))
        [t.join(timeout=3.14) for t in threads]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
