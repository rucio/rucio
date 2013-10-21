#!/opt/rucio/bin/python2.6
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

'''
Automatix is a Data Generator daemon to generate fake data and upload it on a RSE.
'''

import random
import tempfile

from datetime import datetime
from json import load
from logging import getLogger, FileHandler, Formatter, DEBUG, INFO
from os import remove, rmdir, stat
from sys import exit
from time import sleep

from rucio.client.didclient import DIDClient
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.common.config import config_get, config_get_int
from rucio.common.utils import adler32
from rucio.rse import rsemanager

from rucio.common.utils import execute, generate_uuid

logger = getLogger("rucio.tests.daemons.Automatix")
hdlr = FileHandler('/var/log/rucio/Automatix.log')
formatter = Formatter('%(asctime)s %(levelname)s %(process)d %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(DEBUG)
logger.setLevel(INFO)


SUCCESS = 0
FAILURE = 1


# Callback called when you run `supervisorctl stop'
def stop(signum, frame):
    logger.info("Kaboom Baby!")
    exit(SUCCESS)


def upload(files, scope, metadata, rse, account, source_dir, did=None):
    logger.debug('In upload')
    dsn = None
    if did:
        dsn = {'scope': did.split(':')[0], 'name': did.split(':')[1]}
        client = DIDClient()
    else:
        client = RSEClient()
        ruleclient = RuleClient()

    rsemgr = rsemanager.RSEMgr()
    list_files = []
    lfns = []
    logger.debug('Looping over the files')
    for filename in files:
        fullpath = '%s/%s' % (source_dir, filename)
        size = stat(fullpath).st_size
        checksum = adler32(fullpath)
        logger.info('File %s : Size %s , adler32 %s' % (fullpath, str(size), checksum))
        list_files.append({'scope': scope, 'name': filename, 'bytes': size, 'adler32': checksum, 'meta': {'guid': generate_uuid()}})
        lfns.append({'name': filename, 'scope': scope})

    if dsn:
        logger.debug('No dsn is specify')
        try:
            client.add_dataset(scope=dsn['scope'], name=dsn['name'], rules=[{'account': account, 'copies': 1, 'rse_expression': rse, 'grouping': 'DATASET'}], meta=metadata)
            client.add_files_to_dataset(scope=dsn['scope'], name=dsn['name'], files=list_files, rse=rse)
            rsemgr.upload(rse, lfns=lfns, source_dir=source_dir)
            logger.info('Upload operation for %s done' % filename)
        except Exception, e:
            logger.error('Failed to upload %(files)s' % locals())
            logger.error(e)
    else:
        try:
            client.add_replicas(files=list_files, rse=rse)
            ruleclient.add_replication_rule(list_files, copies=1, rse_expression=rse)
            rsemgr.upload(rse, lfns=lfns)
            logger.info('Upload operation for %s done' % filename)
        except Exception, e:
            logger.error('Failed to upload %(files)s' % locals())
            logger(e)


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
    logger.debug(out)
    logger.debug(err)
    return exitcode


def run_once(sites, inputfile):
    nbfiles = 3
    size = 1000
    logger.info('Getting data distribution')
    probabilities, data = get_data_distribution(inputfile)
    logger.debug(probabilities)
    account = 'root'
    scope = 'tests'
    now = datetime.now()
    dsn_extension = '%s.%s.%s.%s' % (now.year, now.month, now.day, generate_uuid())
    for site in sites:
        tmpdir = tempfile.mkdtemp()
        logger.info('Running on site %s' % (site))
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
            logger.info('Generating file %(fname)s in dataset %(dsn)s' % locals())
            generate_file(fname, size)
            fnames.append(fname)
        logger.info('Upload %s to %s' % (dsn, site))
        upload(files=lfns, scope=scope, metadata=metadata, rse=site, account=account, source_dir=tmpdir, did=dsn)
        for fname in fnames:
            remove(fname)
        rmdir(tmpdir)


if __name__ == '__main__':
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

    while True:
        run_once(sites, inputfile)
        logger.info('End of the cycle. Will sleep for %f seconds' % sleep_time)
        sleep(sleep_time)
