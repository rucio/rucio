# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014

"""
ConveyorInjector is a daemon to queue file transfers for testing purposes.
"""

import logging
import os
import sys
import threading
import time
import traceback

from rucio.common.config import config_get, config_get_int
from rucio.common.utils import generate_uuid
from rucio.core import did, rse, replica, rule
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import DIDType
from rucio.db.session import get_session
from rucio.rse import rsemanager

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("dogpile").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def request_transfer(once=False, src=None, dst=None):
    """
    Main loop to request a new transfer.
    """

    logging.info('request: starting')

    site_a = 'RSE%s' % generate_uuid().upper()
    site_b = 'RSE%s' % generate_uuid().upper()

    scheme = 'https'
    impl = 'rucio.rse.protocols.webdav.Default'
    if not src.startswith('https://'):
        scheme = 'srm'
        impl = 'rucio.rse.protocols.srm.Default'
        srctoken = src.split(':')[0]
        dsttoken = dst.split(':')[0]

    tmp_proto = {
        'impl': impl,
        'scheme': scheme,
        'domains': {
            'lan': {'read': 1, 'write': 1, 'delete': 1},
            'wan': {'read': 1, 'write': 1, 'delete': 1}}}

    rse.add_rse(site_a)
    tmp_proto['hostname'] = src.split(':')[1][2:]
    tmp_proto['port'] = src.split(':')[2].split('/')[0]
    tmp_proto['prefix'] = '/'.join([''] + src.split(':')[2].split('/')[1:])
    if scheme == 'srm':
        tmp_proto['extended_attributes'] = {'space_token': srctoken}
    rse.add_protocol(site_a, tmp_proto)

    tmp_proto = {
        'impl': impl,
        'scheme': scheme,
        'domains': {
            'lan': {'read': 1, 'write': 1, 'delete': 1},
            'wan': {'read': 1, 'write': 1, 'delete': 1}}}

    rse.add_rse(site_b)
    tmp_proto['hostname'] = dst.split(':')[1][2:]
    tmp_proto['port'] = dst.split(':')[2].split('/')[0]
    tmp_proto['prefix'] = '/'.join([''] + dst.split(':')[2].split('/')[1:])
    if scheme == 'srm':
        tmp_proto['extended_attributes'] = {'space_token': dsttoken}
    rse.add_protocol(site_b, tmp_proto)

    si = rsemanager.get_rse_info(site_a)

    session = get_session()

    logging.info('request: started')

    while not graceful_stop.is_set():

        try:

            ts = time.time()

            tmp_name = generate_uuid()

            # add a new dataset
            did.add_did(scope='mock', name='dataset-%s' % tmp_name,
                        type=DIDType.DATASET, account='root', session=session)

            # construct PFN
            pfn = rsemanager.lfns2pfns(si, lfns=[{'scope': 'mock', 'name': 'file-%s' % tmp_name}])['mock:file-%s' % tmp_name]

            # create the directories if needed
            p = rsemanager.create_protocol(si, operation='write', scheme=scheme)
            p.connect()
            try:
                p.mkdir(pfn)
            except:
                pass

            # upload the test file
            try:
                fp = os.path.dirname(config_get('injector', 'file'))
                fn = os.path.basename(config_get('injector', 'file'))
                p.put(fn, pfn, source_dir=fp)
            except:
                logging.critical('Could not upload, removing temporary DID: %s' % str(sys.exc_info()))
                did.delete_dids([{'scope': 'mock', 'name': 'dataset-%s' % tmp_name}], account='root', session=session)
                break

            # add the replica
            replica.add_replica(rse=site_a, scope='mock', name='file-%s' % tmp_name,
                                bytes=config_get_int('injector', 'bytes'),
                                adler32=config_get('injector', 'adler32'),
                                md5=config_get('injector', 'md5'),
                                account='root', session=session)

            # to the dataset
            did.attach_dids(scope='mock', name='dataset-%s' % tmp_name, dids=[{'scope': 'mock',
                                                                               'name': 'file-%s' % tmp_name,
                                                                               'bytes': config_get('injector', 'bytes')}],
                            account='root', session=session)

            # add rule for the dataset
            ts = time.time()

            rule.add_rule(dids=[{'scope': 'mock', 'name': 'dataset-%s' % tmp_name}],
                          account='root',
                          copies=1,
                          rse_expression=site_b,
                          grouping='ALL',
                          weight=None,
                          lifetime=None,
                          locked=False,
                          subscription_id=None,
                          session=session)

            logging.info('added rule for %s for DID mock:%s' % (site_b, tmp_name))
            record_timer('daemons.mock.conveyorinjector.add_rule', (time.time()-ts)*1000)

            record_counter('daemons.mock.conveyorinjector.request_transfer')

            session.commit()
        except:
            session.rollback()
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('request: graceful stop requested')

    logging.info('request: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, src=None, dst=None):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one conveyorinjector iteration only')
        request_transfer(once=True, src=src, dst=dst)

    else:

        logging.info('starting conveyorinjector thread')
        t = threading.Thread(target=request_transfer, kwargs={'src': src, 'dst': dst})
        t.start()
        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while t.isAlive():
            t.join(timeout=3.14)
