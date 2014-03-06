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

import commands
import logging
import sys
import threading
import time
import traceback

from rucio.common.config import config_get, config_get_int
from rucio.common.utils import generate_uuid
from rucio.core import did, rse, replica, request
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import DIDType, RequestType
from rucio.db.session import get_session
from rucio.rse import rsemanager

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def request_transfer(once=False, process=0, total_processes=1, thread=0, total_threads=1, davs_src=None, davs_dst=None):
    """
    Main loop to request a new transfer.
    """

    logging.info('request: starting')

    session = get_session()

    site_a = 'rse-%s' % generate_uuid()
    site_b = 'rse-%s' % generate_uuid()

    tmp_proto = {
        'impl': config_get('injector', 'impl'),
        'scheme': config_get('injector', 'scheme'),
        'domains': {
            'lan': {'read': 1, 'write': 1, 'delete': 1},
            'wan': {'read': 1, 'write': 1, 'delete': 1}}}

    rse.add_rse(site_a)
    if davs_src is not None:
        tmp_proto['hostname'] = davs_src.split(':')[1][2:]
        tmp_proto['port'] = davs_src.split(':')[2].split('/')[0]
        tmp_proto['prefix'] = '/'.join([''] + davs_src.split(':')[2].split('/')[1:])
    else:
        tmp_proto['hostname'] = config_get('injector', 'src_host')
        tmp_proto['port'] = config_get_int('injector', 'src_port')
        tmp_proto['prefix'] = config_get('injector', 'src_path')
    rse.add_protocol(site_a, tmp_proto)

    rse.add_rse(site_b)
    if davs_dst is not None:
        tmp_proto['hostname'] = davs_dst.split(':')[1][2:]
        tmp_proto['port'] = davs_dst.split(':')[2].split('/')[0]
        tmp_proto['prefix'] = '/'.join([''] + davs_dst.split(':')[2].split('/')[1:])
    else:
        tmp_proto['hostname'] = config_get('injector', 'dst_host')
        tmp_proto['port'] = config_get_int('injector', 'dst_port')
        tmp_proto['prefix'] = config_get('injector', 'dst_path')
    rse.add_protocol(site_b, tmp_proto)

    logging.info('request: started')

    while not graceful_stop.is_set():

        try:

            ts = time.time()

            tmp_name = generate_uuid()

            # add a new dataset
            did.add_did(scope='mock', name='dataset-%s' % tmp_name,
                        type=DIDType.DATASET, account='root', session=session)

            si = rsemanager.get_rse_info(site_a, session=session)

            # construct PFN
            pfn = rsemanager.lfns2pfns(si, lfns=[{'scope': 'mock', 'name': 'file-%s' % tmp_name}])['mock:file-%s' % tmp_name]

            # create the directories if needed
            p = rsemanager.create_protocol(si, operation='write', scheme='https')
            p.connect()
            try:
                p.mkdir(pfn)
            except:
                pass

            # upload the test file
            s, o = commands.getstatusoutput('curl -s -i --capath /etc/grid-security/certificates/ -E %s -L -T %s %s' % (config_get('injector', 'proxy'), config_get('injector', 'file'), pfn))
            if s != 0:
                print 'Could not upload, removing temporary DID'
                did.delete_dids([{'scope': 'mock', 'name': 'dataset-%s' % tmp_name}], account='root', session=session)
                continue

            # add the replica
            replica.add_replica(rse=site_a, scope='mock', name='file-%s' % tmp_name,
                                bytes=config_get_int('injector', 'bytes'), account='root', session=session)

            # to the dataset
            did.attach_dids(scope='mock', name='dataset-%s' % tmp_name, dids=[{'scope': 'mock',
                                                                               'name': 'file-%s' % tmp_name,
                                                                               'bytes': config_get('injector', 'bytes')}],
                            account='root', session=session)

            # request transfer
            request.queue_request('mock', 'file-%s' % tmp_name, rse.get_rse(site_b)['id'],
                                  RequestType.TRANSFER, {'random': 'metadata'}, session=session)

            logging.info('inserted transfer request for DID mock:%s' % tmp_name)

            record_timer('daemons.mock.conveyorinjector.request_transfer', (time.time()-ts)*1000)

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


def run(once=False, process=0, total_processes=1, total_threads=1, davs_src=None, davs_dst=None):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one conveyorinjector iteration only')
        request_transfer(once=True, davs_src=davs_src, davs_dst=davs_dst)

    else:

        logging.info('starting conveyorinjector threads')
        threads = [threading.Thread(target=request_transfer, kwargs={'process': process,
                                                                     'total_processes': total_processes,
                                                                     'thread': i,
                                                                     'total_threads': total_threads,
                                                                     'davs_src': davs_src,
                                                                     'davs_dst': davs_dst}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t is not None and t.isAlive()]
