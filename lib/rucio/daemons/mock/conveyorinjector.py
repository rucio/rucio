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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Wen Guan <wguan.icedew@gmail.com>, 2015
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

"""
ConveyorInjector is a daemon to queue file transfers for testing purposes.
"""

import logging
import os
import random
import string
import sys
import threading
import traceback

import requests

from rucio.common.config import config_get, config_get_int
from rucio.common.utils import generate_uuid
from rucio.core import account_limit, did, rse, replica, rule
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import get_session
from rucio.rse import rsemanager

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("dogpile").setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def generate_rse(endpoint, token):

    rse_name = 'RSE%s' % generate_uuid().upper()

    scheme = 'https'
    impl = 'rucio.rse.protocols.webdav.Default'
    if not endpoint.startswith('https://'):
        scheme = 'srm'
        impl = 'rucio.rse.protocols.srm.Default'

    tmp_proto = {
        'impl': impl,
        'scheme': scheme,
        'domains': {
            'lan': {'read': 1, 'write': 1, 'delete': 1},
            'wan': {'read': 1, 'write': 1, 'delete': 1}}}

    rse.add_rse(rse_name)
    tmp_proto['hostname'] = endpoint.split(':')[1][2:]
    tmp_proto['port'] = endpoint.split(':')[2].split('/')[0]
    tmp_proto['prefix'] = '/'.join([''] + endpoint.split(':')[2].split('/')[1:])
    if scheme == 'srm':
        tmp_proto['extended_attributes'] = {'space_token': token,
                                            'web_service_path': '/srm/managerv2?SFN='}
    rse.add_protocol(rse_name, tmp_proto)
    rse.add_rse_attribute(rse_name, key='fts', value='https://fts3-pilot.cern.ch:8446')

    account_limit.set_account_limit(account='root', rse_id=rsemanager.get_rse_info(rse_name)['id'], bytes=-1)

    return rsemanager.get_rse_info(rse_name)


def request_transfer(loop=1, src=None, dst=None,
                     upload=False, same_src=False, same_dst=False):
    """
    Main loop to request a new transfer.
    """

    logging.info('request: starting')

    session = get_session()
    src_rse = generate_rse(src, ''.join(random.sample(string.ascii_letters.upper(), 8)))
    dst_rse = generate_rse(dst, ''.join(random.sample(string.ascii_letters.upper(), 8)))

    logging.info('request: started')

    i = 0
    while not graceful_stop.is_set():

        if i >= loop:
            return

        try:

            if not same_src:
                src_rse = generate_rse(src, ''.join(random.sample(string.ascii_letters.upper(), 8)))

            if not same_dst:
                dst_rse = generate_rse(dst, ''.join(random.sample(string.ascii_letters.upper(), 8)))

            tmp_name = generate_uuid()

            # add a new dataset
            did.add_did(scope='mock', name='dataset-%s' % tmp_name,
                        type=DIDType.DATASET, account='root', session=session)

            # construct PFN
            pfn = rsemanager.lfns2pfns(src_rse, lfns=[{'scope': 'mock', 'name': 'file-%s' % tmp_name}])['mock:file-%s' % tmp_name]

            if upload:
                # create the directories if needed
                p = rsemanager.create_protocol(src_rse, operation='write', scheme='srm')
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
            replica.add_replica(rse=src_rse['rse'], scope='mock', name='file-%s' % tmp_name,
                                bytes=config_get_int('injector', 'bytes'),
                                adler32=config_get('injector', 'adler32'),
                                md5=config_get('injector', 'md5'),
                                account='root', session=session)
            logging.info('added replica on %s for DID mock:%s' % (src_rse['rse'], tmp_name))

            # to the dataset
            did.attach_dids(scope='mock', name='dataset-%s' % tmp_name, dids=[{'scope': 'mock',
                                                                               'name': 'file-%s' % tmp_name,
                                                                               'bytes': config_get('injector', 'bytes')}],
                            account='root', session=session)

            # add rule for the dataset
            rule.add_rule(dids=[{'scope': 'mock', 'name': 'dataset-%s' % tmp_name}],
                          account='root',
                          copies=1,
                          rse_expression=dst_rse['rse'],
                          grouping='ALL',
                          weight=None,
                          lifetime=None,
                          locked=False,
                          subscription_id=None,
                          activity='mock-injector',
                          session=session)
            logging.info('added rule for %s for DID mock:%s' % (dst_rse['rse'], tmp_name))

            session.commit()
        except:
            session.rollback()
            logging.critical(traceback.format_exc())

        i += 1

    logging.info('request: graceful stop requested')

    logging.info('request: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(loop=1, src=None, dst=None,
        upload=True, same_src=False, same_dst=False):
    """
    Starts up the conveyer threads.
    """

    logging.info('starting conveyorinjector thread')
    t = threading.Thread(target=request_transfer, kwargs={'loop': loop,
                                                          'src': src,
                                                          'dst': dst,
                                                          'upload': upload,
                                                          'same_src': same_src,
                                                          'same_dst': same_dst})
    t.start()
    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while t.isAlive():
        t.join(timeout=3.14)
