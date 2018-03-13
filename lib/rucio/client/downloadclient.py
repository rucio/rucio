# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Tomas Javurek <tomasjavurek09@gmail.com>, 2018
# - Vincent Garonne <vgaronne@gmail.com>, 2018
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018

import os
import os.path

import logging
import random
import time
import requests
import json
import socket
import signal

from rucio.client.baseclient import BaseClient
from rucio.common.exception import FileConsistencyMismatch, RSEProtocolNotSupported, RSENotFound, RucioException
from rucio.common.utils import sizefmt
from rucio.common.utils import generate_uuid

from rucio.client.client import Client
from Queue import Queue, Empty
from threading import Thread
from rucio.rse import rsemanager as rsemgr
from copy import deepcopy

client = Client()
logging.basicConfig()
logger = logging.getLogger("user")
SUCCESS = 0
FAILURE = 1

DEFAULT_SECURE_PORT = 443
DEFAULT_PORT = 80


class DownloadClient(BaseClient):
    """ This class cover all functionality related to file uploads into Rucio."""

    BASEURL = '??_downloadclient_??'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DownloadClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)
        self.trace_appid = os.environ.get('RUCIO_TRACE_APPID', None),
        self.trace_dataset = os.environ.get('RUCIO_TRACE_DATASET', None),
        self.trace_datasetscope = os.environ.get('RUCIO_TRACE_DATASETSCOPE', None),
        self.trace_pq = os.environ.get('RUCIO_TRACE_PQ', None),
        self.trace_taskid = os.environ.get('RUCIO_TRACE_TASKID', None),
        self.trace_usrdn = os.environ.get('RUCIO_TRACE_USRDN', None)

    def download(self, dids, rse, protocol='srm', pfn=None, nrandom=None, nprocs=None, user_agent='rucio_clients', dir='.', no_subd=False):

        trace_endpoint = client.host
        trace_pattern = {'hostname': socket.getfqdn(),
                         'account': client.account,
                         'uuid': generate_uuid(),
                         'eventType': 'download',
                         'eventVersion': 'api',
                         'appid': self.trace_appid,
                         'dataset': self.trace_dataset,
                         'datasetScope': self.trace_datasetscope,
                         'pq': self.trace_pq,
                         'taskid': self.trace_taskid,
                         'usrdn': self.trace_usrdn}

        # is used account an admin account?
        account_attributes = [acc for acc in client.list_account_attributes(client.account)]
        is_admin = False
        for attr in account_attributes[0]:
            if attr['key'] == 'admin' and attr['value'] is True:
                logger.debug('Admin mode enabled')
                is_admin = True
                break

        # extend RSE expression to exclude tape RSEs for non-admin accounts
        rse_expression = rse
        if not is_admin:
            rse_expression = 'istape=False'
            if rse and len(rse.strip()) > 0:
                rse_expression = '(%s)&istape=False' % rse
                logger.debug('RSE-Expression: %s' % rse_expression)

        # Extract the scope, name from the did(s)
        did_list = []
        for did in dids:
            try:
                scope, name = self.extract_scope(did)
                if name.find('*') > -1:
                    for dsn in client.list_dids(scope, filters={'name': name}):
                        did_list.append({'scope': scope, 'name': dsn})
                else:
                    did_list.append({'scope': scope, 'name': name})
            except ValueError as error:
                raise error
                return FAILURE

        if pfn:
            if not rse:
                logger.error('--rse option is mandatory in combination with --pfn!')
                return FAILURE

            if len(dids) > 1:
                dids = [dids[0]]
                logger.warning('--pfn option and multiple DIDs given! Only considering first DID...')

        summary = {}
        num_files_to_dl = {}
        input_queue = Queue()
        output_queue = Queue()

        # get replicas for every file of the given dids
        for arg_did in did_list:
            arg_didstr = '%s:%s' % (arg_did['scope'], arg_did['name'])
            summary[arg_didstr] = {}

            # get type of given did; save did if its a dataset
            files_with_replicas = []
            if not pfn:
                try:
                    did_info = client.get_did(arg_did['scope'], arg_did['name'])
                    did_type = did_info['type'].upper()
                    dataset_scope = '' if did_type == 'FILE' else arg_did['scope']
                    dataset_name = '' if did_type == 'FILE' else arg_did['name']
                except:
                    logger.error('Failed to get did info for did %s' % arg_didstr)
                    return FAILURE

                try:
                    files_with_replicas = client.list_replicas([arg_did],
                                                               schemes=None,
                                                               rse_expression=rse_expression,
                                                               metalink=None)
                except:
                    logger.error('Failed to get list of files with their replicas for DID %s' % arg_didstr)
                    return FAILURE

                files_with_replicas = [f for f in files_with_replicas]
                if nrandom:
                    random.shuffle(files_with_replicas)
                    files_with_replicas = files_with_replicas[0:nrandom]
            else:
                logger.debug('PFN option overrides replica listing')
                did_type = 'FILE'
                dataset_scope = ''
                dataset_name = ''
                files_with_replicas = [{'bytes': None,
                                        'adler32': None,
                                        'scope': arg_did['scope'],
                                        'name': arg_did['name'],
                                        'pfns': {pfn: {'rse': rse}},
                                        'rses': {rse: [pfn]}}]

            num_files_to_dl[arg_didstr] = len(files_with_replicas)
            for f in files_with_replicas:
                file_scope = f['scope']
                file_name = f['name']
                file_didstr = '%s:%s' % (file_scope, file_name)

                file_exists, dest_dir = self._file_exists(did_type,
                                                          file_scope,
                                                          file_name,
                                                          dir,
                                                          dsn=dataset_name,
                                                          no_subdir=no_subd)
                dest_dir = os.path.abspath(dest_dir)

                if file_exists:
                    logger.info('File %s already exists locally' % file_didstr)

                    out = {}
                    out['dataset_scope'] = dataset_scope
                    out['dataset_name'] = dataset_name
                    out['scope'] = file_scope
                    out['name'] = file_name
                    out['clientState'] = 'ALREADY_DONE'
                    output_queue.put(out)

                    trace = deepcopy(trace_pattern)

                    if 'datasetScope' not in trace:
                        trace['datasetScope'] = dataset_scope
                    if 'dataset' not in trace:
                        trace['dataset'] = dataset_name
                    trace.update({'scope': file_scope,
                                  'filename': file_name,
                                  'filesize': f['bytes'],
                                  'transferStart': time.time(),
                                  'transferEnd': time.time(),
                                  'clientState': 'ALREADY_DONE'})
                    self.send_trace(trace, trace_endpoint, user_agent)
                else:
                    if not os.path.isdir(dest_dir):
                        logger.debug('Destination dir not found: %s' % dest_dir)
                        try:
                            os.makedirs(dest_dir)
                        except:
                            logger.error('Failed to create missing destination directory %s' % dest_dir)
                            return FAILURE
                    if no_subd and os.path.isfile('%s/%s' % (dest_dir, file_name)):
                        # Overwrite the files
                        logger.debug('Deleteing existing files: %s' % file_name)
                        os.remove("%s/%s" % (dest_dir, file_name))
                    f['dataset_scope'] = dataset_scope
                    f['dataset_name'] = dataset_name
                    f['dest_dir'] = dest_dir
                    input_queue.put(f)

        try:
            self.download_rucio(pfn, protocol, input_queue, output_queue, trace_pattern, trace_endpoint, nprocs, user_agent, dir, no_subd)
        except Exception as error:
            logger.error('Exception during download: %s' % str(error))

        while True:
            try:
                item = output_queue.get_nowait()
                output_queue.task_done()
                ds_didstr = '%s:%s' % (item['dataset_scope'], item['dataset_name'])
                file_didstr = '%s:%s' % (item['scope'], item['name'])

                if ds_didstr in summary or file_didstr in summary:
                    if item['dataset_scope'] == '':
                        summary[file_didstr][file_didstr] = item['clientState']
                    else:
                        summary[ds_didstr][file_didstr] = item['clientState']
                    if item['clientState'] == 'CORRUPTED':
                        try:
                            # client.declare_suspicious_file_replicas([item['pfn']], reason='Corrupted')
                            logger.warning('File %s seems to be corrupted.' % item['pfn'])
                        except:
                            logger.warning('File replica %s might be corrupted. Failure to declare it bad to Rucio' % item['pfn'])
            except Empty:
                break

    def download_rucio(self, pfn, protocol, input_queue, output_queue, trace_pattern, trace_endpoint, ndownloader, user_agent, dir='.', no_subdir=False):

        total_workers = 1
        if ndownloader and not pfn:
            total_workers = ndownloader
            nlimit = 5
            if total_workers > nlimit:
                logger.warning('Cannot use more than %s parallel downloader.' % nlimit)
                total_workers = nlimit

        total_workers = min(total_workers, input_queue.qsize())

        logger.debug('Starting %d download threads' % total_workers)
        threads = []
        for worker in range(total_workers):
            kwargs = {'pfn': pfn,
                      'user_agent': user_agent,
                      'protocol': protocol,
                      'human': True,
                      'input_queue': input_queue,
                      'output_queue': output_queue,
                      'threadnb': worker + 1,
                      'total_threads': total_workers,
                      'trace_endpoint': trace_endpoint,
                      'trace_pattern': trace_pattern}
            try:
                thread = Thread(target=self._downloader, kwargs=kwargs)
                thread.start()
                threads.append(thread)
            except:
                logger.warning('Failed to start thread %d' % (worker + 1))

        try:
            logger.debug('Waiting for threads to finish')
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            logger.warning('You pressed Ctrl+C! Exiting gracefully')
            for thread in threads:
                thread.kill_received = True
        logger.debug('All threads finished')

    def _downloader(self, pfn, protocol, human, input_queue, output_queue, user_agent, threadnb, total_threads, trace_endpoint, trace_pattern):

        rse_dict = {}
        thread_prefix = 'Thread %s/%s' % (threadnb, total_threads)
        while True:
            try:
                file = input_queue.get_nowait()
            except Empty:
                return

            dest_dir = file['dest_dir']
            file_scope = file['scope']
            file_name = file['name']
            file_didstr = '%s:%s' % (file_scope, file_name)

            # arguments for rsemgr.download already known
            dlfile = {}
            dlfile['name'] = file_name
            dlfile['scope'] = file_scope
            dlfile['adler32'] = file['adler32']
            ignore_checksum = True if pfn else False
            if pfn:
                dlfile['pfn'] = pfn

            logger.info('%s : Starting the download of %s' % (thread_prefix, file_didstr))
            trace = deepcopy(trace_pattern)
            trace.update({'scope': file_scope,
                          'filename': file_name,
                          'datasetScope': file['dataset_scope'],
                          'dataset': file['dataset_name'],
                          'filesize': file['bytes']})

            rses = list(file['rses'].keys())
            if rses == []:
                logger.warning('%s : File %s has no available replicas. Cannot be downloaded.' % (thread_prefix, file_didstr))
                trace['clientState'] = 'FILE_NOT_FOUND'
                self.send_trace(trace, trace_endpoint, user_agent)
                input_queue.task_done()
                continue
            random.shuffle(rses)

            logger.debug('%s : Potential sources : %s' % (thread_prefix, str(rses)))
            success = False
            while not success and len(rses):
                rse_name = rses.pop()
                if rse_name not in rse_dict:
                    try:
                        rse_dict[rse_name] = rsemgr.get_rse_info(rse_name)
                    except RSENotFound:
                        logger.warning('%s : Could not get info of RSE %s' % (thread_prefix, rse_name))
                        continue

                rse = rse_dict[rse_name]

                if not rse['availability_read']:
                    logger.info('%s : %s is blacklisted for reading' % (thread_prefix, rse_name))
                    continue

                try:
                    if pfn:
                        protocols = [rsemgr.select_protocol(rse, operation='read', scheme=pfn.split(':')[0])]
                    else:
                        protocols = rsemgr.get_protocols_ordered(rse, operation='read', scheme=protocol)
                        protocols.reverse()
                except RSEProtocolNotSupported as error:
                    logger.info('%s : The protocol specfied (%s) is not supported by %s' % (thread_prefix, protocol, rse_name))
                    logger.debug(error)
                    continue
                logger.debug('%s : %d possible protocol(s) for read' % (thread_prefix, len(protocols)))
                trace['remoteSite'] = rse_name
                trace['clientState'] = 'DOWNLOAD_ATTEMPT'

                while not success and len(protocols):
                    protocol_retry = protocols.pop()
                    logger.debug('%s : Trying protocol %s at %s' % (thread_prefix, protocol_retry['scheme'], rse_name))
                    trace['protocol'] = protocol_retry['scheme']
                    out = {}
                    out['dataset_scope'] = file['dataset_scope']
                    out['dataset_name'] = file['dataset_name']
                    out['scope'] = file_scope
                    out['name'] = file_name

                    attempt = 0
                    retries = 2
                    while not success and attempt < retries:
                        attempt += 1
                        out['attemptnr'] = attempt

                        logger.info('%s : File %s trying from %s' % (thread_prefix, file_didstr, rse_name))
                        try:
                            trace['transferStart'] = time.time()

                            rsemgr.download(rse,
                                            files=[dlfile],
                                            dest_dir=dest_dir,
                                            force_scheme=protocol_retry['scheme'],
                                            ignore_checksum=ignore_checksum)

                            trace['transferEnd'] = time.time()
                            trace['clientState'] = 'DONE'
                            out['clientState'] = 'DONE'
                            success = True
                            output_queue.put(out)
                            logger.info('%s : File %s successfully downloaded from %s' % (thread_prefix, file_didstr, rse_name))
                        except KeyboardInterrupt:
                            logger.warning('You pressed Ctrl+C! Exiting gracefully')
                            os.kill(os.getpgid(), signal.SIGINT)
                            return
                        except FileConsistencyMismatch as error:
                            logger.warning(str(error))
                            try:
                                pfns_dict = rsemgr.lfns2pfns(rse,
                                                             lfns=[{'name': file_name, 'scope': file_scope}],
                                                             operation='read',
                                                             scheme=protocol)
                                pfn = pfns_dict[file_didstr]

                                out['clientState'] = 'CORRUPTED'
                                out['pfn'] = pfn
                                output_queue.put(out)
                            except Exception as error:
                                logger.debug('%s : %s' % (thread_prefix, str(error)))
                            trace['clientState'] = 'FAIL_VALIDATE'
                            logger.debug('%s : Failed attempt %s/%s' % (thread_prefix, attempt, retries))
                        except Exception as error:
                            logger.warning(str(error))
                            trace['clientState'] = str(type(error).__name__)
                            logger.debug('%s : Failed attempt %s/%s' % (thread_prefix, attempt, retries))

                    self.send_trace(trace, trace_endpoint, user_agent, threadnb=threadnb, total_threads=total_threads)

            if success:
                duration = round(trace['transferEnd'] - trace['transferStart'], 2)
                if pfn:
                    logger.info('%s : File %s successfully downloaded in %s seconds' % (thread_prefix, file_didstr, duration))
                else:
                    logger.info('%s : File %s successfully downloaded. %s in %s seconds = %s MBps' % (thread_prefix,
                                                                                                      file_didstr,
                                                                                                      sizefmt(file['bytes'], human),
                                                                                                      duration,
                                                                                                      round((file['bytes'] / duration) * 1e-6, 2)))
            else:
                logger.error('%s : Cannot download file %s' % (thread_prefix, file_didstr))

            input_queue.task_done()

    def extract_scope(self, did):
        # Try to extract the scope from the DSN
        if did.find(':') > -1:
            if len(did.split(':')) > 2:
                raise RucioException('Too many colons. Cannot extract scope and name')
            scope, name = did.split(':')[0], did.split(':')[1]
            if name.endswith('/'):
                name = name[:-1]
            return scope, name
        else:
            scope = did.split('.')[0]
            if did.startswith('user') or did.startswith('group'):
                scope = ".".join(did.split('.')[0:2])
            if did.endswith('/'):
                did = did[:-1]
            return scope, did

    def _file_exists(self, type, scope, name, directory, dsn=None, no_subdir=False):
        file_exists = False
        dest_dir = None
        if no_subdir:
            dest_dir = '%s' % (directory)
        else:
            if type != 'FILE':
                dest_dir = '%s/%s' % (directory, dsn)
                if os.path.isfile('%s/%s' % (dest_dir, name)):
                    file_exists = True
            else:
                dest_dir = '%s/%s' % (directory, scope)
                if os.path.isfile('%s/%s' % (dest_dir, name)):
                    file_exists = True
        return file_exists, dest_dir

    def send_trace(self, trace, trace_endpoint, user_agent, retries=5, threadnb=None, total_threads=None):

        if user_agent.startswith('pilot'):
            logger.debug('pilot detected - not sending trace')
            return 0
        else:
            if threadnb is not None and total_threads is not None:
                logger.debug('Thread %s/%s : sending trace' % (threadnb, total_threads))
            else:
                logger.debug('sending trace')

        for dummy in range(retries):
            try:
                requests.post(trace_endpoint + '/traces/', verify=False, data=json.dumps(trace))
                return 0
            except Exception as error:
                if threadnb is not None and total_threads is not None:
                    logger.debug('Thread %s/%s : %s' % (threadnb, total_threads, error))
                else:
                    logger.debug(error)
        return 1
