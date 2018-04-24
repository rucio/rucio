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
# - Nicolo Magini <nicolo.magini@cern.ch>, 2018
# - Tobias Wegner <tobias.wegner@cern.ch>, 2018

import os
import os.path

import copy
import logging
import random
import time
import socket
import signal

from rucio.common.exception import (FileConsistencyMismatch, InputValidationError, NoFilesDownloaded,
                                    NotAllFilesDownloaded, RSEProtocolNotSupported, RSENotFound, RucioException)
from rucio.common.utils import detect_client_location, generate_uuid, send_trace, sizefmt

from rucio.client.client import Client
from Queue import Queue, Empty, deque
from threading import Thread
from rucio.rse import rsemanager as rsemgr


class DownloadClient:

    def __init__(self, _client=None, user_agent='rucio_clients', logger=None):
        """
        Initialises the basic settings for an DownloadClient object

        :param _client: Optional: rucio.client.client.Client object. If None, a new object will be created.
        :param user_agent: user_agent that is using the download client
        :param logger: logging.Logger object to use for downloads. If None nothing will be logged.
        """
        if not logger:
            logger = logging.getLogger(__name__).getChild('null')
            logger.addHandler(logging.NullHandler())

        self.logger = logger
        self.is_human_readable = True
        self.client = _client if _client else Client()
        self.user_agent = user_agent

        account_attributes = [acc for acc in self.client.list_account_attributes(self.client.account)]
        self.is_admin = False
        for attr in account_attributes[0]:
            if attr['key'] == 'admin':
                self.is_admin = attr['value'] is True
                break
        if self.is_admin:
            logger.debug('Admin mode enabled')

        self.trace_tpl = {}
        self.trace_tpl['hostname'] = socket.getfqdn()
        self.trace_tpl['account'] = self.client.account
        self.trace_tpl['eventType'] = 'download'
        self.trace_tpl['eventVersion'] = 'api'

    def download_pfns(self, items, num_threads=2, trace_custom_fields={}):
        """
        Download items with a given PFN. This function can only download files, no datasets.

        :param items: List of dictionaries. Each dictionary describing a file to download. Keys:
            pfn                 - PFN string of this file
            did                 - DID string of this file (e.g. 'scope:file.name'). Wildcards are not allowed
            rse                 - rse name (e.g. 'CERN-PROD_DATADISK'). RSE Expressions are not allowed
            base_dir            - Optional: Base directory where the downloaded files will be stored. (Default: '.')
            no_subdir           - Optional: If true, files are written directly into base_dir and existing files are overwritten. (Default: False)
            ignore_checksum     - Optional: If true, the checksum validation is skipped (for pfn downloads the checksum must be given explicitly). (Default: True)
            transfer_timeout    - Optional: Timeout time for the download protocols. (Default: None)
        :param num_threads: Suggestion of number of threads to use for the download. It will be lowered if it's too high.
        :param trace_custom_fields: Custom key value pairs to send with the traces

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState
                  clientState can be one of the following: ALREADY_DONE, DONE, FILE_NOT_FOUND, FAIL_VALIDATE, FAILED

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises RucioException: if something unexpected went wrong during the download
        """
        logger = self.logger
        trace_custom_fields['uuid'] = generate_uuid()

        logger.info('Processing %d item(s) for input' % len(items))
        input_items = []
        for item in items:
            did_str = item.get('did')
            pfn = item.get('pfn')
            rse = item.get('rse')

            if not did_str or not pfn or not rse:
                logger.debug(item)
                raise InputValidationError('The keys did, pfn, and rse are mandatory')

            logger.debug('Preparing PFN download of %s (%s) from %s' % (did_str, pfn, rse))

            if '*' in did_str:
                logger.debug(did_str)
                raise InputValidationError('Cannot use PFN download with wildcard in DID')

            did_scope, did_name = self._split_did_str(did_str)
            dest_dir_path = self._prepare_dest_dir(item.get('base_dir', '.'),
                                                   did_scope, did_name,
                                                   item.get('no_subdir'))

            item['scope'] = did_scope
            item['name'] = did_name
            item['rses'] = {rse: pfn}
            item['force_scheme'] = pfn.split(':')[0]
            item['dest_dir_path'] = dest_dir_path
            item.setdefault('ignore_checksum', True)

            input_items.append(item)

        num_files_in = len(input_items)
        output_items = self._download_multithreaded(input_items, num_threads, trace_custom_fields)
        num_files_out = len(output_items)

        if num_files_in != num_files_out:
            raise RucioException('%d items were in the input queue but only %d are in the output queue' % (num_files_in, num_files_out))

        return self._check_output(output_items)

    def download_dids(self, items, num_threads=2, trace_custom_fields={}):
        """
        Download items with given DIDs. This function can also download datasets and wildcarded DIDs.

        :param items: List of dictionaries. Each dictionary describing an item to download. Keys:
            did                 - DID string of this file (e.g. 'scope:file.name'). Wildcards are not allowed
            rse                 - Optional: rse name (e.g. 'CERN-PROD_DATADISK') or rse expression from where to download
            force_scheme        - Optional: force a specific scheme to download this item. (Default: None)
            base_dir            - Optional: base directory where the downloaded files will be stored. (Default: '.')
            no_subdir           - Optional: If true, files are written directly into base_dir and existing files are overwritten. (Default: False)
            nrandom             - Optional: if the DID addresses a dataset, nrandom files will be randomly choosen for download from the dataset
            ignore_checksum     - Optional: If true, skips the checksum validation between the downloaded file and the rucio catalouge. (Default: False)
            transfer_timeout    - Optional: Timeout time for the download protocols. (Default: None)
        :param num_threads: Suggestion of number of threads to use for the download. It will be lowered if it's too high.
        :param trace_custom_fields: Custom key value pairs to send with the traces

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises RucioException: if something unexpected went wrong during the download
        """
        logger = self.logger
        trace_custom_fields['uuid'] = generate_uuid()

        logger.info('Processing %d item(s) for input' % len(items))
        resolved_items = []
        for item in items:
            did_str = item.get('did')
            if not did_str:
                raise InputValidationError('The key did is mandatory')

            logger.debug('Processing item %s' % did_str)

            new_item = copy.deepcopy(item)

            # extend RSE expression to exclude tape RSEs for non-admin accounts
            if not self.is_admin:
                rse = new_item.get('rse')
                new_item['rse'] = 'istape=False' if not rse else '(%s)&istape=False' % rse
                logger.debug('RSE-Expression: %s' % new_item['rse'])

            # resolve any wildcards in the input dids
            did_scope, did_name = self._split_did_str(did_str)
            logger.debug('Splitted DID: %s:%s' % (did_scope, did_name))
            new_item['scope'] = did_scope
            if '*' in did_name:
                logger.debug('Resolving wildcarded DID %s' % did_str)
                for dsn in self.client.list_dids(did_scope, filters={'name': did_name}, type='all'):
                    logger.debug('%s:%s' % (did_scope, dsn))
                    new_item['name'] = dsn
                    new_item['did'] = '%s:%s' % (did_scope, dsn)
                    resolved_items.append(new_item)
            else:
                new_item['name'] = did_name
                resolved_items.append(new_item)

        input_items = []

        # get replicas for every file of the given dids
        logger.debug('%d DIDs after processing input' % len(resolved_items))
        for item in resolved_items:
            did_scope = item['scope']
            did_name = item['name']
            did_str = item['did']

            logger.debug('Processing: %s' % item)

            # get type of given did
            did_type = self.client.get_did(did_scope, did_name)['type'].upper()
            logger.debug('Type: %s' % did_type)

            # get replicas (RSEs) with PFNs for each file (especially if its a dataset)
            files_with_replicas = self.client.list_replicas([{'scope': did_scope, 'name': did_name}],
                                                            schemes=item.get('force_scheme'),
                                                            rse_expression=item.get('rse'),
                                                            client_location=detect_client_location())

            nrandom = item.get('nrandom')
            if nrandom:
                logger.info('Selecting %d random replicas from dataset %s' % (nrandom, did_str))
                files_with_replicas = list(files_with_replicas)
                random.shuffle(files_with_replicas)
                files_with_replicas = files_with_replicas[0:nrandom]

            for file_item in files_with_replicas:
                file_did_scope = file_item['scope']
                file_did_name = file_item['name']
                file_did_str = '%s:%s' % (file_did_scope, file_did_name)

                logger.debug('Queueing file: %s' % file_did_str)

                # put the input options from item into the file item
                file_item.update(item)

                dest_dir_name = file_did_scope
                if did_type == 'DATASET':
                    # if the did is a dataset, scope and name were updated wrongly
                    file_item['scope'] = file_did_scope
                    file_item['name'] = file_did_name
                    file_item['did'] = file_did_str
                    file_item['dataset_scope'] = did_scope
                    file_item['dataset_name'] = did_name
                    dest_dir_name = did_name

                dest_dir_path = self._prepare_dest_dir(item.get('base_dir', '.'),
                                                       dest_dir_name, file_did_name,
                                                       item.get('no_subdir'))
                file_item['dest_dir_path'] = dest_dir_path

                input_items.append(file_item)

        num_files_in = len(input_items)
        output_items = self._download_multithreaded(input_items, num_threads, trace_custom_fields)
        num_files_out = len(output_items)

        if num_files_in != num_files_out:
            raise RucioException('%d items were in the input queue but only %d are in the output queue' % (num_files_in, num_files_out))

        return self._check_output(output_items)

    def _download_multithreaded(self, input_items, num_threads, trace_custom_fields={}):
        """
        Starts an appropriate number of threads to download items from the input list.
        (This function is meant to be used as class internal only)

        :param input_items: list containing the input items to download
        :param num_threads: suggestion of how many threads should be started
        :param trace_custom_fields: Custom key value pairs to send with the traces

        :returns: list with output items as dictionaries
        """
        logger = self.logger

        num_files = len(input_items)
        nlimit = 5
        num_threads = max(1, num_threads)
        num_threads = min(num_files, num_threads, nlimit)

        input_queue = Queue()
        output_queue = Queue()
        input_queue.queue = deque(input_items)

        if num_threads < 2:
            logger.info('Using main thread to download %d file(s)' % num_files)
            self._download_worker(input_queue, output_queue, trace_custom_fields, '')
            return list(output_queue.queue)

        logger.info('Using %d threads to download %d files' % (num_threads, num_files))
        threads = []
        for thread_num in range(1, num_threads + 1):
            log_prefix = 'Thread %s/%s : ' % (thread_num, num_threads)
            kwargs = {'input_queue': input_queue,
                      'output_queue': output_queue,
                      'trace_custom_fields': trace_custom_fields,
                      'log_prefix': log_prefix}
            try:
                thread = Thread(target=self._download_worker, kwargs=kwargs)
                thread.start()
                threads.append(thread)
            except Exception as error:
                logger.warning('Failed to start thread %d' % thread_num)
                logger.debug(error)

        try:
            logger.debug('Waiting for threads to finish')
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            logger.warning('You pressed Ctrl+C! Exiting gracefully')
            for thread in threads:
                thread.kill_received = True
        return list(output_queue.queue)

    def _download_worker(self, input_queue, output_queue, trace_custom_fields, log_prefix):
        """
        This function runs as long as there are items in the input queue,
        downloads them and stores the output in the output queue.
        (This function is meant to be used as class internal only)

        :param input_queue: queue containing the input items to download
        :param output_queue: queue where the output items will be stored
        :param trace_custom_fields: Custom key value pairs to send with the traces
        :param log_prefix: string that will be put at the beginning of every log message
        """
        logger = self.logger

        logger.debug('%sStart processing queued downloads' % log_prefix)
        while True:
            try:
                item = input_queue.get_nowait()
            except Empty:
                break
            try:
                trace = copy.deepcopy(self.trace_tpl)
                trace.update(trace_custom_fields)
                download_result = self._download_item(item, trace, log_prefix)
                output_queue.put(download_result)
            except KeyboardInterrupt:
                logger.warning('You pressed Ctrl+C! Exiting gracefully')
                os.kill(os.getpgid(), signal.SIGINT)
                break
            except Exception as error:
                logger.error('%sFailed to download item' % log_prefix)
                logger.debug(error)

    def _download_item(self, item, trace, log_prefix=''):
        """
        Downloads the given item and sends traces for success/failure.
        (This function is meant to be used as class internal only)

        :param item: dictionary that describes the item to download
        :param trace: dictionary representing a pattern of trace that will be send
        :param log_prefix: string that will be put at the beginning of every log message

        :returns: dictionary with all attributes from the input item and a clientState attribute
        """
        logger = self.logger

        did_scope = item['scope']
        did_name = item['name']
        did_str = '%s:%s' % (did_scope, did_name)

        logger.info('%sPreparing download of %s' % (log_prefix, did_str))

        trace['scope'] = did_scope
        trace['filename'] = did_name
        trace.setdefault('dataset_scope', item.get('dataset_scope', ''))
        trace.setdefault('dataset', item.get('dataset_name', ''))
        trace.setdefault('filesize', item.get('bytes'))

        # if file already exists, set state, send trace, and return
        dest_dir_path = item['dest_dir_path']
        dest_file_path = os.path.join(dest_dir_path, did_name)
        if os.path.isfile(dest_file_path):
            logger.info('%sFile exists already locally: %s' % (log_prefix, did_str))
            item['clientState'] = 'ALREADY_DONE'

            trace['transferStart'] = time.time()
            trace['transferEnd'] = time.time()
            trace['clientState'] = 'ALREADY_DONE'
            send_trace(trace, self.client.host, self.user_agent)
            return item

        # check if file has replicas
        rse_names = list(item['rses'].keys())
        if not len(rse_names):
            logger.warning('%sFile %s has no available replicas. Cannot be downloaded' % (log_prefix, did_str))
            item['clientState'] = 'FILE_NOT_FOUND'

            trace['clientState'] = 'FILE_NOT_FOUND'
            send_trace(trace, self.client.host, self.user_agent)
            return item

        # list_replicas order is: best rse at [0]
        rse_names.reverse()

        logger.debug('%sPotential sources: %s' % (log_prefix, str(rse_names)))

        success = False
        # retry with different rses if one is not available or fails
        while not success and len(rse_names):
            rse_name = rse_names.pop()
            try:
                rse = rsemgr.get_rse_info(rse_name)
            except RSENotFound:
                logger.warning('%sCould not get info of RSE %s' % (log_prefix, rse_name))
                continue

            if not rse['availability_read']:
                logger.info('%s%s is blacklisted for reading' % (log_prefix, rse_name))
                continue

            force_scheme = item.get('force_scheme')
            try:
                protocols = rsemgr.get_protocols_ordered(rse, operation='read', scheme=force_scheme)
                protocols.reverse()
            except RSEProtocolNotSupported as error:
                logger.info('%sThe protocol specfied (%s) is not supported by %s' % (log_prefix, force_scheme, rse_name))
                logger.debug(error)
                continue

            logger.debug('%sPotential protocol(s) read: %s' % (log_prefix, protocols))

            trace['remoteSite'] = rse_name
            trace['clientState'] = 'DOWNLOAD_ATTEMPT'

            # retry with different protocols on the given rse
            while not success and len(protocols):
                protocol = protocols.pop()
                cur_scheme = protocol['scheme']
                trace['protocol'] = cur_scheme

                logger.info('%sTrying to download with %s from %s: %s ' % (log_prefix, cur_scheme, rse_name, did_str))

                attempt = 0
                retries = 2
                # do some retries with the same rse and protocol if the download fails
                while not success and attempt < retries:
                    attempt += 1
                    item['attemptnr'] = attempt

                    try:

                        start_time = time.time()
                        rsemgr.download(rse,
                                        files=item,
                                        dest_dir=dest_dir_path,
                                        force_scheme=cur_scheme,
                                        ignore_checksum=item.get('ignore_checksum', False),
                                        transfer_timeout=item.get('transfer_timeout'))
                        end_time = time.time()

                        trace['transferStart'] = start_time
                        trace['transferEnd'] = end_time
                        trace['clientState'] = 'DONE'
                        item['clientState'] = 'DONE'
                        success = True
                    except FileConsistencyMismatch as error:
                        logger.warning(str(error))
                        try:
                            pfn = item.get('pfn')
                            if not pfn:
                                pfns_dict = rsemgr.lfns2pfns(rse,
                                                             lfns={'name': did_name, 'scope': did_scope},
                                                             operation='read',
                                                             scheme=cur_scheme)
                                pfn = pfns_dict[did_str]

                            corrupted_item = copy.deepcopy(item)
                            corrupted_item['clientState'] = 'FAIL_VALIDATE'
                            corrupted_item['pfn'] = pfn
                            # self.corrupted_files.append(corrupted_item)
                        except Exception as error:
                            logger.debug('%s%s' % (log_prefix, str(error)))
                        trace['clientState'] = 'FAIL_VALIDATE'
                    except Exception as error:
                        logger.warning(str(error))
                        trace['clientState'] = str(type(error).__name__)

                    if not success:
                        logger.debug('%sFailed attempt %s/%s' % (log_prefix, attempt, retries))

                    send_trace(trace, self.client.host, self.user_agent)

        if not success:
            logger.error('%sFailed to download file %s' % (log_prefix, did_str))
            item['clientState'] = 'FAILED'
            return item

        duration = round(end_time - start_time, 2)
        size = item.get('bytes')
        size_str = sizefmt(size, self.is_human_readable)
        if size and duration:
            rate = round((size / duration) * 1e-6, 2)
            logger.info('%sFile %s successfully downloaded. %s in %s seconds = %s MBps' % (log_prefix, did_str, size_str, duration, rate))
        else:
            logger.info('%sFile %s successfully downloaded in %s seconds' % (log_prefix, did_str, duration))
        return item

    def download(self, dids, rse, protocol=None, pfn=None, nrandom=None, nprocs=3, user_agent='rucio_clients', dir='.', no_subd=False, transfer_timeout=None):
        """
        OBSOLETE! This function is kept for compability reasons and will be removed in a future release!
        """
        item_tpl = {'rse': rse,
                    'force_scheme': protocol,
                    'nrandom': nrandom,
                    'base_dir': dir,
                    'no_subdir': no_subd,
                    'transfer_timeout': transfer_timeout}
        if pfn:
            item_tpl['pfn'] = pfn
        input_items = []
        for did in dids:
            item = {}
            item.update(item_tpl)
            item['did'] = did
            input_items.append(item)

        trace_pattern = {'appid': os.environ.get('RUCIO_TRACE_APPID', None),
                         'dataset': os.environ.get('RUCIO_TRACE_DATASET', None),
                         'datasetScope': os.environ.get('RUCIO_TRACE_DATASETSCOPE', None),
                         'pq': os.environ.get('RUCIO_TRACE_PQ', None),
                         'taskid': os.environ.get('RUCIO_TRACE_TASKID', None),
                         'usrdn': os.environ.get('RUCIO_TRACE_USRDN', None)}

        if pfn:
            return self.download_pfns(input_items, nprocs, trace_pattern)
        else:
            return self.download_dids(input_items, nprocs, trace_pattern)

    def _split_did_str(self, did_str):
        """
        Splits a given DID string (e.g. 'scope1:name.file') into its scope and name part
        (This function is meant to be used as class internal only)

        :param did_str: the DID string that will be splitted

        :returns: the scope- and name part of the given DID

        :raises InputValidationError: if the given DID string is not valid
        """
        did = did_str.split(':')
        if len(did) == 2:
            did_scope = did[0]
            did_name = did[1]
        elif len(did) == 1:
            did = did_str.split('.')
            did_scope = did[0]
            if did_scope == 'user' or did_scope == 'group':
                did_scope = '%s.%s' % (did[0], did[1])
            did_name = did_str
        else:
            raise InputValidationError('%s is not a valid DID. To many colons.' % did_str)

        if did_name.endswith('/'):
            did_name = did_name[:-1]

        return did_scope, did_name

    def _prepare_dest_dir(self, base_dir, dest_dir_name, file_name, no_subdir):
        """
        Builds the final destination path for a file and:
            1. deletes existing files if no_subdir was given
            2. creates the destination directory if it's not existent
        (This function is meant to be used as class internal only)

        :param base_dir: base directory part
        :param dest_dir_name: name of the destination directory
        :param file_name: name of the file that will be downloaded
        :param no_subdir: if no subdirectory should be created

        :returns: the absolut path of the destination directory
        """
        dest_dir_path = os.path.abspath(base_dir)
        # if no subdirectory is used, existing files will be overwritten
        if no_subdir:
            dest_file_path = os.path.join(dest_dir_path, file_name)
            if os.path.isfile(dest_file_path):
                self.logger.debug('Deleting existing file: %s' % dest_file_path)
                os.remove(dest_file_path)
        else:
            dest_dir_path = os.path.join(dest_dir_path, dest_dir_name)

        if not os.path.isdir(dest_dir_path):
            os.makedirs(dest_dir_path)

        return dest_dir_path

    def _check_output(self, output_items):
        """
        Checks if all files were successfully downloaded
        (This function is meant to be used as class internal only)

        :param output_items: list of dictionaries describing the downloaded files

        :returns: output_items list

        :raises NoFilesDownloaded:
        :raises NotAllFilesDownloaded:
        """
        success_states = ['ALREADY_DONE', 'DONE']
        # failure_states = ['FILE_NOT_FOUND', 'FAIL_VALIDATE', 'FAILED']
        num_successful = 0
        num_failed = 0
        for item in output_items:
            clientState = item.get('clientState', 'FAILED')
            if clientState in success_states:
                num_successful += 1
            else:
                num_failed += 1

        if num_successful == 0:
            raise NoFilesDownloaded()
        elif num_failed > 0:
            raise NotAllFilesDownloaded()

        return output_items
