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
# - Nicolo Magini <nicolo.magini@cern.ch>, 2018-2019
# - Tobias Wegner <tobias.wegner@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import division

import copy
import logging
import os
import os.path
import random
import shutil
import signal
import time

try:
    from Queue import Queue, Empty, deque
except ImportError:
    from queue import Queue, Empty, deque
from threading import Thread

from rucio.client.client import Client
from rucio.common.exception import (InputValidationError, NoFilesDownloaded, ServiceUnavailable,
                                    NotAllFilesDownloaded, RSENotFound, RucioException, SourceNotFound)
from rucio.common.utils import adler32, md5, detect_client_location, generate_uuid, parse_replicas_from_string, send_trace, sizefmt, execute, parse_replicas_from_file
from rucio.rse import rsemanager as rsemgr
from rucio import version


class BaseExtractionTool:

    def __init__(self, program_name, useability_check_args, extract_args, logger):
        """
        Initialises a extraction tool object

        :param program_name: the name of the archive extraction program, e.g., unzip
        :param useability_check_args: the arguments of the extraction program to test if its installed, e.g., --version
        :param extract_args: the arguments that will be passed to the program for extraction
        :param logger: logging.Logger object
        """
        self.program_name = program_name
        self.useability_check_args = useability_check_args
        self.extract_args = extract_args
        self.logger = logger
        self.is_useable_result = None

    def is_useable(self):
        """
        Checks if the extraction tool is installed and usable

        :returns: True if it is usable otherwise False
        """
        if self.is_useable_result is not None:
            return self.is_useable_result
        self.is_usable_result = False
        cmd = '%s %s' % (self.program_name, self.useability_check_args)
        try:
            exitcode, out, err = execute(cmd)
            exitcode = int(exitcode)
            self.logger.debug('"%s" returned with exitcode %d' % (cmd, exitcode))
            self.is_usable_result = (exitcode == 0)
        except Exception as error:
            self.logger.debug('Failed to execute: "%s"' % exitcode)
            self.logger.debug(error)
        return self.is_usable_result

    def try_extraction(self, archive_file_path, file_to_extract, dest_dir_path):
        """
        Calls the extraction program to extract a file from an archive

        :param archive_file_path: path to the archive
        :param file_to_extract: file name to extract from the archive
        :param dest_dir_path: destination directory where the extracted file will be stored

        :returns: True on success otherwise False
        """
        if not self.is_useable():
            return False
        args_map = {'archive_file_path': archive_file_path,
                    'file_to_extract': file_to_extract,
                    'dest_dir_path': dest_dir_path}
        extract_args = self.extract_args % args_map
        cmd = '%s %s' % (self.program_name, extract_args)
        try:
            exitcode, out, err = execute(cmd)
            exitcode = int(exitcode)
            self.logger.debug('"%s" returned with exitcode %d' % (cmd, exitcode))
            return (exitcode == 0)
        except Exception as error:
            self.logger.debug('Failed to execute: "%s"' % exitcode)
            self.logger.debug(error)
        return False


class DownloadClient:

    def __init__(self, client=None, logger=None, tracing=True, check_admin=False):
        """
        Initialises the basic settings for an DownloadClient object

        :param client: Optional: rucio.client.client.Client object. If None, a new object will be created.
        :param logger: Optional: logging.Logger object to use for downloads. If None nothing will be logged.
        """
        if not logger:
            logger = logging.getLogger('%s.null' % __name__)
            logger.disabled = True

        self.logger = logger
        self.tracing = tracing
        if not self.tracing:
            logger.debug('Tracing is turned off.')
        self.is_human_readable = True
        self.client = client if client else Client()

        self.client_location = detect_client_location()

        self.is_tape_excluded = True
        self.is_admin = False
        if check_admin:
            account_attributes = list(self.client.list_account_attributes(self.client.account))
            for attr in account_attributes[0]:
                if attr['key'] == 'admin':
                    self.is_admin = attr['value'] is True
                    break
        if self.is_admin:
            self.is_tape_excluded = False
            logger.debug('Admin mode enabled')

        self.trace_tpl = {}
        self.trace_tpl['hostname'] = self.client_location['fqdn']
        self.trace_tpl['localSite'] = self.client_location['site']
        self.trace_tpl['account'] = self.client.account
        self.trace_tpl['eventType'] = 'download'
        self.trace_tpl['eventVersion'] = 'api_%s' % version.RUCIO_VERSION[0]

        self.use_cea_threshold = 10
        self.extraction_tools = []

        # unzip <archive_file_path> <did_name> -d <dest_dir_path>
        extract_args = '%(archive_file_path)s %(file_to_extract)s -d %(dest_dir_path)s'
        self.extraction_tools.append(BaseExtractionTool('unzip', '-v', extract_args, logger))

        # tar -C <dest_dir_path> -xf <archive_file_path>  <did_name>
        extract_args = '-C %(dest_dir_path)s -xf %(archive_file_path)s %(file_to_extract)s'
        self.extraction_tools.append(BaseExtractionTool('tar', '--version', extract_args, logger))

    def download_file_from_archive(self, items, trace_custom_fields={}):
        """
        Download items with a given PFN. This function can only download files, no datasets.

        :param items: List of dictionaries. Each dictionary describing a file to download. Keys:
            did                 - DID string of the archive file (e.g. 'scope:file.name'). Wildcards are not allowed
            archive             - DID string of the archive from which the file should be extracted
            rse                 - Optional: rse name (e.g. 'CERN-PROD_DATADISK'). RSE Expressions are allowed
            base_dir            - Optional: Base directory where the downloaded files will be stored. (Default: '.')
            no_subdir           - Optional: If true, files are written directly into base_dir and existing files are overwritten. (Default: False)
        :param trace_custom_fields: Custom key value pairs to send with the traces

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState
                  clientState can be one of the following: ALREADY_DONE, DONE, FILE_NOT_FOUND, FAIL_VALIDATE, FAILED

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises SourceNotFound: if xrdcp was unable to find the PFN
        :raises ServiceUnavailable: if xrdcp failed
        :raises RucioException: if something unexpected went wrong during the download
        """
        logger = self.logger
        trace = copy.deepcopy(self.trace_tpl)
        trace['uuid'] = generate_uuid()
        log_prefix = 'Extracting files: '

        logger.info('Processing %d item(s) for input' % len(items))
        for item in items:
            archive = item.get('archive')
            file_extract = item.get('did')
            rse_name = item.get('rse')
            if not archive or not file_extract:
                raise InputValidationError('File DID and archive DID are mandatory')
            if '*' in archive:
                logger.debug(archive)
                raise InputValidationError('Cannot use PFN download with wildcard in DID')

            file_extract_scope, file_extract_name = self._split_did_str(file_extract)
            archive_scope, archive_name = self._split_did_str(archive)

            # listing all available replicas of given archhive file
            rse_expression = 'istape=False' if not rse_name else '(%s)&istape=False' % rse_name
            archive_replicas = self.client.list_replicas([{'scope': archive_scope, 'name': archive_name}],
                                                         schemes=['root'],
                                                         rse_expression=rse_expression,
                                                         unavailable=False,
                                                         client_location=self.client_location)

            # preparing trace
            trace['scope'] = archive_scope
            trace['dataset'] = archive_name
            trace['filename'] = file_extract

            # preparing output directories
            dest_dir_path = self._prepare_dest_dir(item.get('base_dir', '.'),
                                                   os.path.join(archive_scope, archive_name + '.extracted'), file_extract,
                                                   item.get('no_subdir'))
            logger.debug('%sPreparing output destination %s' % (log_prefix, dest_dir_path))

            # validation and customisation of list of replicas
            archive_replicas = list(archive_replicas)
            if len(archive_replicas) != 1:
                raise RucioException('No replicas for DID found or dataset was given.')
            archive_pfns = archive_replicas[0]['pfns'].keys()
            if len(archive_pfns) == 0:
                raise InputValidationError('No PFNs for replicas of archive %s' % archive)

            # checking whether file already exists
            success = False
            dest_file_path = os.path.join(dest_dir_path, file_extract)
            if os.path.isfile(dest_file_path):
                logger.info('%s%s File exists already locally: %s' % (log_prefix, file_extract_name, dest_dir_path))
                trace['clientState'] = 'ALREADY_DONE'
                trace['transferStart'] = time.time()
                trace['transferEnd'] = time.time()
                self._send_trace(trace)
                success = True

            # DOWNLOAD, iteration over different rses unitl success
            retry_counter = 0
            while not success and len(archive_pfns):
                retry_counter += 1
                pfn = archive_pfns.pop()
                trace['rse'] = archive_replicas[0]['pfns'][pfn]['rse']
                try:
                    start_time = time.time()
                    cmd = 'xrdcp -vf %s -z %s %s' % (pfn, file_extract_name, dest_dir_path)
                    logger.debug('%sExecuting: %s' % (log_prefix, cmd))
                    status, out, err = execute(cmd)
                    end_time = time.time()
                    trace['transferStart'] = start_time
                    trace['transferEnd'] = end_time
                    if status == 54:
                        trace['clientState'] = 'FAILED'
                        raise SourceNotFound(err)
                    elif status != 0:
                        trace['clientState'] = 'FAILED'
                        raise RucioException(err)
                    else:
                        success = True
                        item['clientState'] = 'DONE'
                        trace['clientState'] = 'DONE'
                except Exception as e:
                    trace['clientState'] = 'FAILED'
                    trace['stateReason'] = str(ServiceUnavailable(e))
                    raise ServiceUnavailable(e)
                self._send_trace(trace)
            if not success:
                raise RucioException('Failed to download file %s after %d retries' % (file_extract_name, retry_counter))
        return self._check_output(items)

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
            item['sources'] = [{'pfn': pfn, 'rse': rse}]
            dest_file_path = os.path.join(dest_dir_path, did_name)
            item['dest_file_paths'] = [dest_file_path]
            item['temp_file_path'] = '%s.part' % dest_file_path
            options = item.setdefault('merged_options', {})
            options.setdefault('ignore_checksum', item.pop('ignore_checksum', True))
            options.setdefault('transfer_timeout', item.pop('transfer_timeout', None))

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
            did                 - DID string of this file (e.g. 'scope:file.name')
            filters             - Filter to select DIDs for download. Optional if DID is given
            rse                 - Optional: rse name (e.g. 'CERN-PROD_DATADISK') or rse expression from where to download
            no_resolve_archives - Optional: bool indicating whether archives should not be considered for download (Default: False)
            resolve_archives    - Deprecated: Use no_resolve_archives instead
            force_scheme        - Optional: force a specific scheme to download this item. (Default: None)
            base_dir            - Optional: base directory where the downloaded files will be stored. (Default: '.')
            no_subdir           - Optional: If true, files are written directly into base_dir and existing files are overwritten. (Default: False)
            nrandom             - Optional: if the DID addresses a dataset, nrandom files will be randomly choosen for download from the dataset
            ignore_checksum     - Optional: If true, skips the checksum validation between the downloaded file and the rucio catalouge. (Default: False)
            transfer_timeout    - Optional: Timeout time for the download protocols. (Default: None)
        :param num_threads: Suggestion of number of threads to use for the download. It will be lowered if it's too high.
        :param trace_custom_fields: Custom key value pairs to send with the traces.

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises RucioException: if something unexpected went wrong during the download
        """
        logger = self.logger
        trace_custom_fields['uuid'] = generate_uuid()

        logger.info('Processing %d item(s) for input' % len(items))
        download_info = self._resolve_and_merge_input_items(copy.deepcopy(items))
        did_to_options = download_info['did_to_options']
        merged_items = download_info['merged_items']

        self.logger.debug('num_unmerged_items=%d; num_dids=%d; num_merged_items=%d' % (len(items), len(did_to_options), len(merged_items)))

        logger.info('Getting sources of DIDs')
        # if one item wants to resolve archives we enable it for all items
        resolve_archives = not all(item.get('no_resolve_archives') for item in merged_items)
        merged_items_with_sources = self._get_sources(merged_items, resolve_archives=resolve_archives)
        input_items = self._prepare_items_for_download(did_to_options, merged_items_with_sources, resolve_archives=resolve_archives)

        num_files_in = len(input_items)
        output_items = self._download_multithreaded(input_items, num_threads, trace_custom_fields)
        num_files_out = len(output_items)

        if num_files_in != num_files_out:
            raise RucioException('%d items were in the input queue but only %d are in the output queue' % (num_files_in, num_files_out))

        return self._check_output(output_items)

    def download_from_metalink_file(self, item, metalink_file_path, num_threads=2, trace_custom_fields={}):
        """
        Download items using a given metalink file.

        :param item: dictionary describing an item to download. Keys:
            base_dir            - Optional: base directory where the downloaded files will be stored. (Default: '.')
            no_subdir           - Optional: If true, files are written directly into base_dir and existing files are overwritten. (Default: False)
            ignore_checksum     - Optional: If true, skips the checksum validation between the downloaded file and the rucio catalouge. (Default: False)
            transfer_timeout    - Optional: Timeout time for the download protocols. (Default: None)
        :param num_threads: Suggestion of number of threads to use for the download. It will be lowered if it's too high.
        :param trace_custom_fields: Custom key value pairs to send with the traces.

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises RucioException: if something unexpected went wrong during the download
        """
        logger = self.logger

        logger.info('Getting sources from metalink file')
        metalinks = parse_replicas_from_file(metalink_file_path)

        trace_custom_fields['uuid'] = generate_uuid()

        did_to_options = {}
        item.setdefault('destinations', set()).add((item['base_dir'], item['no_subdir']))
        for metalink in metalinks:
            did_to_options[metalink['did']] = item

        metalinks = [metalinks]
        input_items = self._prepare_items_for_download(did_to_options, metalinks)

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
            log_prefix = 'Thread %s/%s: ' % (thread_num, num_threads)
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
        trace.setdefault('datasetScope', item.get('dataset_scope', ''))
        trace.setdefault('dataset', item.get('dataset_name', ''))
        trace.setdefault('filesize', item.get('bytes'))

        dest_file_paths = item['dest_file_paths']

        # if file already exists make sure it exists at all destination paths, set state, send trace, and return
        for dest_file_path in dest_file_paths:
            if os.path.isfile(dest_file_path):
                logger.info('%sFile exists already locally: %s' % (log_prefix, did_str))
                for missing_file_path in dest_file_paths:
                    if not os.path.isfile(missing_file_path):
                        logger.debug("copying '%s' to '%s'" % (dest_file_path, missing_file_path))
                        shutil.copy2(dest_file_path, missing_file_path)
                item['clientState'] = 'ALREADY_DONE'
                trace['transferStart'] = time.time()
                trace['transferEnd'] = time.time()
                trace['clientState'] = 'ALREADY_DONE'
                send_trace(trace, self.client.host, self.client.user_agent)
                return item

        # check if file has replicas
        sources = item.get('sources')
        if not sources or not len(sources):
            logger.warning('%sNo available source found for file: %s' % (log_prefix, did_str))
            item['clientState'] = 'FILE_NOT_FOUND'

            trace['clientState'] = 'FILE_NOT_FOUND'
            self._send_trace(trace)
            return item

        # try different PFNs until one succeeded
        temp_file_path = item['temp_file_path']
        success = False
        i = 0
        while not success and i < len(sources):
            source = sources[i]
            i += 1
            pfn = source['pfn']
            rse_name = source['rse']
            scheme = pfn.split(':')[0]

            try:
                rse = rsemgr.get_rse_info(rse_name)
            except RSENotFound:
                logger.warning('%sCould not get info of RSE %s' % (log_prefix, rse_name))
                continue

            trace['remoteSite'] = rse_name
            trace['clientState'] = 'DOWNLOAD_ATTEMPT'
            trace['protocol'] = scheme

            logger.info('%sTrying to download with %s from %s: %s ' % (log_prefix, scheme, rse_name, did_str))

            try:
                protocol = rsemgr.create_protocol(rse, operation='read', scheme=scheme)
                protocol.connect()
            except Exception as error:
                logger.warning('%sFailed to create protocol for PFN: %s' % (log_prefix, pfn))
                logger.debug('scheme: %s, exception: %s' % (scheme, error))
                continue

            attempt = 0
            retries = 2
            # do some retries with the same PFN if the download fails
            while not success and attempt < retries:
                attempt += 1
                item['attemptnr'] = attempt

                if os.path.isfile(temp_file_path):
                    logger.debug('%sDeleting existing temporary file: %s' % (log_prefix, temp_file_path))
                    os.unlink(temp_file_path)

                start_time = time.time()

                try:
                    protocol.get(pfn, temp_file_path, transfer_timeout=item.get('merged_options', {}).get('transfer_timeout'))
                    success = True
                except Exception as error:
                    logger.debug(error)
                    trace['clientState'] = str(type(error).__name__)

                end_time = time.time()

                if success and not item.get('merged_options', {}).get('ignore_checksum', False):
                    rucio_checksum = item.get('adler32')
                    local_checksum = None
                    if rucio_checksum is None:
                        rucio_checksum = item.get('md5')
                        if rucio_checksum is None:
                            logger.warning('%sNo remote checksum available. Skipping validation.' % log_prefix)
                        else:
                            local_checksum = md5(temp_file_path)
                    else:
                        local_checksum = adler32(temp_file_path)

                    if rucio_checksum != local_checksum:
                        success = False
                        os.unlink(temp_file_path)
                        logger.warning('%sChecksum validation failed for file: %s' % (log_prefix, did_str))
                        logger.debug('Local checksum: %s, Rucio checksum: %s' % (local_checksum, rucio_checksum))
                        trace['clientState'] = 'FAIL_VALIDATE'
                if not success:
                    logger.warning('%sDownload attempt failed. Try %s/%s' % (log_prefix, attempt, retries))
                    self._send_trace(trace)

            protocol.close()

        if not success:
            logger.error('%sFailed to download file %s' % (log_prefix, did_str))
            item['clientState'] = 'FAILED'
            return item

        dest_file_path_iter = iter(dest_file_paths)
        first_dest_file_path = next(dest_file_path_iter)
        logger.debug("renaming '%s' to '%s'" % (temp_file_path, first_dest_file_path))
        os.rename(temp_file_path, first_dest_file_path)
        for cur_dest_file_path in dest_file_path_iter:
            logger.debug("copying '%s' to '%s'" % (first_dest_file_path, cur_dest_file_path))
            shutil.copy2(first_dest_file_path, cur_dest_file_path)

        trace['transferStart'] = start_time
        trace['transferEnd'] = end_time
        trace['clientState'] = 'DONE'
        item['clientState'] = 'DONE'
        self._send_trace(trace)

        duration = round(end_time - start_time, 2)
        size = item.get('bytes')
        size_str = sizefmt(size, self.is_human_readable)
        if size and duration:
            rate = round((size / duration) * 1e-6, 2)
            logger.info('%sFile %s successfully downloaded. %s in %s seconds = %s MBps' % (log_prefix, did_str, size_str, duration, rate))
        else:
            logger.info('%sFile %s successfully downloaded in %s seconds' % (log_prefix, did_str, duration))

        file_items_in_archive = item.get('archive_items', [])
        if len(file_items_in_archive) > 0:
            logger.info('%sExtracting %d file(s) from %s' % (log_prefix, len(file_items_in_archive), did_name))

            archive_file_path = first_dest_file_path
            for file_item in file_items_in_archive:
                extraction_ok = False
                extract_file_name = file_item['name']
                dest_file_path_iter = iter(file_item['dest_file_paths'])
                first_dest_file_path = next(dest_file_path_iter)
                dest_dir = os.path.dirname(first_dest_file_path)
                logger.debug('%sExtracting %s to %s' % (log_prefix, extract_file_name, dest_dir))
                for extraction_tool in self.extraction_tools:
                    if extraction_tool.try_extraction(archive_file_path, extract_file_name, dest_dir):
                        extraction_ok = True
                        break

                if not extraction_ok:
                    logger.error('Extraction of file %s from archive %s failed.' % (extract_file_name, did_name))
                    continue

                first_dest_file_path = os.path.join(dest_dir, extract_file_name)
                for cur_dest_file_path in dest_file_path_iter:
                    logger.debug("copying '%s' to '%s'" % (first_dest_file_path, cur_dest_file_path))
                    shutil.copy2(first_dest_file_path, cur_dest_file_path)

            if not item.get('shall_keep_archive'):
                logger.debug('%sDeleting archive %s' % (log_prefix, did_name))
                os.remove(archive_file_path)

        return item

    def download_aria2c(self, items, trace_custom_fields={}, filters={}):
        """
        Uses aria2c to download the items with given DIDs. This function can also download datasets and wildcarded DIDs.
        It only can download files that are available via https/davs.
        Aria2c needs to be installed and X509_USER_PROXY needs to be set!

        :param items: List of dictionaries. Each dictionary describing an item to download. Keys:
            did                 - DID string of this file (e.g. 'scope:file.name'). Wildcards are not allowed
            rse                 - Optional: rse name (e.g. 'CERN-PROD_DATADISK') or rse expression from where to download
            base_dir            - Optional: base directory where the downloaded files will be stored. (Default: '.')
            no_subdir           - Optional: If true, files are written directly into base_dir and existing files are overwritten. (Default: False)
            nrandom             - Optional: if the DID addresses a dataset, nrandom files will be randomly choosen for download from the dataset
            ignore_checksum     - Optional: If true, skips the checksum validation between the downloaded file and the rucio catalouge. (Default: False)
        :param trace_custom_fields: Custom key value pairs to send with the traces
        :param filters: dictionary containing filter options

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises RucioException: if something went wrong during the download (e.g. aria2c could not be started)
        """
        logger = self.logger
        trace_custom_fields['uuid'] = generate_uuid()

        rpc_secret = '%x' % (random.getrandbits(64))
        rpc_auth = 'token:%s' % rpc_secret
        rpcproc, aria_rpc = self._start_aria2c_rpc(rpc_secret)

        for item in items:
            item['force_scheme'] = ['https', 'davs']

        logger.info('Processing %d item(s) for input' % len(items))
        download_info = self._resolve_and_merge_input_items(copy.deepcopy(items))
        did_to_options = download_info['did_to_options']
        merged_items = download_info['merged_items']

        self.logger.debug('num_unmerged_items=%d; num_dids=%d; num_merged_items=%d' % (len(items), len(did_to_options), len(merged_items)))

        logger.info('Getting sources of DIDs')
        merged_items_with_sources = self._get_sources(merged_items)
        input_items = self._prepare_items_for_download(did_to_options, merged_items_with_sources, resolve_archives=False)

        try:
            output_items = self._download_items_aria2c(input_items, aria_rpc, rpc_auth, trace_custom_fields)
        except Exception as error:
            self.logger.error('Unknown exception during aria2c download')
            self.logger.debug(error)
        finally:
            try:
                aria_rpc.aria2.forceShutdown(rpc_auth)
            finally:
                rpcproc.terminate()

        return self._check_output(output_items)

    def _start_aria2c_rpc(self, rpc_secret):
        """
        Starts aria2c in RPC mode as a subprocess. Also creates
        the RPC proxy instance.
        (This function is meant to be used as class internal only)

        :param rpc_secret: the secret for the RPC proxy

        :returns: a tupel with the process and the rpc proxy objects

        :raises RucioException: if the process or the proxy could not be created
        """
        logger = self.logger
        try:
            from xmlrpclib import ServerProxy as RPCServerProxy  # py2
        except ImportError:
            from xmlrpc.client import ServerProxy as RPCServerProxy

        cmd = 'aria2c '\
              '--enable-rpc '\
              '--certificate=$X509_USER_PROXY '\
              '--private-key=$X509_USER_PROXY '\
              '--ca-certificate=/etc/pki/tls/certs/CERN-bundle.pem '\
              '--quiet=true '\
              '--allow-overwrite=true '\
              '--auto-file-renaming=false '\
              '--stop-with-process=%d '\
              '--rpc-secret=%s '\
              '--rpc-listen-all=false '\
              '--rpc-max-request-size=100M '\
              '--connect-timeout=5 '\
              '--rpc-listen-port=%d'

        logger.info('Starting aria2c rpc server...')

        # trying up to 3 random ports
        for attempt in range(3):
            port = random.randint(1024, 65534)
            logger.debug('Trying to start rpc server on port: %d' % port)
            try:
                to_exec = cmd % (os.getpid(), rpc_secret, port)
                logger.debug(to_exec)
                rpcproc = execute(to_exec, False)
            except Exception as error:
                raise RucioException('Failed to execute aria2c!', error)

            # if port is in use aria should fail to start so give it some time
            time.sleep(2)

            # did it fail?
            if rpcproc.poll() is not None:
                (out, err) = rpcproc.communicate()
                logger.debug('Failed to start aria2c with port: %d' % port)
                logger.debug('aria2c output: %s' % out)
            else:
                break

        if rpcproc.poll() is not None:
            raise RucioException('Failed to start aria2c rpc server!')

        try:
            aria_rpc = RPCServerProxy('http://localhost:%d/rpc' % port)
        except Exception as error:
            rpcproc.kill()
            raise RucioException('Failed to initialise rpc proxy!', error)
        return (rpcproc, aria_rpc)

    def _download_items_aria2c(self, items, aria_rpc, rpc_auth, trace_custom_fields={}):
        """
        Uses aria2c to download the given items. Aria2c needs to be started
        as RPC background process first and a RPC proxy is needed.
        (This function is meant to be used as class internal only)

        :param items: list of dictionaries containing one dict for each file to download
        :param aria_rcp: RPCProxy to the aria2c process
        :param rpc_auth: the rpc authentication token
        :param trace_custom_fields: Custom key value pairs to send with the traces

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState
        """
        logger = self.logger

        gid_to_item = {}  # maps an aria2c download id (gid) to the download item
        pfn_to_rse = {}
        items_to_queue = [item for item in items]

        # items get removed from gid_to_item when they are complete or failed
        while len(gid_to_item) or len(items_to_queue):
            num_queued = 0

            # queue up to 100 files and then check arias status
            while (num_queued < 100) and len(items_to_queue):
                item = items_to_queue.pop()

                file_scope = item['scope']
                file_name = item['name']
                file_did_str = '%s:%s' % (file_scope, file_name)
                trace = {'scope': file_scope,
                         'filename': file_name,
                         'datasetScope': item.get('dataset_scope', ''),
                         'dataset': item.get('dataset_name', ''),
                         'protocol': 'https',
                         'remoteSite': '',
                         'filesize': item.get('bytes', None),
                         'transferStart': time.time(),
                         'transferEnd': time.time()}
                trace.update(self.trace_tpl)
                trace.update(trace_custom_fields)

                # get pfns from all replicas
                pfns = []
                for src in item['sources']:
                    pfn = src['pfn']
                    if pfn[0:4].lower() == 'davs':
                        pfn = pfn.replace('davs', 'https', 1)
                    pfns.append(pfn)
                    pfn_to_rse[pfn] = src['rse']

                # does file exist and are sources available?
                # workaround: only consider first dest file path for aria2c download
                dest_file_path = next(iter(item['dest_file_paths']))
                if os.path.isfile(dest_file_path):
                    logger.info('File exists already locally: %s' % file_did_str)
                    item['clientState'] = 'ALREADY_DONE'
                    trace['clientState'] = 'ALREADY_DONE'
                    self._send_trace(trace)
                elif len(pfns) == 0:
                    logger.warning('No available source found for file: %s' % file_did_str)
                    item['clientState'] = 'FILE_NOT_FOUND'
                    trace['clientState'] = 'FILE_NOT_FOUND'
                    self._send_trace(trace)
                else:
                    item['trace'] = trace
                    options = {'dir': os.path.dirname(dest_file_path),
                               'out': os.path.basename(item['temp_file_path'])}
                    gid = aria_rpc.aria2.addUri(rpc_auth, pfns, options)
                    gid_to_item[gid] = item
                    num_queued += 1
                    logger.debug('Queued file: %s' % file_did_str)

            # get some statistics
            aria_stat = aria_rpc.aria2.getGlobalStat(rpc_auth)
            num_active = int(aria_stat['numActive'])
            num_waiting = int(aria_stat['numWaiting'])
            num_stopped = int(aria_stat['numStoppedTotal'])

            # save start time if one of the active downloads has started
            active = aria_rpc.aria2.tellActive(rpc_auth, ['gid', 'completedLength'])
            for dlinfo in active:
                gid = dlinfo['gid']
                if int(dlinfo['completedLength']) > 0:
                    gid_to_item[gid].setdefault('transferStart', time.time())

            stopped = aria_rpc.aria2.tellStopped(rpc_auth, -1, num_stopped, ['gid', 'status', 'files'])
            for dlinfo in stopped:
                gid = dlinfo['gid']
                item = gid_to_item[gid]

                file_scope = item['scope']
                file_name = item['name']
                file_did_str = '%s:%s' % (file_scope, file_name)
                temp_file_path = item['temp_file_path']
                # workaround: only consider first dest file path for aria2c download
                dest_file_path = next(iter(item['dest_file_paths']))

                # ensure we didnt miss the active state (e.g. a very fast download)
                start_time = item.setdefault('transferStart', time.time())
                end_time = item.setdefault('transferEnd', time.time())

                # get used pfn for traces
                trace = item['trace']
                for uri in dlinfo['files'][0]['uris']:
                    if uri['status'].lower() == 'used':
                        trace['remoteSite'] = pfn_to_rse.get(uri['uri'], '')

                trace['transferStart'] = start_time
                trace['transferEnd'] = end_time

                # ensure file exists
                status = dlinfo.get('status', '').lower()
                if status == 'complete' and os.path.isfile(temp_file_path):
                    # checksum check
                    skip_check = item.get('ignore_checksum', False)
                    rucio_checksum = 0 if skip_check else item.get('adler32')
                    local_checksum = 0 if skip_check else adler32(temp_file_path)
                    if rucio_checksum == local_checksum:
                        item['clientState'] = 'DONE'
                        trace['clientState'] = 'DONE'
                        # remove .part ending
                        os.rename(temp_file_path, dest_file_path)

                        # calculate duration
                        duration = round(end_time - start_time, 2)
                        duration = max(duration, 0.01)  # protect against 0 division
                        size = item.get('bytes', 0)
                        rate = round((size / duration) * 1e-6, 2)
                        size_str = sizefmt(size, self.is_human_readable)
                        logger.info('File %s successfully downloaded. %s in %s seconds = %s MBps' % (file_did_str,
                                                                                                     size_str,
                                                                                                     duration,
                                                                                                     rate))
                    else:
                        os.unlink(temp_file_path)
                        logger.warning('Checksum validation failed for file: %s' % file_did_str)
                        logger.debug('Local checksum: %s, Rucio checksum: %s' % (local_checksum, rucio_checksum))
                        item['clientState'] = 'FAIL_VALIDATE'
                        trace['clientState'] = 'FAIL_VALIDATE'
                else:
                    logger.error('Failed to download file: %s' % file_did_str)
                    logger.debug('Aria2c status: %s' % status)
                    item['clientState'] = 'FAILED'
                    trace['clientState'] = 'DOWNLOAD_ATTEMPT'

                self._send_trace(trace)
                del item['trace']

                aria_rpc.aria2.removeDownloadResult(rpc_auth, gid)
                del gid_to_item[gid]

            if len(stopped) > 0:
                logger.info('Active: %d, Waiting: %d, Stopped: %d' % (num_active, num_waiting, num_stopped))

        return items

    def _resolve_and_merge_input_items(self, items):
        """
        This function takes the input items given to download_dids etc. and merges them
        respecting their individual options. This way functions can operate on these items
        in batch mode. E.g., list_replicas calls are reduced.

        :param items: List of dictionaries. Each dictionary describing an input item

        :returns: a dictionary with a dictionary that maps the input DIDs to options
                  and a list with a dictionary for each merged download item

        :raises InputValidationError: if one of the input items is in the wrong format
        """
        logger = self.logger

        # check mandatory options before doing any server calls
        for item in items:
            if item.get('resolve_archives') is not None:
                logger.warning('resolve_archives option is deprecated and will be removed in a future release.')
                item.setdefault('no_resolve_archives', not item.pop('resolve_archives'))

            did = item.get('did', [])
            if len(did) == 0:
                if not item.get('filters', {}).get('scope'):
                    logger.debug(item)
                    raise InputValidationError('Item without did and filter/scope')
                item['did'] = [None]
            elif not isinstance(did, list):
                item['did'] = [did]

        distinct_keys = ['rse', 'force_scheme', 'nrandom']
        all_resolved_did_strs = set()

        did_to_options = {}
        merged_items = []
        download_info = {'did_to_options': did_to_options,
                         'merged_items': merged_items}

        while len(items) > 0:
            item = items.pop()

            filters = item.get('filters', {})
            item_dids = item.pop('did')
            if item_dids[0] is None:
                logger.debug('Resolving DIDs by using filter options')
                item_dids = []
                scope = filters.pop('scope')
                for did_name in self.client.list_dids(scope, filters=filters, type='all'):
                    item_dids.append('%s:%s' % (scope, did_name))

            base_dir = item.pop('base_dir', '.')
            no_subdir = item.pop('no_subdir', False)
            ignore_checksum = item.pop('ignore_checksum', False)
            new_transfer_timeout = item.pop('transfer_timeout', None)
            resolved_dids = item.setdefault('dids', [])
            for did_str in item_dids:
                did_scope, did_name = self._split_did_str(did_str)
                tmp_did_names = []
                if '*' in did_name:
                    filters['name'] = did_name
                    tmp_did_names = list(self.client.list_dids(did_scope, filters=filters, type='all'))
                else:
                    tmp_did_names = [did_name]

                for did_name in tmp_did_names:
                    resolved_did_str = '%s:%s' % (did_scope, did_name)
                    options = did_to_options.setdefault(resolved_did_str, {})
                    options.setdefault('destinations', set()).add((base_dir, no_subdir))

                    if resolved_did_str in all_resolved_did_strs:
                        # in this case the DID was already given in another item
                        # the options of this DID will be ignored and the options of the first item that contained the DID will be used
                        # another approach would be to compare the options and apply the more relaxed options
                        logger.debug('Ignoring further options of DID: %s' % resolved_did_str)
                        continue

                    options['ignore_checksum'] = (options.get('ignore_checksum') or ignore_checksum)
                    cur_transfer_timeout = options.setdefault('transfer_timeout', None)
                    if cur_transfer_timeout is not None and new_transfer_timeout is not None:
                        options['transfer_timeout'] = max(int(cur_transfer_timeout), int(new_transfer_timeout))
                    elif new_transfer_timeout is not None:
                        options['transfer_timeout'] = int(new_transfer_timeout)

                    resolved_dids.append({'scope': did_scope, 'name': did_name})
                    all_resolved_did_strs.add(resolved_did_str)

            if len(resolved_dids) == 0:
                logger.warning('An item didnt have any DIDs after resolving the input. Ignoring it.')
                logger.debug(item)
                continue

            was_merged = False
            for merged_item in merged_items:
                if all(item.get(k) == merged_item.get(k) for k in distinct_keys):
                    merged_item['dids'].extend(resolved_dids)
                    was_merged = True
                    break
            if not was_merged:
                item['dids'] = resolved_dids
                merged_items.append(item)
        return download_info

    def _get_sources(self, merged_items, resolve_archives=True):
        """
        Get sources (PFNs) of the DIDs.

        :param merged_items: list of dictionaries. Each dictionary describes a bunch of DIDs to download

        :returns: list of list of dictionaries.
        """
        logger = self.logger
        merged_items_with_sources = []
        for item in merged_items:
            # since we're using metalink we need to explicitly give all schemes
            schemes = item.get('force_scheme')
            if schemes:
                schemes = schemes if isinstance(schemes, list) else [schemes]
            logger.debug('schemes: %s' % schemes)

            # extend RSE expression to exclude tape RSEs for non-admin accounts
            rse_expression = item.get('rse')
            if self.is_tape_excluded:
                rse_expression = '*\istape=true' if not rse_expression else '(%s)\istape=true' % rse_expression
            logger.debug('rse_expression: %s' % rse_expression)

            # get PFNs of files and datasets
            logger.debug('num DIDs for list_replicas call: %d' % len(item['dids']))

            metalink_str = self.client.list_replicas(item['dids'],
                                                     schemes=schemes,
                                                     rse_expression=rse_expression,
                                                     client_location=self.client_location,
                                                     resolve_archives=resolve_archives,
                                                     resolve_parents=True,
                                                     metalink=True)
            file_items = parse_replicas_from_string(metalink_str)
            logger.debug('num resolved files: %s' % len(file_items))

            nrandom = item.get('nrandom')
            if nrandom:
                logger.info('Selecting %d random replicas from DID(s): %s' % (nrandom, item['dids']))
                random.shuffle(file_items)
                file_items = file_items[0:nrandom]
                merged_items_with_sources.append(file_items)
            else:
                merged_items_with_sources.append(file_items)
        return merged_items_with_sources

    def _prepare_items_for_download(self, did_to_options, merged_items_with_sources, resolve_archives=True):
        """
        Optimises the amount of files to download
        (This function is meant to be used as class internal only)

        :param did_to_options: dictionary that maps each input DID to some input options
        :param merged_items_with_sources: list of dictionaries. Each dictionary describes a bunch of DIDs to download

        :returns: list of dictionaries. Each dictionary describes an element to download

        :raises InputValidationError: if the given input is not valid or incomplete
        """
        logger = self.logger
        if resolve_archives:
            # perhaps we'll need an extraction tool so check what is installed
            self.extraction_tools = [tool for tool in self.extraction_tools if tool.is_useable()]
            if len(self.extraction_tools) < 1:
                logger.warning('Archive resolution is enabled but no extraction tool is available. '
                               'Sources whose protocol doesnt support extraction wont be considered for download.')

        # maps file item IDs (fiid) to the file item object
        fiid_to_file_item = {}

        # list of all file item objects
        all_file_items = []

        # cea -> client_extract archives to avoid confusion with archives that dont need explicit extraction
        # this dict will contain all ids of cea's that definitely will be downloaded
        cea_id_pure_to_fiids = {}

        # this dict will contain ids of cea's that have higher prioritised non cea sources
        cea_id_mixed_to_fiids = {}

        all_input_dids = set(did_to_options.keys())
        all_dest_file_paths = set()

        # get replicas for every file of the given dids
        logger.debug('num list_replicas calls: %d' % len(merged_items_with_sources))
        for file_items in merged_items_with_sources:
            all_file_items.extend(file_items)
            for file_item in file_items:
                # parent_dids contains all parents, so we take the intersection with the input dids
                dataset_did_strs = file_item.setdefault('parent_dids', set())
                dataset_did_strs.intersection_update(all_input_dids)

                file_did_str = file_item['did']
                file_did_scope, file_did_name = self._split_did_str(file_did_str)
                file_item['scope'] = file_did_scope
                file_item['name'] = file_did_name

                logger.debug('Queueing file: %s' % file_did_str)
                logger.debug('real parents: %s' % dataset_did_strs)
                logger.debug('options: %s' % did_to_options)

                # prepare destinations:
                # if datasets were given: prepare the destination paths for each dataset
                options = None
                dest_file_paths = file_item.get('dest_file_paths', set())
                for dataset_did_str in dataset_did_strs:
                    options = did_to_options.get(dataset_did_str)
                    if not options:
                        logger.error('No input options available for %s' % dataset_did_str)
                        continue

                    destinations = options['destinations']
                    dataset_scope, dataset_name = self._split_did_str(dataset_did_str)
                    paths = [os.path.join(self._prepare_dest_dir(dest[0], dataset_name, file_did_name, dest[1]), file_did_name) for dest in destinations]
                    if any(path in all_dest_file_paths for path in paths):
                        raise RucioException("Multiple file items with same destination file path")

                    all_dest_file_paths.update(paths)
                    dest_file_paths.update(paths)

                    # workaround: just take any given dataset for the traces and the output
                    file_item.setdefault('dataset_scope', dataset_scope)
                    file_item.setdefault('dataset_name', dataset_name)

                # if no datasets were given only prepare the given destination paths
                if len(dataset_did_strs) == 0:
                    options = did_to_options.get(file_did_str)
                    if not options:
                        logger.error('No input options available for %s' % file_did_str)
                        continue
                    destinations = options['destinations']
                    paths = [os.path.join(self._prepare_dest_dir(dest[0], file_did_scope, file_did_name, dest[1]), file_did_name) for dest in destinations]
                    if any(path in all_dest_file_paths for path in paths):
                        raise RucioException("Multiple file items with same destination file path")
                    all_dest_file_paths.update(paths)
                    dest_file_paths.update(paths)

                if options is None:
                    continue
                file_item['merged_options'] = options
                file_item['dest_file_paths'] = list(dest_file_paths)
                file_item['temp_file_path'] = '%s.part' % file_item['dest_file_paths'][0]

                # the file did str ist not an unique key for this dict because multiple calls of list_replicas
                # could result in the same DID multiple times. So we're using the id of the dictionary objects
                fiid = id(file_item)
                fiid_to_file_item[fiid] = file_item

                if resolve_archives:
                    min_cea_priority = None
                    num_non_cea_sources = 0
                    cea_ids = []
                    sources = []
                    # go through sources and check how many (non-)cea sources there are,
                    # index cea sources, or remove cea sources if there is no extraction tool
                    for source in file_item['sources']:
                        is_cea = source.get('client_extract', False)
                        if is_cea and (len(self.extraction_tools) > 0):
                            priority = int(source['priority'])
                            if min_cea_priority is None or priority < min_cea_priority:
                                min_cea_priority = priority

                            # workaround since we dont have the archive DID use the part behind the last slash of the PFN
                            # this doesn't respect the scope of the archive DID!!!
                            # and we trust that client_extract==True sources dont have any parameters at the end of the PFN
                            cea_id = source['pfn'].split('/')
                            cea_id = cea_id[-1] if len(cea_id[-1]) > 0 else cea_id[-2]
                            cea_ids.append(cea_id)

                            sources.append(source)
                        elif not is_cea:
                            num_non_cea_sources += 1
                            sources.append(source)
                        else:
                            # no extraction tool
                            logger.debug('client_extract=True; ignoring source: %s' % source['pfn'])

                    logger.debug('Prepared sources: num_sources=%d/%d; num_non_cea_sources=%d; num_cea_ids=%d'
                                 % (len(sources), len(file_item['sources']), num_non_cea_sources, len(cea_ids)))

                    file_item['sources'] = sources

                    # if there are no cea sources we are done for this item
                    if min_cea_priority is None:
                        continue
                    # decide if file item belongs to the pure or mixed map
                    # if no non-archive src exists or the highest prio src is an archive src we put it in the pure map
                    elif num_non_cea_sources == 0 or min_cea_priority == 1:
                        logger.debug('Adding fiid to cea pure map: '
                                     'num_non_cea_sources=%d; min_cea_priority=%d; num_cea_sources=%d'
                                     % (num_non_cea_sources, min_cea_priority, len(cea_ids)))
                        for cea_id in cea_ids:
                            cea_id_pure_to_fiids.setdefault(cea_id, set()).add(fiid)
                            file_item.setdefault('cea_ids_pure', set()).add(cea_id)
                    # if there are non-archive sources and archive sources we put it in the mixed map
                    elif len(cea_ids) > 0:
                        logger.debug('Adding fiid to cea mixed map: '
                                     'num_non_cea_sources=%d; min_cea_priority=%d; num_cea_sources=%d'
                                     % (num_non_cea_sources, min_cea_priority, len(cea_ids)))
                        for cea_id in cea_ids:
                            cea_id_mixed_to_fiids.setdefault(cea_id, set()).add(fiid)
                            file_item.setdefault('cea_ids_mixed', set()).add(cea_id)

        # put all archives from the mixed list into the pure list if they meet
        # certain conditions, e.g., an archive that is already in the pure list
        for cea_id_mixed in list(cea_id_mixed_to_fiids.keys()):
            fiids_mixed = cea_id_mixed_to_fiids[cea_id_mixed]
            if cea_id_mixed in cea_id_pure_to_fiids:
                # file from mixed list is already in a pure list
                logger.debug('Mixed ID is already in cea pure map: '
                             'cea_id_mixed=%s; num_fiids_mixed=%d; num_cea_pure_fiids=%d'
                             % (cea_id_mixed, len(fiids_mixed), len(cea_id_pure_to_fiids[cea_id_mixed])))
            elif len(fiids_mixed) >= self.use_cea_threshold:
                # more than use_cea_threshold files are in a common archive
                logger.debug('Number of needed files in cea reached threshold: '
                             'cea_id_mixed=%s; num_fiids_mixed=%d; threshold=%d'
                             % (cea_id_mixed, len(fiids_mixed), self.use_cea_threshold))
            else:
                # dont move from mixed list to pure list
                continue

            # first add cea_id to pure map so it can be removed from mixed map later
            cea_id_pure_to_fiids.setdefault(cea_id_mixed, set()).update(fiids_mixed)

            # now update all file_item mixed/pure maps
            for fiid_mixed in list(fiids_mixed):
                file_item = fiid_to_file_item[fiid_mixed]
                # add cea id to file_item pure map
                file_item.setdefault('cea_ids_pure', set()).add(cea_id_mixed)

                # remove file item mixed map and
                # remove references from all other mixed archives to file_item
                for cea_id_mixed2 in file_item.pop('cea_ids_mixed'):
                    cea_id_mixed_to_fiids[cea_id_mixed2].remove(fiid_mixed)

            # finally remove cea_id from mixed map
            cea_id_mixed_to_fiids.pop(cea_id_mixed)

        for file_item in all_file_items:
            cea_ids_pure = file_item.get('cea_ids_pure', set())
            cea_ids_mixed = file_item.get('cea_ids_mixed', set())

            if len(cea_ids_pure) > 0:
                logger.debug('Removing all non-cea sources of file %s' % file_item['did'])
                file_item['sources'] = [s for s in file_item['sources'] if s.get('client_extract', False)]
            elif len(cea_ids_mixed) > 0:
                logger.debug('Removing all cea sources of file %s' % file_item['did'])
                file_item['sources'] = [s for s in file_item['sources'] if not s.get('client_extract', False)]

        # reduce the amount of archives to download by removing
        # all redundant pure archives (=all files can be extracted from other archives)
        for cea_id_pure in list(cea_id_pure_to_fiids.keys()):
            # if all files of this archive are available in more than one archive the archive is redundant
            if all(len(fiid_to_file_item[fiid_pure]['cea_ids_pure']) > 1 for fiid_pure in cea_id_pure_to_fiids[cea_id_pure]):
                for fiid_pure in cea_id_pure_to_fiids[cea_id_pure]:
                    fiid_to_file_item[fiid_pure]['cea_ids_pure'].discard(cea_id_pure)
                logger.debug('Removing redundant archive %s' % cea_id_pure)
                cea_id_pure_to_fiids.pop(cea_id_pure)

        # remove all archives of a file except a single one so
        # that each file is assigned to exactly one pure archive
        for cea_id_pure in cea_id_pure_to_fiids:
            for fiid_pure in cea_id_pure_to_fiids[cea_id_pure]:
                cea_ids_pure = fiid_to_file_item[fiid_pure]['cea_ids_pure']
                for cea_id_pure_other in list(cea_ids_pure):
                    if cea_id_pure != cea_id_pure_other:
                        cea_id_pure_to_fiids[cea_id_pure_other].discard(fiid_pure)
                        cea_ids_pure.discard(cea_id_pure_other)

        download_packs = []
        cea_id_to_pack = {}
        for file_item in all_file_items:
            cea_ids = file_item.get('cea_ids_pure', set())
            if len(cea_ids) > 0:
                cea_id = next(iter(cea_ids))
                pack = cea_id_to_pack.get(cea_id)
                if pack is None:
                    scope = file_item['scope']
                    first_dest = next(iter(file_item['merged_options']['destinations']))
                    dest_path = os.path.join(self._prepare_dest_dir(first_dest[0], scope, cea_id, first_dest[1]), cea_id)
                    pack = {'scope': scope,
                            'name': cea_id,
                            'dest_file_paths': [dest_path],
                            'temp_file_path': '%s.part' % dest_path,
                            'sources': file_item['sources'],
                            'merged_options': {'ignore_checksum': True},  # we currently dont have checksums for the archive
                            'archive_items': []
                            }
                    cea_id_to_pack[cea_id] = pack
                    download_packs.append(pack)
                file_item.pop('sources')
                pack['archive_items'].append(file_item)
            else:
                download_packs.append(file_item)
        return download_packs

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

    def _send_trace(self, trace):
        """
        Checks if sending trace is allowed and send the trace.

        :param trace: the trace
        """
        if self.tracing:
            send_trace(trace, self.client.host, self.client.user_agent)
