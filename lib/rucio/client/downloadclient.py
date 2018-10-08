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


import copy
import logging
import os
import os.path
import random
import signal
import time

try:
    from Queue import Queue, Empty, deque
except ImportError:
    from queue import Queue, Empty, deque
from threading import Thread
from xml.etree import ElementTree

from rucio.client.client import Client
from rucio.common.exception import (InputValidationError, NoFilesDownloaded, ServiceUnavailable,
                                    NotAllFilesDownloaded, RSENotFound, RucioException, SourceNotFound)
from rucio.common.utils import adler32, md5, detect_client_location, generate_uuid, send_trace, sizefmt, execute
from rucio.rse import rsemanager as rsemgr
from rucio import version


class DownloadClient:

    def __init__(self, client=None, logger=None, check_admin=False):
        """
        Initialises the basic settings for an DownloadClient object

        :param client: Optional: rucio.client.client.Client object. If None, a new object will be created.
        :param logger: Optional: logging.Logger object to use for downloads. If None nothing will be logged.
        """
        if not logger:
            logger = logging.getLogger('%s.null' % __name__)
            logger.disabled = True

        self.logger = logger
        self.is_human_readable = True
        self.client = client if client else Client()

        self.client_location = detect_client_location()

        self.is_admin = False
        if check_admin:
            account_attributes = list(self.client.list_account_attributes(self.client.account))
            for attr in account_attributes[0]:
                if attr['key'] == 'admin':
                    self.is_admin = attr['value'] is True
                    break
        if self.is_admin:
            logger.debug('Admin mode enabled')

        self.trace_tpl = {}
        self.trace_tpl['hostname'] = self.client_location['fqdn']
        self.trace_tpl['localSite'] = self.client_location['site']
        self.trace_tpl['account'] = self.client.account
        self.trace_tpl['eventType'] = 'download'
        self.trace_tpl['eventVersion'] = 'api_' + version.RUCIO_VERSION[0]

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
                send_trace(trace, self.client.host, self.client.user_agent)
                success = True

            # DOWNLOAD, iteration over different rses unitl success
            retry_counter = 0
            while not success and len(archive_pfns):
                retry_counter += 1
                pfn = archive_pfns.pop()
                trace['rse'] = archive_replicas[0]['pfns'][pfn]['rse']
                try:
                    start_time = time.time()
                    cmd = 'xrdcp -vf %s -z %s file://%s' % (pfn, file_extract_name, dest_dir_path)
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
                    raise ServiceUnavailable(e)
                send_trace(trace, self.client.host, self.client.user_agent)
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
            item['dest_dir_path'] = dest_dir_path
            item['dest_file_path'] = dest_file_path
            item['temp_file_path'] = dest_file_path + '.part'
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
            resolve_archives    - Optional: bool indicating whether archives should be considered for download (Default: False)
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
        trace_custom_fields['uuid'] = generate_uuid()

        input_items = self._prepare_items_for_download(items)

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

        # if file already exists, set state, send trace, and return
        temp_file_path = item['temp_file_path']
        dest_file_path = item['dest_file_path']
        if os.path.isfile(dest_file_path):
            logger.info('%sFile exists already locally: %s' % (log_prefix, did_str))
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
            send_trace(trace, self.client.host, self.client.user_agent)
            return item

        success = False
        # try different PFNs until one succeeded
        i = 0
        while not success and i < len(sources):
            pfn = sources[i]['pfn']
            rse_name = sources[i]['rse']
            i += 1
            scheme = pfn.split(':')[0]

            # this is a workaround to fix that gfal doesnt use root's -z option for archives
            # this will be removed as soon as gfal has fixed this
            temp_file_path = item['temp_file_path']
            dest_file_path = item['dest_file_path']
            unzip_arg_name = '?xrdcl.unzip='
            if scheme == 'root' and unzip_arg_name in pfn:
                logger.info('%sFound xrdcl.unzip in PFN. Using xrdcp overwrite.' % log_prefix)
                filename_in_archive = ''
                pfn_filename_start = pfn.find(unzip_arg_name) + len(unzip_arg_name)
                for c in pfn[pfn_filename_start:]:
                    if c == '&' or c == '?':
                        break
                    filename_in_archive += c

                dest_file_path = os.path.join(os.path.dirname(dest_file_path), filename_in_archive)
                temp_file_path = '%s.part' % dest_file_path
                cmd = 'xrdcp -vf %s -z %s file://%s' % (pfn, filename_in_archive, temp_file_path)
                start_time = time.time()
                try:
                    logger.debug('Executing: %s' % cmd)
                    status, out, err = execute(cmd)
                except Exception as error:
                    logger.debug('xrdcp execution failed')
                    logger.debug(error)
                    continue
                end_time = time.time()
                success = (status == 0)
                if not success:
                    logger.debug('xrdcp status: %s' % status)
                    logger.debug('xrdcp stdout: %s' % out)
                    logger.debug('xrdcp stderr: %s' % err)
                    trace['clientState'] = ('%s' % err)
                    send_trace(trace, self.client.host, self.client.user_agent)
                    continue
                else:
                    break

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
                    protocol.get(pfn, temp_file_path, transfer_timeout=item.get('transfer_timeout'))
                    success = True
                except Exception as error:
                    logger.debug(error)
                    trace['clientState'] = str(type(error).__name__)

                end_time = time.time()

                if success and not item.get('ignore_checksum', False):
                    rucio_checksum = item.get('adler32')
                    local_checksum = None
                    if not rucio_checksum:
                        rucio_checksum = item.get('md5')
                        local_checksum = md5(temp_file_path)
                    else:
                        local_checksum = adler32(temp_file_path)

                    if rucio_checksum != local_checksum:
                        success = False
                        os.unlink(temp_file_path)
                        logger.warning('%sChecksum validation failed for file: %s' % (log_prefix, did_str))
                        logger.debug('Local checksum: %s, Rucio checksum: %s' % (local_checksum, rucio_checksum))
                        try:
                            self.client.declare_suspicious_file_replicas([pfn], reason='Corrupted')
                        except Exception:
                            pass
                        trace['clientState'] = 'FAIL_VALIDATE'
                if not success:
                    logger.warning('%sDownload attempt failed. Try %s/%s' % (log_prefix, attempt, retries))
                    send_trace(trace, self.client.host, self.client.user_agent)

            protocol.close()

        if not success:
            logger.error('%sFailed to download file %s' % (log_prefix, did_str))
            item['clientState'] = 'FAILED'
            return item

        logger.debug("renaming '%s' to '%s'" % (temp_file_path, dest_file_path))
        os.rename(temp_file_path, dest_file_path)

        trace['transferStart'] = start_time
        trace['transferEnd'] = end_time
        trace['clientState'] = 'DONE'
        item['clientState'] = 'DONE'
        send_trace(trace, self.client.host, self.client.user_agent)

        duration = round(end_time - start_time, 2)
        size = item.get('bytes')
        size_str = sizefmt(size, self.is_human_readable)
        if size and duration:
            rate = round((size / duration) * 1e-6, 2)
            logger.info('%sFile %s successfully downloaded. %s in %s seconds = %s MBps' % (log_prefix, did_str, size_str, duration, rate))
        else:
            logger.info('%sFile %s successfully downloaded in %s seconds' % (log_prefix, did_str, duration))
        return item

    def download_aria2c(self, items, trace_custom_fields={}):
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

        :returns: a list of dictionaries with an entry for each file, containing the input options, the did, and the clientState

        :raises InputValidationError: if one of the input items is in the wrong format
        :raises NoFilesDownloaded: if no files could be downloaded
        :raises NotAllFilesDownloaded: if not all files could be downloaded
        :raises RucioException: if something went wrong during the download (e.g. aria2c could not be started)
        """
        trace_custom_fields['uuid'] = generate_uuid()

        rpc_secret = '%x' % (random.getrandbits(64))
        rpc_auth = 'token:' + rpc_secret
        rpcproc, aria_rpc = self._start_aria2c_rpc(rpc_secret)

        for item in items:
            item['force_scheme'] = ['https', 'davs']
        input_items = self._prepare_items_for_download(items)

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
                if os.path.isfile(item['dest_file_path']):
                    logger.info('File exists already locally: %s' % file_did_str)
                    item['clientState'] = 'ALREADY_DONE'
                    trace['clientState'] = 'ALREADY_DONE'
                    send_trace(trace, self.client.host, self.client.user_agent)
                elif len(pfns) == 0:
                    logger.warning('No available source found for file: %s' % file_did_str)
                    item['clientState'] = 'FILE_NOT_FOUND'
                    trace['clientState'] = 'FILE_NOT_FOUND'
                    send_trace(trace, self.client.host, self.client.user_agent)
                else:
                    item['trace'] = trace
                    options = {'dir': item['dest_dir_path'],
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
                dest_file_path = item['dest_file_path']

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

                send_trace(trace, self.client.host, self.client.user_agent)
                del item['trace']

                aria_rpc.aria2.removeDownloadResult(rpc_auth, gid)
                del gid_to_item[gid]

            if len(stopped) > 0:
                logger.info('Active: %d, Waiting: %d, Stopped: %d' % (num_active, num_waiting, num_stopped))

        return items

    def _prepare_items_for_download(self, items):
        """
        Resolves wildcarded DIDs, get DID details (e.g. type), and collects
        the available replicas for each DID
        (This function is meant to be used as class internal only)

        :param items: list of dictionaries containing the items to prepare

        :returns: list of dictionaries, one dict for each file to download

        :raises InputValidationError: if the given input is not valid or incomplete
        """
        logger = self.logger

        logger.info('Processing %d item(s) for input' % len(items))
        resolved_items = []
        # resolve input: extend rse expression, resolve wildcards, get did type
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
                for dids in self.client.list_dids(did_scope, filters={'name': did_name}, type='all', long=True):
                    logger.debug('%s - %s:%s' % (dids['did_type'], did_scope, dids['name']))
                    new_item['type'] = dids['did_type'].upper()
                    new_item['name'] = dids['name']
                    new_item['did'] = '%s:%s' % (did_scope, dids['name'])
                    resolved_items.append(copy.deepcopy(new_item))
            else:
                new_item['type'] = self.client.get_did(did_scope, did_name)['type'].upper()
                new_item['name'] = did_name
                resolved_items.append(new_item)

        # this list will have one dict for each file to download
        file_items = []

        # get replicas for every file of the given dids
        logger.debug('%d DIDs after processing input' % len(resolved_items))
        for item in resolved_items:
            did_scope = item['scope']
            did_name = item['name']
            did_str = item['did']

            logger.debug('Processing: %s' % item)

            # since we are using metalink we need to explicitly
            # give all schemes (probably due to a bad server site implementation)
            force_scheme = item.get('force_scheme')
            if force_scheme:
                schemes = force_scheme if isinstance(force_scheme, list) else [force_scheme]
            else:
                schemes = ['davs', 'gsiftp', 'https', 'root', 'srm', 'file']

            # get PFNs of files and datasets
            metalink_str = self.client.list_replicas([{'scope': did_scope, 'name': did_name}],
                                                     schemes=schemes,
                                                     rse_expression=item.get('rse'),
                                                     client_location=self.client_location,
                                                     resolve_archives=item.get('resolve_archives', False),
                                                     metalink=True)
            files_with_pfns = self._parse_list_replica_metalink(metalink_str)

            nrandom = item.get('nrandom')
            if nrandom:
                logger.info('Selecting %d random replicas from dataset %s' % (nrandom, did_str))
                random.shuffle(files_with_pfns)
                files_with_pfns = files_with_pfns[0:nrandom]

            for file_item in files_with_pfns:
                file_did_scope = file_item['scope']
                file_did_name = file_item['name']
                file_did_str = '%s:%s' % (file_did_scope, file_did_name)

                logger.debug('Queueing file: %s' % file_did_str)

                # put the input options from item into the file item
                file_item.update(item)

                dest_dir_name = file_did_scope
                if item['type'] != 'FILE':
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
                dest_file_path = os.path.join(dest_dir_path, file_did_name)
                file_item['dest_file_path'] = dest_file_path
                file_item['temp_file_path'] = dest_file_path + '.part'

                file_items.append(file_item)

        return file_items

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

    def _parse_list_replica_metalink(self, metalink_str):
        """
        Parses the metalink string that list_replicas can return into a list of dictionaries.
        (This function is meant to be used as class internal only)

        :param metalink_str: the metalink string to be parsed

        :returns: a list with a dictionary for each file
        """
        try:
            root = ElementTree.fromstring(metalink_str)
        except Exception as error:
            self.logger.debug(metalink_str)
            raise error
        files = []

        # metalink namespace
        ns = '{urn:ietf:params:xml:ns:metalink}'

        # loop over all <file> tags of the metalink string
        for file_ml in root.findall(ns + 'file'):
            # search for identity-tag
            cur_did = file_ml.find(ns + 'identity')
            if not ElementTree.iselement(cur_did):
                raise RucioException('Failed to locate identity-tag inside %s' % ElementTree.tostring(file_ml))

            # try extracting scope,name
            scope, name = self._split_did_str(cur_did.text)

            cur_file = {'scope': scope,
                        'name': name,
                        'bytes': None,
                        'adler32': None,
                        'md5': None,
                        'sources': []}

            size = file_ml.find(ns + 'size')
            if ElementTree.iselement(size):
                cur_file['bytes'] = int(size.text)

            for cur_hash in file_ml.findall(ns + 'hash'):
                hash_type = cur_hash.get('type')
                if hash_type:
                    cur_file[hash_type] = cur_hash.text

            for rse_ml in file_ml.findall(ns + 'url'):
                # check if location attrib (rse name) is given
                rse = rse_ml.get('location')
                pfn = rse_ml.text
                cur_file['sources'].append({'pfn': pfn, 'rse': rse})

            files.append(cur_file)

        return files

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
