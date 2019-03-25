# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Ralph Vigne <ralph.vigne@cern.ch>, 2012-2015
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Tobias Wegner <twegner@cern.ch>, 2018
# - Nicolo Magini <nicolo.magini@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

import copy
import json
import os
import os.path
import socket

import logging
import time

from rucio.client.client import Client
from rucio.common.exception import (RucioException, RSEBlacklisted, DataIdentifierAlreadyExists,
                                    DataIdentifierNotFound, NoFilesUploaded, NotAllFilesUploaded,
                                    ResourceTemporaryUnavailable, ServiceUnavailable, InputValidationError)
from rucio.common.utils import adler32, execute, generate_uuid, md5, send_trace
from rucio.rse import rsemanager as rsemgr
from rucio import version


class UploadClient:

    def __init__(self, _client=None, logger=None, tracing=True):
        """
        Initialises the basic settings for an UploadClient object

        :param _client:     - Optional: rucio.client.client.Client object. If None, a new object will be created.
        :param logger:      - logging.Logger object to use for uploads. If None nothing will be logged.
        """
        if not logger:
            logger = logging.getLogger('%s.null' % __name__)
            logger.disabled = True

        self.logger = logger
        self.client = _client if _client else Client()
        self.tracing = tracing
        if not self.tracing:
            logger.debug('Tracing is turned off.')
        self.default_file_scope = 'user.' + self.client.account
        self.rses = {}

        self.trace = {}
        self.trace['hostname'] = socket.getfqdn()
        self.trace['account'] = self.client.account
        self.trace['eventType'] = 'upload'
        self.trace['eventVersion'] = version.RUCIO_VERSION[0]

    def upload(self, items, summary_file_path=None):
        """

        :param items: List of dictionaries. Each dictionary describing a file to upload. Keys:
            path                  - path of the file that will be uploaded
            rse                   - rse name (e.g. 'CERN-PROD_DATADISK') where to upload the file
            did_scope             - Optional: custom did scope (Default: user.<account>)
            did_name              - Optional: custom did name (Default: name of the file)
            dataset_scope         - Optional: custom dataset scope
            dataset_name          - Optional: custom dataset name
            force_scheme          - Optional: force a specific scheme (if PFN upload this will be overwritten) (Default: None)
            pfn                   - Optional: use a given PFN (this sets no_register to True, and no_register becomes mandatory)
            no_register           - Optional: if True, the file will not be registered in the rucio catalogue
            register_after_upload - Optional: if True, the file will be registered after successful upload
            lifetime              - Optional: the lifetime of the file after it was uploaded
            transfer_timeout      - Optional: time after the upload will be aborted
            guid                  - Optional: guid of the file
        :param summary_file_path: Optional: a path where a summary in form of a json file will be stored

        :returns: 0 on success

        :raises InputValidationError: if any input arguments are in a wrong format
        :raises RSEBlacklisted: if a given RSE is not available for writing
        :raises NoFilesUploaded: if no files were successfully uploaded
        :raises NotAllFilesUploaded: if not all files were successfully uploaded
        """
        logger = self.logger

        self.trace['uuid'] = generate_uuid()

        # check given sources, resolve dirs into files, and collect meta infos
        files = self._collect_and_validate_file_info(items)

        # check if RSE of every file is available for writing
        # and cache rse settings
        registered_dataset_dids = set()
        registered_file_dids = set()
        for file in files:
            rse = file['rse']
            if not self.rses.get(rse):
                rse_settings = self.rses.setdefault(rse, rsemgr.get_rse_info(rse))
                if rse_settings['availability_write'] != 1:
                    raise RSEBlacklisted('%s is blacklisted for writing. No actions have been taken' % rse)

            dataset_scope = file.get('dataset_scope')
            dataset_name = file.get('dataset_name')
            if dataset_scope and dataset_name:
                dataset_did_str = ('%s:%s' % (dataset_scope, dataset_name))
                file['dataset_did_str'] = dataset_did_str
                registered_dataset_dids.add(dataset_did_str)

            registered_file_dids.add('%s:%s' % (file['did_scope'], file['did_name']))

        wrong_dids = registered_file_dids.intersection(registered_dataset_dids)
        if len(wrong_dids):
            raise InputValidationError('DIDs used to address both files and datasets: %s' % str(wrong_dids))

        # clear this set again to ensure that we only try to register datasets once
        registered_dataset_dids = set()
        num_succeeded = 0
        summary = []
        for file in files:
            basename = file['basename']
            logger.info('Preparing upload for file %s' % basename)

            no_register = file.get('no_register')
            register_after_upload = file.get('register_after_upload') and not no_register
            pfn = file.get('pfn')
            force_scheme = file.get('force_scheme')
            delete_existing = False

            self.trace['scope'] = file['did_scope']
            self.trace['datasetScope'] = file.get('dataset_scope', '')
            self.trace['dataset'] = file.get('dataset_name', '')
            self.trace['remoteSite'] = rse
            self.trace['filesize'] = file['bytes']

            file_did = {'scope': file['did_scope'], 'name': file['did_name']}
            dataset_did_str = file.get('dataset_did_str')

            rse = file['rse']
            rse_settings = self.rses[rse]
            is_deterministic = rse_settings.get('deterministic', True)
            if not is_deterministic and not pfn:
                logger.error('PFN has to be defined for NON-DETERMINISTIC RSE.')
                continue
            if pfn and not is_deterministic:
                logger.warning('Upload with given pfn implies that no_register is True, except non-deterministic RSEs')
                no_register = True

            if not no_register and not register_after_upload:
                self._register_file(file, registered_dataset_dids)

            # if register_after_upload, file should be overwritten if it is not registered
            # otherwise if file already exists on RSE we're done
            if register_after_upload:
                if rsemgr.exists(rse_settings, file_did):
                    try:
                        self.client.get_did(file['did_scope'], file['did_name'])
                        logger.info('File already registered. Skipping upload.')
                        continue
                    except DataIdentifierNotFound:
                        logger.info('File already exists on RSE. Previous left overs will be overwritten.')
                        delete_existing = True
            elif not is_deterministic and not no_register:
                if rsemgr.exists(rse_settings, pfn):
                    logger.info('File already exists on RSE with given pfn. Skipping upload. Existing replica has to be removed first.')
                    continue
                elif rsemgr.exists(rse_settings, file_did):
                    logger.info('File already exists on RSE with different pfn. Skipping upload.')
                    continue
            else:
                if rsemgr.exists(rse_settings, pfn if pfn else file_did):
                    logger.info('File already exists on RSE. Skipping upload')
                    continue
            protocols = rsemgr.get_protocols_ordered(rse_settings=rse_settings, operation='write', scheme=force_scheme)
            protocols.reverse()
            success = False
            state_reason = ''
            while not success and len(protocols):
                protocol = protocols.pop()
                cur_scheme = protocol['scheme']
                logger.info('Trying upload with %s to %s' % (cur_scheme, rse))
                lfn = {}
                lfn['filename'] = basename
                lfn['scope'] = file['did_scope']
                lfn['name'] = file['did_name']
                lfn['adler32'] = file['adler32']
                lfn['filesize'] = file['bytes']

                self.trace['protocol'] = cur_scheme
                self.trace['transferStart'] = time.time()
                try:
                    state = rsemgr.upload(rse_settings=rse_settings,
                                          lfns=lfn,
                                          source_dir=file['dirname'],
                                          force_scheme=cur_scheme,
                                          force_pfn=pfn,
                                          transfer_timeout=file.get('transfer_timeout'),
                                          delete_existing=delete_existing)
                    success = state['success']
                    file['upload_result'] = state
                except (ServiceUnavailable, ResourceTemporaryUnavailable) as error:
                    logger.warning('Upload attempt failed')
                    logger.debug('Exception: %s' % str(error))
                    state_reason = str(error)

            if success:
                num_succeeded += 1
                self.trace['transferEnd'] = time.time()
                self.trace['clientState'] = 'DONE'
                file['state'] = 'A'
                logger.info('Successfully uploaded file %s' % basename)
                self._send_trace(self.trace)

                if summary_file_path:
                    summary.append(copy.deepcopy(file))

                if not no_register:
                    if register_after_upload:
                        self._register_file(file, registered_dataset_dids)
                    replica_for_api = self._convert_file_for_api(file)
                    if not self.client.update_replicas_states(rse, files=[replica_for_api]):
                        logger.warning('Failed to update replica state')

                # add file to dataset if needed
                if dataset_did_str and not no_register:
                    try:
                        self.client.attach_dids(file['dataset_scope'], file['dataset_name'], [file_did])
                    except Exception as error:
                        logger.warning('Failed to attach file to the dataset')
                        logger.debug(error)
            else:
                self.trace['clientState'] = 'FAILED'
                self.trace['stateReason'] = state_reason
                self._send_trace(self.trace)
                logger.error('Failed to upload file %s' % basename)

        if summary_file_path:
            final_summary = {}
            for file in summary:
                file_scope = file['did_scope']
                file_name = file['did_name']
                file_did_str = '%s:%s' % (file_scope, file_name)
                final_summary[file_did_str] = {'scope': file_scope,
                                               'name': file_name,
                                               'bytes': file['bytes'],
                                               'rse': file['rse'],
                                               'pfn': file['upload_result'].get('pfn', ''),
                                               'guid': file['meta']['guid'],
                                               'adler32': file['adler32'],
                                               'md5': file['md5']}
            with open(summary_file_path, 'wb') as summary_file:
                json.dump(final_summary, summary_file, sort_keys=True, indent=1)

        if num_succeeded == 0:
            raise NoFilesUploaded()
        elif num_succeeded != len(files):
            raise NotAllFilesUploaded()
        return 0

    def _register_file(self, file, registered_dataset_dids):
        """
        Registers the given file in Rucio. Creates a dataset if
        needed. Registers the file DID and creates the replication
        rule if needed. Adds a replica to the file did.
        (This function is meant to be used as class internal only)

        :param file: dictionary describing the file
        :param registered_dataset_dids: set of dataset dids that were already registered

        :raises DataIdentifierAlreadyExists: if file DID is already registered and the checksums do not match
        """
        logger = self.logger
        logger.debug('Registering file')
        rse = file['rse']
        dataset_did_str = file.get('dataset_did_str')
        # register a dataset if we need to
        if dataset_did_str and dataset_did_str not in registered_dataset_dids:
            registered_dataset_dids.add(dataset_did_str)
            try:
                logger.debug('Trying to create dataset: %s' % dataset_did_str)
                self.client.add_dataset(scope=file['dataset_scope'],
                                        name=file['dataset_name'],
                                        rules=[{'account': self.client.account,
                                                'copies': 1,
                                                'rse_expression': rse,
                                                'grouping': 'DATASET',
                                                'lifetime': file.get('lifetime')}])
                logger.info('Successfully created dataset %s' % dataset_did_str)
            except DataIdentifierAlreadyExists:
                logger.debug('Dataset %s already exists' % dataset_did_str)
        else:
            logger.debug('Skipping dataset registration')

        file_scope = file['did_scope']
        file_name = file['did_name']
        file_did = {'scope': file_scope, 'name': file_name}
        replica_for_api = self._convert_file_for_api(file)
        try:
            # if the remote checksum is different this did must not be used
            meta = self.client.get_metadata(file_scope, file_name)
            logger.info('File DID already exists')
            logger.debug('local checksum: %s, remote checksum: %s' % (file['adler32'], meta['adler32']))
            if meta['adler32'] != file['adler32']:
                logger.error('Local checksum %s does not match remote checksum %s' % (file['adler32'], meta['adler32']))
                raise DataIdentifierAlreadyExists

            # add file to rse if it is not registered yet
            replicastate = list(self.client.list_replicas([file_did], all_states=True))
            if rse not in replicastate[0]['rses']:
                self.client.add_replicas(rse=rse, files=[replica_for_api])
                logger.info('Successfully added replica in Rucio catalogue at %s' % rse)
        except DataIdentifierNotFound:
            logger.debug('File DID does not exist')
            self.client.add_replicas(rse=rse, files=[replica_for_api])
            logger.info('Successfully added replica in Rucio catalogue at %s' % rse)
            if not dataset_did_str:
                # only need to add rules for files if no dataset is given
                self.client.add_replication_rule([file_did], copies=1, rse_expression=rse, lifetime=file.get('lifetime'))
                logger.info('Successfully added replication rule at %s' % rse)

    def _get_file_guid(self, file):
        """
        Get the guid of a file, trying different strategies
        (This function is meant to be used as class internal only)

        :param file: dictionary describing the file

        :returns: the guid
        """
        guid = file.get('guid')
        if not guid and 'pool.root' in file['basename'].lower() and not file.get('no_register'):
            status, output, err = execute('pool_extractFileIdentifier %s' % file['path'])
            if status != 0:
                msg = 'Trying to upload ROOT files but pool_extractFileIdentifier tool can not be found.\n'
                msg += 'Setup your ATHENA environment and try again.'
                raise RucioException(msg)
            try:
                guid = output.splitlines()[-1].split()[0].replace('-', '').lower()
            except Exception:
                raise RucioException('Error extracting GUID from ouput of pool_extractFileIdentifier')
        elif guid:
            guid = guid.replace('-', '')
        else:
            guid = generate_uuid()
        return guid

    def _collect_file_info(self, filepath, item):
        """
        Collects infos (e.g. size, checksums, etc.) about the file and
        returns them as a dictionary
        (This function is meant to be used as class internal only)

        :param filepath: path where the file is stored
        :param item: input options for the given file

        :returns: a dictionary containing all collected info and the input options
        """
        new_item = copy.deepcopy(item)
        new_item['path'] = filepath
        new_item['dirname'] = os.path.dirname(filepath)
        new_item['basename'] = os.path.basename(filepath)

        new_item['bytes'] = os.stat(filepath).st_size
        new_item['adler32'] = adler32(filepath)
        new_item['md5'] = md5(filepath)
        new_item['meta'] = {'guid': self._get_file_guid(new_item)}
        new_item['state'] = 'C'
        if not new_item.get('did_scope'):
            new_item['did_scope'] = self.default_file_scope
        if not new_item.get('did_name'):
            new_item['did_name'] = new_item['basename']

        return new_item

    def _collect_and_validate_file_info(self, items):
        """
        Checks if there are any inconsistencies within the given input
        options and stores the output of _collect_file_info for every file
        (This function is meant to be used as class internal only)

        :param filepath: list of dictionaries with all input files and options

        :returns: a list of dictionaries containing all descriptions of the files to upload

        :raises InputValidationError: if an input option has a wrong format
        """
        logger = self.logger
        files = []
        for item in items:
            path = item.get('path')
            pfn = item.get('pfn')
            if not path:
                logger.warning('Skipping source entry because the key "path" is missing')
                continue
            if not item.get('rse'):
                logger.warning('Skipping file %s because no rse was given' % path)
                continue
            if pfn:
                item['force_scheme'] = pfn.split(':')[0]

            if os.path.isdir(path):
                dname, subdirs, fnames = next(os.walk(path))
                for fname in fnames:
                    file = self._collect_file_info(os.path.join(dname, fname), item)
                    files.append(file)
                if not len(fnames) and not len(subdirs):
                    logger.warning('Skipping %s because it is empty.' % dname)
                elif not len(fnames):
                    logger.warning('Skipping %s because it has no files in it. Subdirectories are not supported.' % dname)
            elif os.path.isfile(path):
                file = self._collect_file_info(path, item)
                files.append(file)
            else:
                logger.warning('No such file or directory: %s' % path)

        if not len(files):
            raise InputValidationError('No valid input files given')

        return files

    def _convert_file_for_api(self, file):
        """
        Creates a new dictionary that contains only the values
        that are needed for the upload with the correct keys
        (This function is meant to be used as class internal only)

        :param file: dictionary describing a file to upload

        :returns: dictionary containing not more then the needed values for the upload
        """
        replica = {}
        replica['scope'] = file['did_scope']
        replica['name'] = file['did_name']
        replica['bytes'] = file['bytes']
        replica['adler32'] = file['adler32']
        replica['md5'] = file['md5']
        replica['meta'] = file['meta']
        replica['state'] = file['state']
        pfn = file.get('pfn')
        if pfn:
            replica['pfn'] = pfn
        return replica

    def _send_trace(self, trace):
        """
        Checks if sending trace is allowed and send the trace.

        :param trace: the trace
        """
        if self.tracing:
            send_trace(trace, self.client.host, self.client.user_agent)
