# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import base64
import copy
import json
import logging
import os
import os.path
import random
import socket
import time

from rucio import version
from rucio.client.client import Client
from rucio.common.config import config_get_int, config_get, config_get_bool
from rucio.common.exception import (RucioException, RSEWriteBlocked, DataIdentifierAlreadyExists, RSEOperationNotSupported,
                                    DataIdentifierNotFound, NoFilesUploaded, NotAllFilesUploaded, FileReplicaAlreadyExists,
                                    ResourceTemporaryUnavailable, ServiceUnavailable, InputValidationError, RSEChecksumUnavailable,
                                    ScopeNotFound)
from rucio.common.utils import (adler32, detect_client_location, execute, generate_uuid, make_valid_did, md5, send_trace,
                                retry, bittorrent_v2_merkle_sha256, GLOBALLY_SUPPORTED_CHECKSUMS)
from rucio.rse import rsemanager as rsemgr


class UploadClient:

    def __init__(self, _client=None, logger=None, tracing=True):
        """
        Initialises the basic settings for an UploadClient object

        :param _client:     - Optional: rucio.client.client.Client object. If None, a new object will be created.
        :param logger:      - Optional: logging.Logger object. If None, default logger will be used.
        """
        if not logger:
            self.logger = logging.log
        else:
            self.logger = logger.log

        self.client = _client if _client else Client()
        self.client_location = detect_client_location()
        # if token should be used, use only JWT tokens
        self.auth_token = self.client.auth_token if len(self.client.auth_token.split(".")) == 3 else None
        self.tracing = tracing
        if not self.tracing:
            logger(logging.DEBUG, 'Tracing is turned off.')
        self.default_file_scope = 'user.' + self.client.account
        self.rses = {}
        self.rse_expressions = {}

        self.trace = {}
        self.trace['hostname'] = socket.getfqdn()
        self.trace['account'] = self.client.account
        if self.client.vo != 'def':
            self.trace['vo'] = self.client.vo
        self.trace['eventType'] = 'upload'
        self.trace['eventVersion'] = version.RUCIO_VERSION[0]

    def upload(self, items, summary_file_path=None, traces_copy_out=None, ignore_availability=False, activity=None):
        """
        :param items: List of dictionaries. Each dictionary describing a file to upload. Keys:
            path                  - path of the file that will be uploaded
            rse                   - rse expression/name (e.g. 'CERN-PROD_DATADISK') where to upload the file
            did_scope             - Optional: custom did scope (Default: user.<account>)
            did_name              - Optional: custom did name (Default: name of the file)
            dataset_scope         - Optional: custom dataset scope
            dataset_name          - Optional: custom dataset name
            dataset_meta          - Optional: custom metadata for dataset
            impl                  - Optional: name of the protocol implementation to be used to upload this item.
            force_scheme          - Optional: force a specific scheme (if PFN upload this will be overwritten) (Default: None)
            pfn                   - Optional: use a given PFN (this sets no_register to True, and no_register becomes mandatory)
            no_register           - Optional: if True, the file will not be registered in the rucio catalogue
            register_after_upload - Optional: if True, the file will be registered after successful upload
            lifetime              - Optional: the lifetime of the file after it was uploaded
            transfer_timeout      - Optional: time after the upload will be aborted
            guid                  - Optional: guid of the file
            recursive             - Optional: if set, parses the folder structure recursively into collections
        :param summary_file_path: Optional: a path where a summary in form of a json file will be stored
        :param traces_copy_out: reference to an external list, where the traces should be uploaded
        :param ignore_availability: ignore the availability of a RSE
        :param activity: the activity set to the rule if no dataset is specified

        :returns: 0 on success

        :raises InputValidationError: if any input arguments are in a wrong format
        :raises RSEWriteBlocked: if a given RSE is not available for writing
        :raises NoFilesUploaded: if no files were successfully uploaded
        :raises NotAllFilesUploaded: if not all files were successfully uploaded
        """
        # helper to get rse from rse_expression:
        def _pick_random_rse(rse_expression):
            rses = [r['rse'] for r in self.client.list_rses(rse_expression)]  # can raise InvalidRSEExpression
            random.shuffle(rses)
            return rses[0]

        logger = self.logger
        self.trace['uuid'] = generate_uuid()

        # check given sources, resolve dirs into files, and collect meta infos
        files = self._collect_and_validate_file_info(items)
        logger(logging.DEBUG, 'Num. of files that upload client is processing: {}'.format(len(files)))

        # check if RSE of every file is available for writing
        # and cache rse settings
        registered_dataset_dids = set()
        registered_file_dids = set()
        rse_expression = None
        for file in files:
            rse_expression = file['rse']
            rse = self.rse_expressions.setdefault(rse_expression, _pick_random_rse(rse_expression))

            if not self.rses.get(rse):
                rse_settings = self.rses.setdefault(rse, rsemgr.get_rse_info(rse, vo=self.client.vo))
                if not ignore_availability and rse_settings['availability_write'] != 1:
                    raise RSEWriteBlocked('%s is not available for writing. No actions have been taken' % rse)

            dataset_scope = file.get('dataset_scope')
            dataset_name = file.get('dataset_name')
            file['rse'] = rse
            if dataset_scope and dataset_name:
                dataset_did_str = ('%s:%s' % (dataset_scope, dataset_name))
                file['dataset_did_str'] = dataset_did_str
                registered_dataset_dids.add(dataset_did_str)

            registered_file_dids.add('%s:%s' % (file['did_scope'], file['did_name']))
        wrong_dids = registered_file_dids.intersection(registered_dataset_dids)
        if len(wrong_dids):
            raise InputValidationError('DIDs used to address both files and datasets: %s' % str(wrong_dids))
        logger(logging.DEBUG, 'Input validation done.')

        # clear this set again to ensure that we only try to register datasets once
        registered_dataset_dids = set()
        num_succeeded = 0
        summary = []
        for file in files:
            basename = file['basename']
            logger(logging.INFO, 'Preparing upload for file %s' % basename)

            no_register = file.get('no_register')
            register_after_upload = file.get('register_after_upload') and not no_register
            pfn = file.get('pfn')
            force_scheme = file.get('force_scheme')
            impl = file.get('impl')
            delete_existing = False

            trace = copy.deepcopy(self.trace)
            # appending trace to list reference, if the reference exists
            if traces_copy_out is not None:
                traces_copy_out.append(trace)

            rse = file['rse']
            trace['scope'] = file['did_scope']
            trace['datasetScope'] = file.get('dataset_scope', '')
            trace['dataset'] = file.get('dataset_name', '')
            trace['remoteSite'] = rse
            trace['filesize'] = file['bytes']

            file_did = {'scope': file['did_scope'], 'name': file['did_name']}
            dataset_did_str = file.get('dataset_did_str')
            rse_settings = self.rses[rse]
            rse_sign_service = rse_settings.get('sign_url', None)
            is_deterministic = rse_settings.get('deterministic', True)
            if not is_deterministic and not pfn:
                logger(logging.ERROR, 'PFN has to be defined for NON-DETERMINISTIC RSE.')
                continue
            if pfn and is_deterministic:
                logger(logging.WARNING, 'Upload with given pfn implies that no_register is True, except non-deterministic RSEs')
                no_register = True

            # resolving local area networks
            domain = 'wan'
            rse_attributes = {}
            try:
                rse_attributes = self.client.list_rse_attributes(rse)
            except:
                logger(logging.WARNING, 'Attributes of the RSE: %s not available.' % rse)
            if (self.client_location and 'lan' in rse_settings['domain'] and 'site' in rse_attributes):
                if self.client_location['site'] == rse_attributes['site']:
                    domain = 'lan'
            logger(logging.DEBUG, '{} domain is used for the upload'.format(domain))

            # FIXME:
            # Rewrite preferred_impl selection - also check test_upload.py/test_download.py and fix impl order (see FIXME there)
            #
            # if not impl and not force_scheme:
            #    impl = self.preferred_impl(rse_settings, domain)

            if not no_register and not register_after_upload:
                self._register_file(file, registered_dataset_dids, ignore_availability=ignore_availability, activity=activity)

            # if register_after_upload, file should be overwritten if it is not registered
            # otherwise if file already exists on RSE we're done
            if register_after_upload:
                if rsemgr.exists(rse_settings, pfn if pfn else file_did, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    try:
                        self.client.get_did(file['did_scope'], file['did_name'])
                        logger(logging.INFO, 'File already registered. Skipping upload.')
                        trace['stateReason'] = 'File already exists'
                        continue
                    except DataIdentifierNotFound:
                        logger(logging.INFO, 'File already exists on RSE. Previous left overs will be overwritten.')
                        delete_existing = True
            elif not is_deterministic and not no_register:
                if rsemgr.exists(rse_settings, pfn, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    logger(logging.INFO, 'File already exists on RSE with given pfn. Skipping upload. Existing replica has to be removed first.')
                    trace['stateReason'] = 'File already exists'
                    continue
                elif rsemgr.exists(rse_settings, file_did, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    logger(logging.INFO, 'File already exists on RSE with different pfn. Skipping upload.')
                    trace['stateReason'] = 'File already exists'
                    continue
            else:
                if rsemgr.exists(rse_settings, pfn if pfn else file_did, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    logger(logging.INFO, 'File already exists on RSE. Skipping upload')
                    trace['stateReason'] = 'File already exists'
                    continue

            # protocol handling and upload
            protocols = rsemgr.get_protocols_ordered(rse_settings=rse_settings, operation='write', scheme=force_scheme, domain=domain, impl=impl)
            protocols.reverse()
            success = False
            state_reason = ''
            logger(logging.DEBUG, str(protocols))
            while not success and len(protocols):
                protocol = protocols.pop()
                cur_scheme = protocol['scheme']
                logger(logging.INFO, 'Trying upload with %s to %s' % (cur_scheme, rse))
                lfn = {}
                lfn['filename'] = basename
                lfn['scope'] = file['did_scope']
                lfn['name'] = file['did_name']

                for checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS:
                    if checksum_name in file:
                        lfn[checksum_name] = file[checksum_name]

                lfn['filesize'] = file['bytes']

                sign_service = None
                if cur_scheme == 'https':
                    sign_service = rse_sign_service

                trace['protocol'] = cur_scheme
                trace['transferStart'] = time.time()
                logger(logging.DEBUG, 'Processing upload with the domain: {}'.format(domain))
                try:
                    pfn = self._upload_item(rse_settings=rse_settings,
                                            rse_attributes=rse_attributes,
                                            lfn=lfn,
                                            source_dir=file['dirname'],
                                            domain=domain,
                                            impl=impl,
                                            force_scheme=cur_scheme,
                                            force_pfn=pfn,
                                            transfer_timeout=file.get('transfer_timeout'),
                                            delete_existing=delete_existing,
                                            sign_service=sign_service)
                    logger(logging.DEBUG, 'Upload done.')
                    success = True
                    file['upload_result'] = {0: True, 1: None, 'success': True, 'pfn': pfn}  # needs to be removed
                except (ServiceUnavailable, ResourceTemporaryUnavailable, RSEOperationNotSupported, RucioException) as error:
                    logger(logging.WARNING, 'Upload attempt failed')
                    logger(logging.INFO, 'Exception: %s' % str(error), exc_info=True)
                    state_reason = str(error)

            if success:
                num_succeeded += 1
                trace['transferEnd'] = time.time()
                trace['clientState'] = 'DONE'
                file['state'] = 'A'
                logger(logging.INFO, 'Successfully uploaded file %s' % basename)
                self._send_trace(trace)

                if summary_file_path:
                    summary.append(copy.deepcopy(file))

                if not no_register:
                    if register_after_upload:
                        self._register_file(file, registered_dataset_dids, ignore_availability=ignore_availability, activity=activity)
                    else:
                        replica_for_api = self._convert_file_for_api(file)
                        try:
                            self.client.update_replicas_states(rse, files=[replica_for_api])
                        except Exception as error:
                            logger(logging.ERROR, 'Failed to update replica state for file {}'.format(basename))
                            logger(logging.DEBUG, 'Details: {}'.format(str(error)))

                # add file to dataset if needed
                if dataset_did_str and not no_register:
                    try:
                        self.client.attach_dids(file['dataset_scope'], file['dataset_name'], [file_did])
                    except Exception as error:
                        logger(logging.WARNING, 'Failed to attach file to the dataset')
                        logger(logging.DEBUG, 'Attaching to dataset {}'.format(str(error)))
            else:
                trace['clientState'] = 'FAILED'
                trace['stateReason'] = state_reason
                self._send_trace(trace)
                logger(logging.ERROR, 'Failed to upload file %s' % basename)

        if summary_file_path:
            logger(logging.DEBUG, 'Summary will be available at {}'.format(summary_file_path))
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
                                               'guid': file['meta']['guid']}

                for checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS:
                    if checksum_name in file:
                        final_summary[file_did_str][checksum_name] = file[checksum_name]

            with open(summary_file_path, 'w') as summary_file:
                json.dump(final_summary, summary_file, sort_keys=True, indent=1)

        if num_succeeded == 0:
            raise NoFilesUploaded()
        elif num_succeeded != len(files):
            raise NotAllFilesUploaded()
        return 0

    def _add_bittorrent_meta(self, file, logger):
        if not config_get_bool('client', 'register_bittorrent_meta', default=False):
            return

        pieces_root, pieces_layers, piece_length = bittorrent_v2_merkle_sha256(os.path.join(file['dirname'], file['basename']))
        bittorrent_meta = {
            'bittorrent_pieces_root': base64.b64encode(pieces_root).decode(),
            'bittorrent_pieces_layers': base64.b64encode(pieces_layers).decode(),
            'bittorrent_piece_length': piece_length,
        }
        self.client.set_metadata_bulk(scope=file['did_scope'], name=file['did_name'], meta=bittorrent_meta)

    def _register_file(self, file, registered_dataset_dids, ignore_availability=False, activity=None):
        """
        Registers the given file in Rucio. Creates a dataset if
        needed. Registers the file DID and creates the replication
        rule if needed. Adds a replica to the file did.
        (This function is meant to be used as class internal only)

        :param file: dictionary describing the file
        :param registered_dataset_dids: set of dataset dids that were already registered
        :param ignore_availability: ignore the availability of a RSE
        :param activity: the activity set to the rule if no dataset is specified

        :raises DataIdentifierAlreadyExists: if file DID is already registered and the checksums do not match
        """
        logger = self.logger
        logger(logging.DEBUG, 'Registering file')

        # verification whether the scope exists
        account_scopes = []
        try:
            account_scopes = self.client.list_scopes_for_account(self.client.account)
        except ScopeNotFound:
            pass
        if account_scopes and file['did_scope'] not in account_scopes:
            logger(logging.WARNING, 'Scope {} not found for the account {}.'.format(file['did_scope'], self.client.account))

        rse = file['rse']
        dataset_did_str = file.get('dataset_did_str')
        # register a dataset if we need to
        if dataset_did_str and dataset_did_str not in registered_dataset_dids:
            registered_dataset_dids.add(dataset_did_str)
            try:
                logger(logging.DEBUG, 'Trying to create dataset: %s' % dataset_did_str)
                self.client.add_dataset(scope=file['dataset_scope'],
                                        name=file['dataset_name'],
                                        meta=file.get('dataset_meta'),
                                        rules=[{'account': self.client.account,
                                                'copies': 1,
                                                'rse_expression': rse,
                                                'grouping': 'DATASET',
                                                'lifetime': file.get('lifetime')}])
                logger(logging.INFO, 'Successfully created dataset %s' % dataset_did_str)
            except DataIdentifierAlreadyExists:
                logger(logging.INFO, 'Dataset %s already exists - no rule will be created' % dataset_did_str)

                if file.get('lifetime') is not None:
                    raise InputValidationError('Dataset %s exists and lifetime %s given. Prohibited to modify parent dataset lifetime.' % (dataset_did_str,
                                                                                                                                           file.get('lifetime')))
        else:
            logger(logging.DEBUG, 'Skipping dataset registration')

        file_scope = file['did_scope']
        file_name = file['did_name']
        file_did = {'scope': file_scope, 'name': file_name}
        replica_for_api = self._convert_file_for_api(file)
        try:
            # if the remote checksum is different this did must not be used
            meta = self.client.get_metadata(file_scope, file_name)
            logger(logging.INFO, 'File DID already exists')
            logger(logging.DEBUG, 'local checksum: %s, remote checksum: %s' % (file['adler32'], meta['adler32']))

            if str(meta['adler32']).lstrip('0') != str(file['adler32']).lstrip('0'):
                logger(logging.ERROR, 'Local checksum %s does not match remote checksum %s' % (file['adler32'], meta['adler32']))

                raise DataIdentifierAlreadyExists

            # add file to rse if it is not registered yet
            replicastate = list(self.client.list_replicas([file_did], all_states=True))
            if rse not in replicastate[0]['rses']:
                self.client.add_replicas(rse=rse, files=[replica_for_api])
                logger(logging.INFO, 'Successfully added replica in Rucio catalogue at %s' % rse)
        except DataIdentifierNotFound:
            logger(logging.DEBUG, 'File DID does not exist')
            self.client.add_replicas(rse=rse, files=[replica_for_api])
            self._add_bittorrent_meta(file=file, logger=logger)
            logger(logging.INFO, 'Successfully added replica in Rucio catalogue at %s' % rse)
            if not dataset_did_str:
                # only need to add rules for files if no dataset is given
                self.client.add_replication_rule([file_did], copies=1, rse_expression=rse, lifetime=file.get('lifetime'), ignore_availability=ignore_availability, activity=activity)
                logger(logging.INFO, 'Successfully added replication rule at %s' % rse)

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
            recursive = item.get('recursive')
            if not path:
                logger(logging.WARNING, 'Skipping source entry because the key "path" is missing')
                continue
            if not item.get('rse'):
                logger(logging.WARNING, 'Skipping file %s because no rse was given' % path)
                continue
            if pfn:
                item['force_scheme'] = pfn.split(':')[0]
            if item.get('impl'):
                impl = item.get('impl')
                impl_split = impl.split('.')
                if len(impl_split) == 1:
                    impl = 'rucio.rse.protocols.' + impl + '.Default'
                else:
                    impl = 'rucio.rse.protocols.' + impl
                item['impl'] = impl
            if os.path.isdir(path) and not recursive:
                dname, subdirs, fnames = next(os.walk(path))
                for fname in fnames:
                    file = self._collect_file_info(os.path.join(dname, fname), item)
                    files.append(file)
                if not len(fnames) and not len(subdirs):
                    logger(logging.WARNING, 'Skipping %s because it is empty.' % dname)
                elif not len(fnames):
                    logger(logging.WARNING, 'Skipping %s because it has no files in it. Subdirectories are not supported.' % dname)
            elif os.path.isdir(path) and recursive:
                files.extend(self._recursive(item))
            elif os.path.isfile(path) and not recursive:
                file = self._collect_file_info(path, item)
                files.append(file)
            elif os.path.isfile(path) and recursive:
                logger(logging.WARNING, 'Skipping %s because of --recursive flag' % path)
            else:
                logger(logging.WARNING, 'No such file or directory: %s' % path)

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

    def _upload_item(self, rse_settings, rse_attributes, lfn, source_dir=None, domain='wan', impl=None, force_pfn=None, force_scheme=None, transfer_timeout=None, delete_existing=False, sign_service=None):
        """
            Uploads a file to the connected storage.

            :param rse_settings: dictionary containing the RSE settings
            :param rse_attributes: dictionary containing the RSE attribute key value pairs
            :param lfn:         a single dict containing 'scope' and 'name'.
                                Example:
                             {'name': '1_rse_local_put.raw', 'scope': 'user.jdoe', 'filesize': 42, 'adler32': '87HS3J968JSNWID'}
                              If the 'filename' key is present, it will be used by Rucio as the actual name of the file on disk (separate from the Rucio 'name').
            :param source_dir:  path to the local directory including the source files
            :param force_pfn: use the given PFN -- can lead to dark data, use sparingly
            :param force_scheme: use the given protocol scheme, overriding the protocol priority in the RSE description
            :param transfer_timeout: set this timeout (in seconds) for the transfers, for protocols that support it
            :param sign_service: use the given service (e.g. gcs, s3, swift) to sign the URL

            :raises RucioException(msg): general exception with msg for more details.
        """
        logger = self.logger

        # Construct protocol for write operation.
        # IMPORTANT: All upload stat() checks are always done with the write_protocol EXCEPT for cloud resources (signed URL for write cannot be used for read)
        protocol_write = self._create_protocol(rse_settings, 'write', force_scheme=force_scheme, domain=domain, impl=impl)

        base_name = lfn.get('filename', lfn['name'])
        name = lfn.get('name', base_name)
        scope = lfn['scope']

        # Conditional lfn properties
        if 'adler32' not in lfn and 'md5' not in lfn:
            logger(logging.WARNING, 'Missing checksum for file %s:%s' % (lfn['scope'], name))

        # Getting pfn
        pfn = None
        signed_read_pfn = None
        try:
            pfn = list(protocol_write.lfns2pfns(make_valid_did(lfn)).values())[0]
            logger(logging.DEBUG, 'The PFN created from the LFN: {}'.format(pfn))
        except Exception as error:
            logger(logging.WARNING, 'Failed to create PFN for LFN: %s' % lfn)
            logger(logging.DEBUG, str(error), exc_info=True)
        if force_pfn:
            pfn = force_pfn
            logger(logging.DEBUG, 'The given PFN is used: {}'.format(pfn))

        # Auth. mostly for object stores
        if sign_service:
            protocol_read = self._create_protocol(rse_settings, 'read', domain=domain, impl=impl)
            signed_read_pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'read', pfn)    # NOQA pylint: disable=undefined-variable
            pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'write', pfn)       # NOQA pylint: disable=undefined-variable

        # Create a name of tmp file if renaming operation is supported
        pfn_tmp = '%s.rucio.upload' % pfn if protocol_write.renaming else pfn
        signed_read_pfn_tmp = '%s.rucio.upload' % signed_read_pfn if protocol_write.renaming else signed_read_pfn

        # Either DID exists or not register_after_upload
        if protocol_write.overwrite is False and delete_existing is False:
            if sign_service:
                # Construct protocol for read ONLY for cloud resources and get signed URL for GET
                if protocol_read.exists(signed_read_pfn):
                    raise FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))  # wrong exception ?
            elif protocol_write.exists(pfn):
                raise FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))  # wrong exception ?

        # Removing tmp from earlier attempts
        if (not sign_service and protocol_write.exists(pfn_tmp)) or (sign_service and protocol_read.exists(signed_read_pfn_tmp)):
            logger(logging.DEBUG, 'Removing remains of previous upload attempts.')
            try:
                # Construct protocol for delete operation.
                protocol_delete = self._create_protocol(rse_settings, 'delete', force_scheme=force_scheme, domain=domain, impl=impl)
                delete_pfn = '%s.rucio.upload' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0]
                if sign_service:
                    delete_pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'delete', delete_pfn)
                protocol_delete.delete(delete_pfn)
                protocol_delete.close()
            except Exception as error:
                raise RSEOperationNotSupported('Unable to remove temporary file %s.rucio.upload: %s' % (pfn, str(error)))

        # Removing not registered files from earlier attempts
        if delete_existing:
            logger(logging.DEBUG, 'Removing not-registered remains of previous upload attempts.')
            try:
                # Construct protocol for delete operation.
                protocol_delete = self._create_protocol(rse_settings, 'delete', force_scheme=force_scheme, domain=domain, impl=impl)
                delete_pfn = '%s' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0]
                if sign_service:
                    delete_pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'delete', delete_pfn)
                protocol_delete.delete(delete_pfn)
                protocol_delete.close()
            except Exception as error:
                raise RSEOperationNotSupported('Unable to remove file %s: %s' % (pfn, str(error)))

        # Process the upload of the tmp file
        try:
            retry(protocol_write.put, base_name, pfn_tmp, source_dir, transfer_timeout=transfer_timeout)(mtries=2, logger=logger)
            logger(logging.INFO, 'Successful upload of temporary file. {}'.format(pfn_tmp))
        except Exception as error:
            raise RSEOperationNotSupported(str(error))

        # Is stat after that upload allowed?
        skip_upload_stat = rse_attributes.get('skip_upload_stat', False)
        self.logger(logging.DEBUG, 'skip_upload_stat=%s', skip_upload_stat)

        # Checksum verification, obsolete, see Gabriele changes.
        if not skip_upload_stat:
            try:
                stats = self._retry_protocol_stat(protocol_write, pfn_tmp)
                if not isinstance(stats, dict):
                    raise RucioException('Could not get protocol.stats for given PFN: %s' % pfn)

                # The checksum and filesize check
                if ('filesize' in stats) and ('filesize' in lfn):
                    self.logger(logging.DEBUG, 'Filesize: Expected=%s Found=%s' % (lfn['filesize'], stats['filesize']))
                    if int(stats['filesize']) != int(lfn['filesize']):
                        raise RucioException('Filesize mismatch. Source: %s Destination: %s' % (lfn['filesize'], stats['filesize']))
                if rse_settings['verify_checksum'] is not False:
                    if ('adler32' in stats) and ('adler32' in lfn):
                        self.logger(logging.DEBUG, 'Checksum: Expected=%s Found=%s' % (lfn['adler32'], stats['adler32']))
                        if str(stats['adler32']).lstrip('0') != str(lfn['adler32']).lstrip('0'):
                            raise RucioException('Checksum mismatch. Source: %s Destination: %s' % (lfn['adler32'], stats['adler32']))

            except Exception as error:
                raise error

        # The upload finished successful and the file can be renamed
        try:
            if protocol_write.renaming:
                logger(logging.DEBUG, 'Renaming file %s to %s' % (pfn_tmp, pfn))
                protocol_write.rename(pfn_tmp, pfn)
        except Exception:
            raise RucioException('Unable to rename the tmp file %s.' % pfn_tmp)

        protocol_write.close()

        return pfn

    def _retry_protocol_stat(self, protocol, pfn):
        """
        Try to stat file, on fail try again 1s, 2s, 4s, 8s, 16s, 32s later. Fail is all fail
        :param protocol:     The protocol to use to reach this file
        :param pfn:          Physical file name of the target for the protocol stat
        """
        retries = config_get_int('client', 'protocol_stat_retries', raise_exception=False, default=6)
        for attempt in range(retries):
            try:
                self.logger(logging.DEBUG, 'stat: pfn=%s' % pfn)
                stats = protocol.stat(pfn)

                if int(stats['filesize']) == 0:
                    raise Exception('Filesize came back as 0. Potential storage race condition, need to retry.')

                return stats
            except RSEChecksumUnavailable as error:
                # The stat succeeded here, but the checksum failed
                raise error
            except Exception as error:
                self.logger(logging.DEBUG, 'stat: unexpected error=%s' % error)
                fail_str = ['The requested service is not available at the moment', 'Permission refused']
                if any(x in str(error) for x in fail_str):
                    raise error
                self.logger(logging.DEBUG, 'stat: unknown edge case, retrying in %ss' % 2**attempt)
                time.sleep(2**attempt)
        return protocol.stat(pfn)

    def _create_protocol(self, rse_settings, operation, impl=None, force_scheme=None, domain='wan'):
        """
        Protol construction.
        :param rse_settings:        rse_settings
        :param operation:           activity, e.g. read, write, delete etc.
        :param force_scheme:        custom scheme
        :param auth_token: Optionally passing JSON Web Token (OIDC) string for authentication
        """
        try:
            protocol = rsemgr.create_protocol(rse_settings, operation, scheme=force_scheme, domain=domain, impl=impl, auth_token=self.auth_token, logger=self.logger)
            protocol.connect()
        except Exception as error:
            self.logger(logging.WARNING, 'Failed to create protocol for operation: %s' % operation)
            self.logger(logging.DEBUG, 'scheme: %s, exception: %s' % (force_scheme, error))
            raise error
        return protocol

    def _send_trace(self, trace):
        """
        Checks if sending trace is allowed and send the trace.

        :param trace: the trace
        """
        if self.tracing:
            send_trace(trace, self.client.trace_host, self.client.user_agent)

    def _recursive(self, item):
        """
        If the --recursive flag is set, it replicates the folder structure recursively into collections
        A folder only can have either other folders inside or files, but not both of them
            - If it has folders, the root folder will be a container
            - If it has files, the root folder will be a dataset
            - If it is empty, it does not create anything

        :param item:        dictionary containing all descriptions of the files to upload
        """
        files = []
        datasets = []
        containers = []
        attach = []
        scope = item.get('did_scope') if item.get('did_scope') is not None else self.default_file_scope
        rse = item.get('rse')
        path = item.get('path')
        if path[-1] == '/':
            path = path[0:-1]
        i = 0
        path = os.path.abspath(path)
        for root, dirs, fnames in os.walk(path):
            if len(dirs) > 0 and len(fnames) > 0 and i == 0:
                self.logger(logging.ERROR, 'A container can only have either collections or files, not both')
                raise InputValidationError('Invalid input folder structure')
            if len(fnames) > 0:
                datasets.append({'scope': scope, 'name': root.split('/')[-1], 'rse': rse})
                self.logger(logging.DEBUG, 'Appended dataset with DID %s:%s' % (scope, path))
                for fname in fnames:
                    file = self._collect_file_info(os.path.join(root, fname), item)
                    file['dataset_scope'] = scope
                    file['dataset_name'] = root.split('/')[-1]
                    files.append(file)
                    self.logger(logging.DEBUG, 'Appended file with DID %s:%s' % (scope, fname))
            elif len(dirs) > 0:
                containers.append({'scope': scope, 'name': root.split('/')[-1]})
                self.logger(logging.DEBUG, 'Appended container with DID %s:%s' % (scope, path))
                attach.extend([{'scope': scope, 'name': root.split('/')[-1], 'rse': rse, 'dids': {'scope': scope, 'name': dir_}} for dir_ in dirs])
            elif len(dirs) == 0 and len(fnames) == 0:
                self.logger(logging.WARNING, 'The folder %s is empty, skipping' % root)
                continue
            i += 1
        # if everything went ok, replicate the folder structure in Rucio storage
        for dataset in datasets:
            try:
                self.client.add_dataset(scope=dataset['scope'], name=dataset['name'], rse=dataset['rse'])
                self.logger(logging.INFO, 'Created dataset with DID %s:%s' % (dataset['scope'], dataset['name']))
            except RucioException as error:
                self.logger(logging.ERROR, error)
                self.logger(logging.ERROR, 'It was not possible to create dataset with DID %s:%s' % (dataset['scope'], dataset['name']))
        for container in containers:
            try:
                self.client.add_container(scope=container['scope'], name=container['name'])
                self.logger(logging.INFO, 'Created container with DID %s:%s' % (container['scope'], container['name']))
            except RucioException as error:
                self.logger(logging.ERROR, error)
                self.logger(logging.ERROR, 'It was not possible to create dataset with DID %s:%s' % (container['scope'], container['name']))
        for att in attach:
            try:
                self.client.attach_dids(scope=att['scope'], name=att['name'], dids=[att['dids']])
                self.logger(logging.INFO, 'DIDs attached to collection %s:%s' % (att['scope'], att['name']))
            except RucioException as error:
                self.logger(logging.ERROR, error)
                self.logger(logging.ERROR, 'It was not possible to attach to collection with DID %s:%s' % (att['scope'], att['name']))
        return files

    def preferred_impl(self, rse_settings, domain):
        """
            Finds the optimum protocol impl preferred by the client and
            supported by the remote RSE.

            :param rse_settings: dictionary containing the RSE settings
            :param domain:     The network domain, either 'wan' (default) or 'lan'

            :raises RucioException(msg): general exception with msg for more details.
        """
        preferred_protocols = []
        supported_impl = None

        try:
            preferred_impls = config_get('upload', 'preferred_impl')
        except Exception as error:
            self.logger(logging.INFO, 'No preferred protocol impl in rucio.cfg: %s' % (error))
            pass
        else:
            preferred_impls = list(preferred_impls.split(', '))
            i = 0
            while i < len(preferred_impls):
                impl = preferred_impls[i]
                impl_split = impl.split('.')
                if len(impl_split) == 1:
                    preferred_impls[i] = 'rucio.rse.protocols.' + impl + '.Default'
                else:
                    preferred_impls[i] = 'rucio.rse.protocols.' + impl
                i += 1

            preferred_protocols = [protocol for protocol in reversed(rse_settings['protocols']) if protocol['impl'] in preferred_impls]

        if len(preferred_protocols) > 0:
            preferred_protocols += [protocol for protocol in reversed(rse_settings['protocols']) if protocol not in preferred_protocols]
        else:
            preferred_protocols = reversed(rse_settings['protocols'])

        for protocol in preferred_protocols:
            if domain not in list(protocol['domains'].keys()):
                self.logger(logging.DEBUG, 'Unsuitable protocol "%s": Domain %s not supported' % (protocol['impl'], domain))
                continue
            if not all(operations in protocol['domains'][domain] for operations in ("read", "write", "delete")):
                self.logger(logging.DEBUG, 'Unsuitable protocol "%s": All operations are not supported' % (protocol['impl']))
                continue
            try:
                supported_protocol = rsemgr.create_protocol(rse_settings, 'write', domain=domain, impl=protocol['impl'], auth_token=self.auth_token, logger=self.logger)
                supported_protocol.connect()
            except Exception as error:
                self.logger(logging.DEBUG, 'Failed to create protocol "%s", exception: %s' % (protocol['impl'], error))
                pass
            else:
                self.logger(logging.INFO, 'Preferred protocol impl supported locally and remotely: %s' % (protocol['impl']))
                supported_impl = protocol['impl']
                break

        return supported_impl
