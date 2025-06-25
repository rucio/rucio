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
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Optional, Union, cast

from rucio import version
from rucio.client.client import Client
from rucio.common.bittorrent import bittorrent_v2_merkle_sha256
from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS, adler32, md5
from rucio.common.client import detect_client_location
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.constants import RseAttr
from rucio.common.exception import (
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    FileReplicaAlreadyExists,
    InputValidationError,
    NoFilesUploaded,
    NotAllFilesUploaded,
    ResourceTemporaryUnavailable,
    RSEChecksumUnavailable,
    RSEOperationNotSupported,
    RSEWriteBlocked,
    RucioException,
    ScopeNotFound,
    ServiceUnavailable,
)
from rucio.common.utils import execute, generate_uuid, make_valid_did, retry, send_trace
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from rucio.common.types import AttachDict, DatasetDict, DIDStringDict, FileToUploadDict, FileToUploadWithCollectedAndDatasetInfoDict, FileToUploadWithCollectedInfoDict, LFNDict, LoggerFunction, PathTypeAlias, RSESettingsDict, TraceBaseDict, TraceDict
    from rucio.rse.protocols.protocol import RSEProtocol


class UploadClient:
    def __init__(
        self,
        _client: Optional[Client] = None,
        logger: Optional["LoggerFunction"] = None,
        tracing: bool = True
    ):
        """
        Initialize the UploadClient with the necessary configuration to manage file uploads.

        This method is used to create a new UploadClient instance that can upload files. It
        allows the use of an existing Rucio Client, a custom logger, and tracing for debug
        information during the upload process.

        Parameters
        ----------
        _client
            An existing Rucio `Client` instance to reuse. If not provided, a new one is created.
        logger
            A logger function. If not provided, the default Python logger is used.
        tracing
            Indicates whether to enable tracing to capture upload activity details.

        Raises
        ------
        InputValidationError
            If the client account is not found or is invalid, preventing upload setup.
        """
        if not logger:
            self.logger = logging.log
        else:
            self.logger = logger.log

        self.client: Final[Client] = _client if _client else Client()
        self.client_location = detect_client_location()
        # if token should be used, use only JWT tokens
        self.auth_token: Optional[str] = (
            self.client.auth_token if len(self.client.auth_token.split(".")) == 3 else None
        )
        self.tracing = tracing
        if not self.tracing:
            logger(logging.DEBUG, 'Tracing is turned off.')
        if self.client.account is None:
            self.logger(logging.DEBUG, 'No account specified, querying rucio.')
            try:
                acc = self.client.whoami()
                if acc is None:
                    raise InputValidationError(
                        'Account not specified and rucio has no account with your identity'
                    )
                self.client.account = acc['account']
            except RucioException as e:
                raise InputValidationError(
                    f'Account not specified and problem with rucio: {e}'
                )
            self.logger(logging.DEBUG, 'Discovered account as "%s"' % self.client.account)
        self.default_file_scope: Final[str] = 'user.' + self.client.account
        self.rses = {}
        self.rse_expressions = {}

        self.trace: "TraceBaseDict" = {
            'hostname': socket.getfqdn(),
            'account': self.client.account,
            'eventType': 'upload',
            'eventVersion': version.RUCIO_VERSION[0],
            'vo': self.client.vo if self.client.vo != 'def' else None
        }

    def upload(
            self,
            items: "Iterable[FileToUploadDict]",
            summary_file_path: Optional[Union[str, os.PathLike[str]]] = None,
            traces_copy_out: Optional[list["TraceBaseDict"]] = None,
            ignore_availability: bool = False,
            activity: Optional[str] = None
    ) -> int:
        """
        Uploads one or more files to an RSE (Rucio Storage Element) and optionally registers them.

        An overview of this method's performed actions:

        1. Collects and validates file info from the passed `items` (directories may be
            also included), ensuring valid paths exist on the local filesystem. If an RSE
            expression is provided, a single RSE is picked at random from it.

        2. Checks the RSE's availability for writing (unless `ignore_availability` is True).

        3. Optionally registers each file in the Rucio Catalog, handling the DID creation,
            dataset creation/attachment, and replication rules as needed.

        4. Uploads the files using the underlying protocol handlers and verifies checksums
            if desired/possible. Partial or failed uploads raise exceptions.

        5. (Optional) Produces a JSON summary file at `summary_file_path`, listing the final
            PFNs, checksums, and other info for all successfully uploaded files.

        Parameters
        ----------
        items
            A sequence of dictionaries, each describing a file to upload (or a
            directory to be scanned). For each item, the supported keys are:

            * **`path`** (PathTypeAlias, required):
                The local path to the file or directory. If this is a directory and
                `recursive` is True, the directory (and its subdirectories) are traversed.

            * **`rse`** (str, required):
                The target RSE or an RSE expression where the upload should be placed. If
                an expression is provided (e.g., "tier=1"), one RSE from that expression
                is chosen randomly.

            * **`did_scope`** (str, not required):
                The Rucio scope in which to register the file DID. Defaults to `user.<account>`.

            * **`did_name`** (str, not required):
                The logical filename in Rucio. Defaults to the local basename if not provided.

            * **`lifetime`** (int, not required):
                The lifetime (in seconds) to apply when creating a new replication rule.
                For file uploads without a dataset, a new rule with that lifetime is created
                if the file DID does not already exist in Rucio. For a new dataset, the
                dataset is created with a rule using this lifetime, but if the dataset
                already exists and you specify a lifetime, an error is raised.

                _**Note:**_ **`lifetime`** is not automatically applied to nested containers
                or datasets in recursive mode.

            * **`impl`** (str, not required):
                Name of the protocol implementation to be used for uploading this item.
                For example, `"rucio.rse.protocols.gfal.Default"`.

            * **`pfn`** (str, not required):
                Allows you to explicitly set the Physical File Name (PFN) for the upload,
                determining exactly where the file is placed on the storage. However, for
                deterministic RSEs, specifying a PFN causes the client to skip registering
                the file under the usual deterministic scheme. For non-deterministic RSEs,
                you can still force the file to be registered in the Rucio catalog after
                being uploaded, using `no_register=False` along with `register_after_upload=True`
                (or by manually handling the registration later).

            * **`force_scheme`** (str, not required):
                Enforces the use of a specific protocol scheme (e.g., davs, https) during
                file uploads. If the selected protocol is not compatible, the upload will
                stop and raise an error instead of falling back to any other scheme.

            * **`transfer_timeout`** (int, not required):
                A maximum duration (in seconds) to wait for each individual file transfer
                to complete. If the file transfer does not finish before this timeout
                elapses, the operation will be aborted and retried one last time. When
                transfer_timeout is None, no specific timeout is enforced, and the transfer
                may continue until it completes or fails for another reason.

            * **`guid`** (str, not required):
                If provided, Rucio will use this GUID. If not provided and the file is
                “pool.root” with `no_register` unset, Rucio tries to extract the GUID via
                `pool_extractFileIdentifier`, raising an error if that fails. Otherwise, a
                random GUID will be generated.

            * **`no_register`** (bool, not required, default=False):
                If set to True, the file is not registered in the Rucio Catalog, i.e., there
                is no DID creation, no replica entry, and no rules. This is appropriate if
                you plan to register the replica or create rules separately.

                _**Note:**_ If **`recursive`**=True, the method still creates datasets
                and/or containers for the directories when needed.

            * **`register_after_upload`** (bool, not required, default=False):
                If set to True, the file is uploaded first, and only then is the DID created
                or updated in the Catalog. This can be useful when you want the actual data
                on storage before finalizing the registration. By default (False), the file
                is registered in Rucio before the physical upload if `no_register` is False.

            * **`recursive`** (bool, not required, default=False):
                If set to `True`, the method treats the specified path as a directory and
                (depending on the combination with other parameters) recursively traverses
                its subdirectories, mapping them into container/dataset hierarchies. Single
                top-level file paths are ignored, but individual files found in subdirectories
                are processed. Empty directories or non-existent paths also produce a warning.
                If `False`, then top-level file paths or the direct children-files of the
                given top-level directory are only processed (subdirectories are ignored,
                and no container structure is created).

            * **`dataset_scope`** / **`dataset_name`** (str, not required):
                To register uploaded files into a dataset DID, you need to specify both
                dataset_name and dataset_scope. With no_register=False, the client ensures
                {dataset_scope}:{dataset_name} exists (creating it with a replication rule
                if it doesn't), or simply attaching new files if it does. If the dataset
                already exists and you specify a new lifetime, or if a checksum mismatch
                is detected, registration fails. In non-recursive mode, only files in the
                top-level directory are attached to the dataset and subdirectories are
                skipped with a warning. In recursive mode, the client aims to create
                containers for directories containing only subdirectories and datasets for
                directories containing only files (raising an error if the top-level folder
                mixes files and directories). If the top-level directory has subdirectories,
                the user-supplied dataset_name is effectively ignored at that level (each
                subdirectory becomes its own dataset or container); if there are no
                subdirectories, the entire folder is registered as a single dataset.

            * **`dataset_meta`** (dict, not required):
                Additional metadata (e.g., `{'project': 'myProject'}`) to attach to the
                newly created dataset when: the dataset does not already exist, `recursive=False`,
                `no_register=False` and both `dataset_scope` and `dataset_name` are provided.

                _**Note:**_ If multiple files share the same `dataset_scope` and `dataset_name`,
                then if a dataset is created, it considers only the first item’s dataset_meta.
        summary_file_path
            If specified, a JSON file is created with a summary of each successfully
            uploaded file, including checksum, PFN, scope, and name entries.
        traces_copy_out
            A list reference for collecting the trace dictionaries that Rucio generates
            while iterating over each file. A new trace dictionary is appended to this list
            for each file considered (even those ultimately skipped or already on the RSE).
        ignore_availability
            If set to True, the RSE's "write availability" is not enforced. By default,
            this is False, and an RSE marked as unavailable for writing will raise an error.
        activity
            If you are uploading files without a parent dataset, this string sets the “activity”
            on the replication rule that Rucio creates for each file (e.g., "Analysis"),
            which can affect RSE queue priorities.

            _**Note:**_ If your files are uploaded into a dataset, the dataset’s replication
            rule does not use this activity parameter.

        Returns
        -------
        int
            Status code (``0`` if all files were uploaded successfully).

        Raises
        ------
        NoFilesUploaded
            Raised if none of the requested files could be uploaded.
        NotAllFilesUploaded
            Raised if some files were successfully uploaded, but others failed.
        RSEWriteBlocked
            Raised if `ignore_availability=False` but the chosen RSE does not allow writing.
        InputValidationError
            Raised if mandatory fields are missing, if conflicting DIDs are found,
            or if no valid files remain after input parsing.

        Examples
        --------
        ??? Example

            Upload a single local file to the *CERN-PROD* RSE and write a JSON summary to
            ``upload_summary.json``:

            ```python
            from rucio.client.uploadclient import UploadClient
            upload_client = UploadClient()
            items = [
                {"path": "/data/file1.txt",
                 "rse": "CERN-PROD",            # target RSE
                 "did_scope": "user.alice",     # optional; defaults to user.<account>
                 "did_name": "file1.txt"}       # optional; defaults to basename
            ]
            upload_client.upload(items, summary_file_path="upload_summary.json")
            ```

            Recursively upload every file found under ``/data/dataset`` into a new
            dataset ``user.alice:mydataset`` on a random RSE that matches the
            expression ``tier=1``; collect per-file *trace* dictionaries for later
            inspection:

            ```python
            traces: list[TraceBaseDict] = []
            dir_item = {
                "path": "/data/dataset",
                "rse": "tier=1",                # RSE expression; one will be chosen
                "recursive": True,
                "dataset_scope": "user.alice",
                "dataset_name": "mydataset",
                "dataset_meta": {"project": "demo"},
            }
            upload_client.upload([dir_item], traces_copy_out=traces)
            ```
        """
        # helper to get rse from rse_expression:
        def _pick_random_rse(rse_expression: str) -> dict[str, Any]:
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
            # appending trace to the list reference if the reference exists
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
                logger(logging.WARNING,
                       'Upload with given pfn implies that no_register is True, except non-deterministic RSEs')
                no_register = True

            # resolving local area networks
            domain = 'wan'
            rse_attributes = {}
            try:
                rse_attributes = self.client.list_rse_attributes(rse)
            except Exception:
                logger(logging.WARNING, 'Attributes of the RSE: %s not available.' % rse)
            if self.client_location and 'lan' in rse_settings['domain'] and RseAttr.SITE in rse_attributes:
                if self.client_location['site'] == rse_attributes[RseAttr.SITE]:
                    domain = 'lan'
            logger(logging.DEBUG, '{} domain is used for the upload'.format(domain))

            # FIXME:
            # Rewrite preferred_impl selection - also check test_upload.py/test_download.py and fix impl order (see FIXME there)
            #
            # if not impl and not force_scheme:
            #    impl = self.preferred_impl(rse_settings, domain)

            if not no_register and not register_after_upload:
                self._register_file(file,
                                    registered_dataset_dids,
                                    ignore_availability=ignore_availability,
                                    activity=activity)

            # if register_after_upload, the file should be overwritten if it is not registered,
            # otherwise if the file already exists on RSE we're done
            if register_after_upload:
                if rsemgr.exists(rse_settings,
                                 pfn if pfn else file_did,  # type: ignore (pfn is str)
                                 domain=domain,
                                 scheme=force_scheme,
                                 impl=impl,
                                 auth_token=self.auth_token,
                                 vo=self.client.vo,
                                 logger=logger):
                    try:
                        self.client.get_did(file['did_scope'], file['did_name'])
                        logger(logging.INFO, 'File already registered. Skipping upload.')
                        trace['stateReason'] = 'File already exists'
                        continue
                    except DataIdentifierNotFound:
                        logger(logging.INFO, 'File already exists on RSE. Previous left overs will be overwritten.')
                        delete_existing = True
            elif not is_deterministic and not no_register:
                if rsemgr.exists(rse_settings,
                                 pfn,  # type: ignore (pfn is str)
                                 domain=domain,
                                 scheme=force_scheme,
                                 impl=impl,
                                 auth_token=self.auth_token,
                                 vo=self.client.vo,
                                 logger=logger):
                    logger(logging.INFO,
                           'File already exists on RSE with given pfn. Skipping upload. Existing replica has to be removed first.')
                    trace['stateReason'] = 'File already exists'
                    continue
                elif rsemgr.exists(rse_settings,
                                   file_did,
                                   domain=domain,
                                   scheme=force_scheme,
                                   impl=impl,
                                   auth_token=self.auth_token,
                                   vo=self.client.vo,
                                   logger=logger):
                    logger(logging.INFO, 'File already exists on RSE with different pfn. Skipping upload.')
                    trace['stateReason'] = 'File already exists'
                    continue
            else:
                if rsemgr.exists(rse_settings,
                                 pfn if pfn else file_did,  # type: ignore (pfn is str)
                                 domain=domain,
                                 scheme=force_scheme,
                                 impl=impl,
                                 auth_token=self.auth_token,
                                 vo=self.client.vo,
                                 logger=logger):
                    logger(logging.INFO, 'File already exists on RSE. Skipping upload')
                    trace['stateReason'] = 'File already exists'
                    continue

            # protocol handling and upload
            protocols = rsemgr.get_protocols_ordered(rse_settings=rse_settings,
                                                     operation='write',
                                                     scheme=force_scheme,
                                                     domain=domain,
                                                     impl=impl)
            protocols.reverse()
            success = False
            state_reason = ''
            logger(logging.DEBUG, str(protocols))
            while not success and len(protocols):
                protocol = protocols.pop()
                cur_scheme = protocol['scheme']
                logger(logging.INFO, 'Trying upload with %s to %s' % (cur_scheme, rse))
                lfn: "LFNDict" = {'name': file['did_name'],
                                  'scope': file['did_scope'],
                                  'filename': basename}

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
                    file['upload_result'] = {0: True, 1: None, 'success': True, 'pfn': pfn}  # TODO: needs to be removed
                except (ServiceUnavailable,
                        ResourceTemporaryUnavailable,
                        RSEOperationNotSupported,
                        RucioException) as error:
                    logger(logging.WARNING, 'Upload attempt failed')
                    logger(logging.INFO, 'Exception: %s' % str(error), exc_info=True)
                    state_reason = str(error)

            if success:
                trace['transferEnd'] = time.time()
                trace['clientState'] = 'DONE'
                file['state'] = 'A'
                logger(logging.INFO, 'Successfully uploaded file %s' % basename)
                self._send_trace(cast("TraceDict", trace))

                if summary_file_path:
                    summary.append(copy.deepcopy(file))

                registration_succeeded = True
                if not no_register:
                    if register_after_upload:
                        self._register_file(file,
                                            registered_dataset_dids,
                                            ignore_availability=ignore_availability,
                                            activity=activity)
                    else:
                        replica_for_api = self._convert_file_for_api(file)
                        try:
                            self.client.update_replicas_states(rse, files=[replica_for_api])
                        except Exception as error:
                            registration_succeeded = False
                            logger(logging.ERROR, 'Failed to update replica state for file {}'.format(basename))
                            logger(logging.DEBUG, 'Details: {}'.format(str(error)))

                # add the file to dataset if needed
                if dataset_did_str and not no_register:
                    try:
                        self.client.attach_dids(
                            file['dataset_scope'],  # type: ignore (`dataset_scope` always exists if `dataset_did_str`)
                            file['dataset_name'],  # type: ignore (`dataset_name` always exists if `dataset_did_str`)
                            [file_did])
                    except Exception as error:
                        registration_succeeded = False
                        logger(logging.ERROR, 'Failed to attach file to the dataset')
                        logger(logging.DEBUG, 'Attaching to dataset {}'.format(str(error)))

                # only report success if the registration operations succeeded as well
                if registration_succeeded:
                    num_succeeded += 1
            else:
                trace['clientState'] = 'FAILED'
                trace['stateReason'] = state_reason
                self._send_trace(cast('TraceDict', trace))
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

            summary_path = Path(summary_file_path)
            with summary_path.open('w') as summary_file:
                json.dump(final_summary, summary_file, sort_keys=True, indent=1)

        if num_succeeded == 0:
            raise NoFilesUploaded()
        elif num_succeeded != len(files):
            raise NotAllFilesUploaded()
        return 0

    def _add_bittorrent_meta(
            self,
            file: "Mapping[str, Any]"
    ) -> None:
        """
        Add BitTorrent v2 metadata to the file DID.

        This method calculates the BitTorrent v2 pieces root, layers, and piece length for
        the specified local file, and updates the file DID's metadata with these values.

        Parameters
        ----------
        file
            A dictionary that must include 'dirname', 'basename', 'did_scope',
            and 'did_name', describing the file path and the associated DID.
        """
        pieces_root, pieces_layers, piece_length = bittorrent_v2_merkle_sha256(
            os.path.join(file['dirname'], file['basename']))
        bittorrent_meta = {
            'bittorrent_pieces_root': base64.b64encode(pieces_root).decode(),
            'bittorrent_pieces_layers': base64.b64encode(pieces_layers).decode(),
            'bittorrent_piece_length': piece_length,
        }
        self.client.set_metadata_bulk(scope=file['did_scope'], name=file['did_name'], meta=bittorrent_meta)
        self.logger(logging.INFO, f"Added BitTorrent metadata to file DID {file['did_scope']}:{file['did_name']}")

    def _register_file(
            self,
            file: "Mapping[str, Any]",
            registered_dataset_dids: set[str],
            ignore_availability: bool = False,
            activity: Optional[str] = None
    ) -> None:
        """
        Register a single file DID in Rucio, optionally creating its parent dataset if needed.

        Ensures that a file is known in the Rucio catalog under the specified scope. If a
        dataset is specified in `file` and it does not yet exist, the method creates it and
        attaches the file to that dataset, applying replication rules as appropriate. If no
        dataset is provided and the file DID does not yet exist in Rucio, the method creates
        a replication rule for the newly added file. If the file DID already exists, no new
        top-level rule is created (the file’s existing rules or attachments remain unchanged).
        Checksums are compared to prevent conflicts if the file is already registered.

        Parameters
        ----------
        file
            A dictionary containing file information (e.g., 'did_scope', 'did_name', 'adler32', etc.).
        registered_dataset_dids
            A set of dataset DIDs already registered to avoid duplicates.
        ignore_availability
            If True, creates replication rules even when the RSE is marked unavailable.
        activity
            Specifies the transfer activity (e.g., 'User Subscriptions') for the replication rule.

        Raises
        ------
        InputValidationError
            If a dataset already exists, but the caller attempts to set a new lifetime for it.
        DataIdentifierAlreadyExists
            If the local checksum differs from the remote checksum.
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
            logger(logging.WARNING,
                   'Scope {} not found for the account {}.'.format(file['did_scope'], self.client.account))

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
                    raise InputValidationError(
                        'Dataset %s exists and lifetime %s given. Prohibited to modify parent dataset lifetime.' % (dataset_did_str, file.get('lifetime')))
        else:
            logger(logging.DEBUG, 'Skipping dataset registration')

        file_scope = file['did_scope']
        file_name = file['did_name']
        file_did = {'scope': file_scope, 'name': file_name}
        replica_for_api = self._convert_file_for_api(file)
        try:
            # if the remote checksum is different, this DID must not be used
            meta = self.client.get_metadata(file_scope, file_name)
            logger(logging.INFO, 'File DID already exists')
            logger(logging.DEBUG, 'local checksum: %s, remote checksum: %s' % (file['adler32'], meta['adler32']))

            if str(meta['adler32']).lstrip('0') != str(file['adler32']).lstrip('0'):
                logger(logging.ERROR,
                       'Local checksum %s does not match remote checksum %s' % (file['adler32'], meta['adler32']))
                raise DataIdentifierAlreadyExists

            # add the file to rse if it is not registered yet
            replicastate = list(self.client.list_replicas([file_did], all_states=True))
            if rse not in replicastate[0]['rses']:
                self.client.add_replicas(rse=rse, files=[replica_for_api])
                logger(logging.INFO, 'Successfully added replica in Rucio catalogue at %s' % rse)
        except DataIdentifierNotFound:
            logger(logging.DEBUG, 'File DID does not exist')
            self.client.add_replicas(rse=rse, files=[replica_for_api])
            if config_get_bool('client', 'register_bittorrent_meta', default=False):
                self._add_bittorrent_meta(file=file)
            logger(logging.INFO, 'Successfully added replica in Rucio catalogue at %s' % rse)
            if not dataset_did_str:
                # only need to add rules for files if no dataset is given
                self.client.add_replication_rule([file_did],
                                                 copies=1,
                                                 rse_expression=rse,
                                                 lifetime=file.get('lifetime'),
                                                 ignore_availability=ignore_availability,
                                                 activity=activity)
                logger(logging.INFO, 'Successfully added replication rule at %s' % rse)

    def _get_file_guid(
            self,
            file: "Mapping[str, Any]"
    ) -> str:
        """
        Returns the unique identifier (GUID) for the given file.

        If no GUID exists and the filename suggests a ROOT file, it extracts it with
        `pool_extractFileIdentifier`. If a GUID exists, it is returned without dashes.
        Otherwise, a new GUID is generated.

        Parameters
        ----------
        file
            A dictionary describing the file, expected to include:

            * **`basename`**:
                The base filename.

            * **`path`**:
                The path to the file.

            * **`guid`** (optional):
                A pre-assigned GUID string.

            * **`no_register`** (optional):
                If True, skip attempts to derive a GUID for ROOT files.

        Returns
        -------
        str
            A string containing the file's GUID, stripped of dashes and in lowercase.

        Raises
        ------
        RucioException
            If GUID extraction using the `pool_extractFileIdentifier` command fails.
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
                raise RucioException('Error extracting GUID from output of pool_extractFileIdentifier')
        elif guid:
            guid = guid.replace('-', '')
        else:
            guid = generate_uuid()
        return guid

    def _collect_file_info(
            self,
            filepath: "PathTypeAlias",
            item: "FileToUploadDict"
    ) -> "FileToUploadWithCollectedInfoDict":
        """
        Collects and returns essential file descriptors (e.g., size, checksums, GUID, etc.).

        This method computes the file's size, calculates its Adler-32 and MD5 checksums,
        and retrieves the file's GUID. These values, along with other existing fields from
        the input dictionary, are returned in a new dictionary.

        Parameters
        ----------
        filepath
            The local filesystem path to the file.
        item
            A dictionary containing initial upload parameters (e.g., RSE name, scope) for the
            file. Some of its fields may be updated or augmented in the returned dictionary.

        Returns
        -------
        "FileToUploadWithCollectedInfoDict"
            A new dictionary enriched with relevant file descriptors.
        """
        new_item = copy.deepcopy(item)
        new_item = cast("FileToUploadWithCollectedInfoDict", new_item)
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

    def _collect_and_validate_file_info(
            self,
            items: "Iterable[FileToUploadDict]"
    ) -> list["FileToUploadWithCollectedInfoDict"]:
        """
        Collect and verify local file info for upload, optionally registering folders as
        datasets/containers.

        This method iterates over the provided items, each describing a local path and
        associated upload parameters, checks that each item has a valid path and RSE, and
        computes basic file details such as size and checksums. If the item is a directory
        and `recursive` is set, the method calls `_recursive` to traverse subdirectories,
        creating or attaching them as Rucio datasets or containers.

        Parameters
        ----------
        items
            An iterable of dictionaries describing files or directories, where each dictionary
            typically has:

            * **`path`**:
                Local file system path

            * **`rse`**:
                Name of the RSE destination

            * **`pfn`** (optional):
                Physical file name (PFN)

            * **`impl`** (optional):
                Protocol implementation

            * **`recursive`** (optional):
                Whether to traverse directories recursively

        Returns
        -------
        list["FileToUploadWithCollectedInfoDict"]
            A list of dictionaries enriched with file descriptors (size, checksums, etc.)
            and ready for further upload processing.

        Raises
        ------
        InputValidationError
            If no valid files are found.
        """
        logger = self.logger
        files: list["FileToUploadWithCollectedInfoDict"] = []
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
            impl = item.get('impl')
            if impl:
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
                    logger(logging.WARNING,
                           'Skipping %s because it has no files in it. Subdirectories are not supported.' % dname)
            elif os.path.isdir(path) and recursive:
                files.extend(cast("list[FileToUploadWithCollectedInfoDict]", self._recursive(item)))
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

    def _convert_file_for_api(
            self,
            file: "Mapping[str, Any]"
    ) -> dict[str, Any]:
        """
        Create a minimal dictionary of file attributes for the Rucio API.

        This method extracts only the necessary fields from the provided file dictionary,
        producing a new dictionary that is suitable for registering or updating
        a file replica in Rucio.

        Parameters
        ----------
        file
            A dictionary describing a file, expected to include at least `did_scope`,
            `did_name`, `bytes`, `adler32`, `md5`, `meta`, `state`, and optionally `pfn`.

        Returns
        -------
        dict[str, Any]
            A dictionary containing only the relevant file attributes for Rucio's REST API.
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

    def _upload_item(
            self,
            rse_settings: "RSESettingsDict",
            rse_attributes: dict[str, Any],
            lfn: "LFNDict",
            source_dir: Optional[str] = None,
            domain: str = 'wan',
            impl: Optional[str] = None,
            force_pfn: Optional[str] = None,
            force_scheme: Optional[str] = None,
            transfer_timeout: Optional[int] = None,
            delete_existing: bool = False,
            sign_service: Optional[str] = None
    ) -> Optional[str]:
        """
        Perform the actual file transfer to an RSE using the appropriate protocol.

        This method is used once all necessary file information is resolved (logical file
        name, checksums, etc.). It creates and verifies the physical file name (PFN),
        optionally removes or overwrites stale replicas, uploads the file (potentially via
        a temporary PFN suffix), checks its size/checksum consistency, and finalizes it
        under the expected PFN.

        Parameters
        ----------
        rse_settings
            Dictionary containing the RSE configuration.
        rse_attributes
            Additional attributes of the RSE (e.g. 'archive_timeout').
        lfn
            An optional dictionary describing the logical file (e.g., {'name': '1_rse_local_put.raw',
            'scope': 'user.jdoe', ..}). If the 'filename' key is present, it overrides 'name'
            in determining the local file name to read from source_dir.
        source_dir
            Local source directory path where the file to be uploaded resides.
        domain
            Network domain for the upload, commonly 'wan' for wide-area networks.
        impl
            Name of the protocol implementation to be enforced (if any).
        force_pfn
            If provided, forces the use of this PFN for the file location on the storage
            (use with care since it can lead to "dark" data).
        force_scheme
            If provided, forces the protocol scheme (e.g. 'davs', 'https') to be used.
        transfer_timeout
            Timeout (in seconds) for the transfer operation before it fails.
        delete_existing
            If True, removes any unregistered or stale file on the storage that matches this PFN.
        sign_service
            If set, requests a signed URL from the given service (e.g., gcs, s3, swift).

        Returns
        -------
        Optional[str]
            The final PFN (physical file name) of the successfully uploaded file, or None
            if creation failed.

        Raises
        ------
        FileReplicaAlreadyExists
            If the target file already exists and overwrite is not allowed.
        RSEOperationNotSupported
            If storage-side operations (delete/rename/put) are not supported or fail.
        RucioException
            If renaming or other critical operations cannot be completed.
        """

        logger = self.logger

        # Construct protocol for write operation.
        # IMPORTANT: All upload stat() checks are always done with the write_protocol EXCEPT for cloud resources (signed URL for write cannot be used for read)
        protocol_write = self._create_protocol(rse_settings,
                                               'write',
                                               force_scheme=force_scheme,
                                               domain=domain,
                                               impl=impl)

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
            protocol_read = self._create_protocol(rse_settings,
                                                  'read',
                                                  domain=domain,
                                                  impl=impl)
            if pfn is not None:
                signed_read_pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'read', pfn)
                pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'write', pfn)

        # Create a name of tmp file if the renaming operation is supported
        pfn_tmp = cast("str", '%s.rucio.upload' % pfn if protocol_write.renaming else pfn)
        signed_read_pfn_tmp = '%s.rucio.upload' % signed_read_pfn if protocol_write.renaming else signed_read_pfn

        # Either DID exists or not register_after_upload
        if protocol_write.overwrite is False and delete_existing is False:
            if sign_service:
                # Construct protocol for read-ONLY for cloud resources and get signed URL for GET
                if protocol_read.exists(signed_read_pfn):
                    raise FileReplicaAlreadyExists('File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))  # wrong exception?
            elif protocol_write.exists(pfn):
                raise FileReplicaAlreadyExists(
                    'File %s in scope %s already exists on storage as PFN %s' % (name, scope, pfn))  # wrong exception?

        # Removing tmp from earlier attempts
        if (not sign_service and protocol_write.exists(pfn_tmp)) or (
                sign_service and protocol_read.exists(signed_read_pfn_tmp)):
            logger(logging.DEBUG, 'Removing remains of previous upload attempts.')
            try:
                # Construct protocol for delete operation.
                protocol_delete = self._create_protocol(rse_settings,
                                                        'delete',
                                                        force_scheme=force_scheme,
                                                        domain=domain,
                                                        impl=impl)
                delete_pfn = '%s.rucio.upload' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0]
                if sign_service:
                    delete_pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'delete', delete_pfn)
                protocol_delete.delete(delete_pfn)
                protocol_delete.close()
            except Exception as error:
                raise RSEOperationNotSupported(
                    'Unable to remove temporary file %s.rucio.upload: %s' % (pfn, str(error)))

        # Removing not registered files from earlier attempts
        if delete_existing:
            logger(logging.DEBUG, 'Removing not-registered remains of previous upload attempts.')
            try:
                # Construct protocol for delete operation.
                protocol_delete = self._create_protocol(rse_settings,
                                                        'delete',
                                                        force_scheme=force_scheme,
                                                        domain=domain,
                                                        impl=impl)
                delete_pfn = '%s' % list(protocol_delete.lfns2pfns(make_valid_did(lfn)).values())[0]
                if sign_service:
                    delete_pfn = self.client.get_signed_url(rse_settings['rse'], sign_service, 'delete', delete_pfn)
                protocol_delete.delete(delete_pfn)
                protocol_delete.close()
            except Exception as error:
                raise RSEOperationNotSupported('Unable to remove file %s: %s' % (pfn, str(error)))

        # Process the upload of the tmp file
        try:
            retry(protocol_write.put,
                  base_name,
                  pfn_tmp,
                  source_dir,
                  transfer_timeout=transfer_timeout)(
                mtries=2,
                logger=logger
            )
            logger(logging.INFO, 'Successful upload of temporary file. {}'.format(pfn_tmp))
        except Exception as error:
            raise RSEOperationNotSupported(str(error))

        # Is stat after that upload allowed?
        skip_upload_stat = rse_attributes.get(RseAttr.SKIP_UPLOAD_STAT, False)
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
                        raise RucioException(
                            'Filesize mismatch. Source: %s Destination: %s' % (lfn['filesize'], stats['filesize']))
                if rse_settings['verify_checksum'] is not False:
                    if ('adler32' in stats) and ('adler32' in lfn):
                        self.logger(logging.DEBUG,
                                    'Checksum: Expected=%s Found=%s' % (lfn['adler32'], stats['adler32']))
                        if str(stats['adler32']).lstrip('0') != str(lfn['adler32']).lstrip('0'):
                            raise RucioException(
                                'Checksum mismatch. Source: %s Destination: %s' % (lfn['adler32'], stats['adler32']))

            except Exception as error:
                raise error

        # The upload finished successfully and the file can be renamed
        try:
            if protocol_write.renaming:
                logger(logging.DEBUG, 'Renaming file %s to %s' % (pfn_tmp, pfn))
                protocol_write.rename(pfn_tmp, pfn)  # type: ignore (pfn might be None)
        except Exception:
            raise RucioException('Unable to rename the tmp file %s.' % pfn_tmp)

        protocol_write.close()

        return pfn

    def _retry_protocol_stat(
            self,
            protocol: "RSEProtocol",
            pfn: str
    ) -> dict[str, Any]:
        """
        Attempt to retrieve file statistics with exponential backoff.

        This method invokes `protocol.stat` a limited number of times, waiting with an
        exponential backoff between each attempt when an error occurs. After the configured
        number of retries, the method performs one final `stat` call and returns its result
        or lets any resulting exception propagate.

        Parameters
        ----------
        protocol
            The RSEProtocol instance to use for retrieving file statistics
        pfn
            The physical file name (PFN) to be checked.

        Returns
        -------
        dict[str, Any]
            A dictionary expected to include the filesize and adler32 for the provided pfn.

        Raises
        ------
        RSEChecksumUnavailable
            If the protocol indicates a missing checksum for the file.
        Exception
            If the requested service is not available or permissions are not granted.
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
                self.logger(logging.DEBUG, 'stat: unknown edge case, retrying in %ss' % 2 ** attempt)
                time.sleep(2 ** attempt)
        return protocol.stat(pfn)

    def _create_protocol(
            self,
            rse_settings: "RSESettingsDict",
            operation: str,
            impl: Optional[str] = None,
            force_scheme: Optional[str] = None,
            domain: str = 'wan'
    ) -> "RSEProtocol":
        """
        Creates and returns the protocol object for the requested RSE operation.

        Establishes a connection using the specified parameters (scheme, domain, etc.)
        and returns a protocol instance capable of handling the requested operation.

        Parameters
        ----------
        rse_settings
            The dictionary containing RSE configuration.
        operation
            The intended operation, such as 'read', 'write', or 'delete'.
        impl
            An optional override for the default protocol implementation.
        force_scheme
            If provided, forces the protocol to use this scheme.
        domain
            The network domain to be used, defaulting to 'wan'.

        Returns
        -------
        "RSEProtocol"
            The instantiated `RSEProtocol` object.

        Raises
        ------
        Exception
            If the protocol creation or connection attempt fails.
        """
        try:
            protocol = rsemgr.create_protocol(
                rse_settings,
                operation,
                scheme=force_scheme,
                domain=domain,
                impl=impl,
                auth_token=self.auth_token,
                logger=self.logger
            )
            protocol.connect()
        except Exception as error:
            self.logger(logging.WARNING, 'Failed to create protocol for operation: %s' % operation)
            self.logger(logging.DEBUG, 'scheme: %s, exception: %s' % (force_scheme, error))
            raise error
        return protocol

    def _send_trace(
            self,
            trace: "TraceDict"
    ) -> None:
        """
        Sends the trace if tracing is enabled.

        If `self.tracing` is True, this method uses Rucio's `send_trace` function to
        dispatch the provided trace object to Rucio host. Otherwise, it takes no action.

        Parameters
        ----------
        trace
            The trace object to be sent.
        """
        if self.tracing:
            send_trace(trace, self.client.trace_host, self.client.user_agent)

    def _recursive(
            self,
            item: "FileToUploadDict"
    ) -> list["FileToUploadWithCollectedAndDatasetInfoDict"]:
        """
        Recursively inspects a folder and creates corresponding Rucio datasets or containers.

        This method traverses the local path specified in the given dictionary `item` and
        interprets subfolders as either Rucio containers (if they themselves contain further
        subfolders) or datasets (if they only contain files). Files within these datasets
        are gathered into a list with additional upload information. The method also attempts
        to create and attach these datasets/containers in Rucio, replicating the folder
        structure.

        Note:
        ------
        Currently, this method does not allow the top-level directory to contain both files
        and subdirectories.

        Parameters
        ----------
        item
            A dictionary describing the local path and upload parameters.
            It must contain at least:

            * **`rse`**:
                The target RSE for the upload.

            * **`path`**:
                The local directory path to inspect.

            * **`did_scope`** (optional):
                Custom scope for the resulting datasets/containers.

        Returns
        -------
        list["FileToUploadWithCollectedAndDatasetInfoDict"]
            A list of file descriptors enriched with collected file information, each
            conforming to FileToUploadWithCollectedAndDatasetInfoDict.

        Raises
        ------
        InputValidationError
            If a folder contains both files and subdirectories at its top level (invalid
            container/dataset structure).
        """
        files: list["FileToUploadWithCollectedAndDatasetInfoDict"] = []
        datasets: list["DatasetDict"] = []
        containers: list["DIDStringDict"] = []
        attach: "Iterable[AttachDict]" = []
        scope = item.get('did_scope')
        if scope is None:
            scope = self.default_file_scope
        rse = item.get('rse')
        path = item.get('path')
        if path and isinstance(path, str):
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
                        file = cast("FileToUploadWithCollectedAndDatasetInfoDict", file)
                        file['dataset_scope'] = scope
                        file['dataset_name'] = root.split('/')[-1]
                        files.append(file)
                        self.logger(logging.DEBUG, 'Appended file with DID %s:%s' % (scope, fname))
                elif len(dirs) > 0:
                    containers.append({'scope': scope, 'name': root.split('/')[-1]})
                    self.logger(logging.DEBUG, 'Appended container with DID %s:%s' % (scope, path))
                    attach.extend([{'scope': scope, 'name': root.split('/')[-1], 'rse': rse,
                                    'did': {'scope': scope, 'name': dir_}} for dir_ in dirs])
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
                self.client.attach_dids(scope=att['scope'], name=att['name'], dids=[att['did']])
                self.logger(logging.INFO, 'DIDs attached to collection %s:%s' % (att['scope'], att['name']))
            except RucioException as error:
                self.logger(logging.ERROR, error)
                self.logger(logging.ERROR,
                            'It was not possible to attach to collection with DID %s:%s' % (att['scope'], att['name']))
        return files

    def preferred_impl(
            self,
            rse_settings: "RSESettingsDict",
            domain: str
    ) -> Optional[str]:
        """
        Select a suitable protocol implementation for read, write, and delete operations on
        the given RSE and domain.

        This method checks the local client configuration (under the `[upload] preferred_impl`
        setting) and compares it against the list of protocols declared in `rse_settings`.
        It attempts to find a protocol that supports the required I/O operations (read,
        write, delete) in the specified domain. If multiple preferred protocols are listed
        in the config, it iterates in order and returns the first viable match.

        Parameters
        ----------
        rse_settings
            A dictionary describing RSE details, including available protocols and their
            domains.
        domain
            The network domain (e.g., 'lan' or 'wan') in which the protocol must support
            all operations.

        Returns
        -------
        Optional[str]
            The name of a protocol implementation that can handle read/write/delete
            for the specified domain, or None if no suitable protocol was found.
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

            preferred_protocols = [protocol for protocol in reversed(rse_settings['protocols']) if
                                   protocol['impl'] in preferred_impls]

        if len(preferred_protocols) > 0:
            preferred_protocols += [protocol for protocol in reversed(rse_settings['protocols']) if
                                    protocol not in preferred_protocols]
        else:
            preferred_protocols = reversed(rse_settings['protocols'])

        for protocol in preferred_protocols:
            if domain not in list(protocol['domains'].keys()):
                self.logger(logging.DEBUG,
                            'Unsuitable protocol "%s": Domain %s not supported' % (protocol['impl'], domain))
                continue
            if not all(operations in protocol['domains'][domain] for operations in ("read", "write", "delete")):
                self.logger(logging.DEBUG,
                            'Unsuitable protocol "%s": All operations are not supported' % (protocol['impl']))
                continue
            try:
                supported_protocol = rsemgr.create_protocol(rse_settings, 'write', domain=domain, impl=protocol['impl'],
                                                            auth_token=self.auth_token, logger=self.logger)
                supported_protocol.connect()
            except Exception as error:
                self.logger(logging.DEBUG, 'Failed to create protocol "%s", exception: %s' % (protocol['impl'], error))
                pass
            else:
                self.logger(logging.INFO,
                            'Preferred protocol impl supported locally and remotely: %s' % (protocol['impl']))
                supported_impl = protocol['impl']
                break

        return supported_impl
