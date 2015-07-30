# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2015


import os
import os.path

from logging import getLogger

from rucio.client.baseclient import BaseClient
from rucio.common.exception import SourceAccessDenied
from rucio.common.exception import SourceNotFound
from rucio.common.exception import RSEAccessDenied
from rucio.common.exception import FullStorage

LOG = getLogger(__name__)


class UploadClient(BaseClient):
    """ This class cover all functionality related to file uploads into Rucio."""

    BASEURL = '??_uploadclient_??'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, user_agent='rucio-clients'):
        super(UploadClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def upload_files(account, sources):
        """
        This operation is used to upload files into the system. First, file size,
        file checksum and access permissions on the local file system are derived.
        Second, the rucio-server is called to register all necessary data in the
        database i.e. add the file to file catalogue, add file metadata, add
        replication rules. Note that file replicas without replication rule will be
        deleted automatically and therefore at least one replication rule (default)
        must be created. After the rucio server responded without error, the physical
        copy of the file can be started. After the physical copy finished successfully
        the replica's state is changed from 'queued' to 'active' to enable the
        replica for users.

        :param account Account identifier
        :param sources Dictonary with the following structure: { path_to_file: { 'scope': scope, 'replication_spec': {replication_rules}, 'dataset': datasetname, 'checksum': checksum, 'filesize': filesize}}
        :return: report represented by dictonary with informtion on a per file basis, e.g. { 'file.a': True, 'File.b': SourceNotFound, 'File.c': RSEAccessDenied, 'File.d': DatasetAcessDenied, ... }
        """
        report = {}

        for src in sources:
            try:
                if not os.access(src, os.R_OK):
                    report[src] = SourceAccessDenied()
                    continue
            except Exception:
                report[src] = SourceNotFound()
            if not sources[src].filesize:
                sources[src].filesize = os.path.getsize(src)
            if not sources[src].checksum:
                pass  # sources[src].cheksum = TODO: Derive checksum

        # Remove unaccessible/unexisting files from sources to avoid unnecessary checks on the server
        for src in report:
            del(sources[src])

        # ToDo the REST call for:  report = rucio_server.declare_for_upload(sources, atomic=False)
        # ToDo: Merge the response from above into the report array (per file)
        #       possible file status are: DatasetAcessDenied, ScopeAccessDenied, RSEOverQuota, InvalidMetadata, FileReplicaAlreadyExsists, FileConsitencyConfilct, InvalidRepliactionRule, FullStorage
        #       if the transfer is considered to be fine, the value fo the file will be True
        RSEMgr, recommendation = None, None  # In waiting
        for src in sources:
            if report[src]:
                # ToDo the REST call for: recommendation = rucio_server.recommend_storage(account, sources[src])
                # ToDo the REST call for: rucio_server.prepare_upload(account, sources[src], recommendation)
                try:
                    RSEMgr.upload(src, recommendation)
                except (RSEAccessDenied, FullStorage), e:
                    report[src] = e
                    continue
                # ToDo the REST call for: rucio_server.confirm_upload(src, recommendation)
                report[src] = True
