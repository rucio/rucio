# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

'''
Compatibility Wrapper for DQ2 and Rucio.
     http://svnweb.cern.ch/world/wsvn/dq2/trunk/dq2.clients/lib/dq2/clientapi/DQ2.py
'''

from rucio.client.client import Client
from rucio.common.utils import generate_uuid


class DQ2Client:

    def __init__(self):
        self.client = Client()

    def finger(self, userId=None):
        """
        User information lookup program.
        :param userId: The userId (Distinguished Name or account/nickname).
        :return: A dictionary with the name nickname, email, dn.
        """
        if not userId:
            ret = self.client.whoami()
            # ret['email']
            return {'email': 'ph-adp-ddm-lab@cern.ch', 'nickname': ret['account'], 'dn': '/C=CH/ST=Geneva/O=CERN/OU=PH-ADP-CO/CN=DDMLAB Client Certificate/emailAddress=ph-adp-ddm-lab@cern.ch'}

    def bulkDeleteDatasetReplicas(self):
        """
        ToDo MARTIN
        """
        raise NotImplementedError

    def cancelReplicaDeletions(self):
        """
        ToDo MARTIN ???
        """
        raise NotImplementedError

    def checkDatasetConsistency(self):
        """
        ToDo --> N/A
        """
        raise NotImplementedError

    def closeDataset(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def declareBadFiles(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def declareSuspiciousFiles(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def deleteDatasetReplicas(self):
        """
        ToDo MARTIN
        """
        raise NotImplementedError

    def deleteDatasetSubscription(self):
        """
        ToDo MARTIN
        """
        raise NotImplementedError

    def deleteDatasetSubscriptions(self):
        """
        ToDo MARTIN
        """
        raise NotImplementedError

    def deleteDatasetVersionSubscriptions(self):
        """
        ToDo --> N/A
        """
        raise NotImplementedError

    def deleteDatasetsFromContainer(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def deleteFilesFromDataset(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def eraseDataset(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def freezeDataset(self, dsn, scope=None):
        """
        Freezes a dataset.
        ToDo Cedric

        @since: 0.2.0

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions:}
           - DQDaoException is raised,
               in case there is a python or database error in the central catalogs.
           - DQFrozenDatasetException is raised,
               in case the user is trying to freeze an already frozen dataset.
           - DQInvalidRequestException is raised,
               in case the given lfns and guids are not the same length.
           - DQSecurityException is raised,
               in case the given user cannot change the dataset version state.
           - DQUnknownDatasetException is raised,
               in case there is no dataset with the given name.
        """
        raise NotImplementedError

    def getDatasetSize(self):
        """
        Todo Cedric
        """
        raise NotImplementedError

    def getMasterReplicaLocation(self):
        """
        ToDo --> N/A ?
        """
        raise NotImplementedError

    def getMetaDataAttribute(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def getNumberOfFiles(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def getState(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def getVersionMetadata(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetReplicas(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetReplicasInContainer(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasets(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasets2(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsByCreationDate(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsByGUIDs(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsByMetaData(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsByNameInSite(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsInContainer(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsInSite(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listFileReplicas(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listFileReplicasBySites(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listFilesInDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listMetaDataAttributes(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listMetaDataReplica(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listSubscriptionInfo(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listSubscriptions(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listSubscriptionsInSite(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listSuspiciousFiles(self):
        """
        ToDo
        """
        raise NotImplementedError

    def ping(self):
        """
        ToDo
        """
        raise NotImplementedError

    def queryReplicaHistory(self):
        """
        ToDo
        """
        raise NotImplementedError

    def queryStorageUsage(self):
        """
        ToDo
        """
        raise NotImplementedError

    def queryStorageUsageHistory(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerContainer(self, name, datasets=[], scope=None):
        """
        Creates a container.

        @since: 1.0

        @param name: name of the container.
        @type name: str
        @param datasets: list of datasets to be registered.
            [dataset_name1, ..., dataset_nameN]
        @type datasets: list

        @see: https://twiki.cern.ch/twiki/bin/view/Atlas/DonQuijote2ContainerCatalogUC0001

        @raise DQContainerExistsException:
            in case a container with the same name already exists.

        @return: None
        @rtype: NoneType
        """
        self.client.add_container(scope=scope, name=name)
        if datasets:
            self.client.add_datasets_to_container(scope=scope, name=name, datasets=datasets)

    def registerDatasetLocation(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerDatasetSubscription(self):
        """
        ToDo MARTIN
        """
        raise NotImplementedError

    def registerDatasetsInContainer(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerFilesInDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerFilesInDatasets(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerNewDataset(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], scopes=[], cooldown=None,  provenance=None, group=None, hidden=False, scope=None):
        """
        Register a brand new dataset and associated files (lists of lfns and guids).
        @since: 0.2.0

        @param dsn: is the dataset name.
        @param lfns: is a list of logical filenames (LFN).
        @param guids: is a list of file unique identifiers (GUID).
               Note: the GUID is typically assigned by external tools
            (e.g. POOL) and must be passed along as is.
        @param sizes: is a list of the file sizes.
        @param checksums: is a list of the file checksums.
           [md5:<md5_32_character_string>, ...]
        @param cooldown: is a time delta after which the dataset will be automaticaly frozen.
                        Acceptable formats are: "X days" or "X days, HH:MM:SS" or "HH:MM:SS".
        @param provenance: is the dataset provenance, e.g. TO.
        @param group: is the delegated owning group.
        @param hidden: hidden dataset.
        @param scope: is the dataset scope.


        B{Exceptions:}
           - DQDaoException is raised,
               in case there is a python or database error in the central catalogs.
           - DQDatasetExistsException is raised,
               in case there is a dataset with the given name.

        @return: Dictionary containing the dataset duid, vuid and version information.::
           {'duid': '...', 'vuid': '...', 'version': ...}
        """
        self.client.add_dataset(scope=scope, name=dsn)
        if lfns:
            files = []
            for lfn, s, guid, size, checksum in zip(lfns, scopes, guids, sizes, checksums):
                file = {'scope': s, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}}
                if checksum.startswith('md5:'):
                    file['md5'] = checksum[4:]
                elif checksum.startswith('ad:'):
                    file['adler32'] = checksum[3:]
                files.append(file)
            self.client.add_files_to_dataset(scope=scope, name=dsn, files=files)

        return {'duid': generate_uuid(), 'version': 1, 'vuid': generate_uuid()}

    def registerNewDataset2(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerNewVersion(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], ignore=False, scope=None):
        """
        Register a new version of the dataset with the
        given additional files (lists of lfns and guids).
        Plus, it notifies the subscription catalog for changes
        on the dataset and on dataset previous version.

        @since: 0.2.0

        @param dsn: is the dataset name.
        @param lfns: is a list of logical filenames (LFN).
        @param guids: is a list of file unique identifiers (GUID).
            Note: the GUID is typically assigned by external tools
            (e.g. POOL) and must be passed along as is.
        @param sizes: is a list of the file sizes.
        @param checksums: is a list of the file checksums.
            [md5:<md5_32_character_string>, ...]
        @param scope: is the dataset scope.

        B{Exceptions:}
           - DQDaoException is raised,
               in case there is a python or database error in the central catalogs.
           - DQFileExistsInDatasetException is raised,
               in case the given guid is already registered for the given dataset.
           - DQInvalidRequestException is raised,
               in case no files have been added to the content catalog.
           - DQSecurityException is raised,
               in case the user has no permissions to update the dataset.
           - DQUnknownDatasetException is raised,
               in case there is no dataset with the given name.

        @return: Dictionary containing the dataset version information.::
           {'vuid': vuid_1, 'version': 1, 'duid': duid}
        """
        raise NotImplementedError

    def registerNewVersion2(self):
        """
        ToDo
        """
        raise NotImplementedError

    def resetSubscription(self, dsn, location, version=0, scope=None):
        """
        ToDo
        """
        raise NotImplementedError

    def resetSubscriptionsInSite(self):
        """
        ToDo
        """
        raise NotImplementedError

    def searchDatasets(self):
        """
        ToDo
        """
        raise NotImplementedError

    def setDatasetReplicaToDeleted(self):
        """
        ToDo
        """
        raise NotImplementedError

    def setMetaDataAttribute(self):
        """
        ToDo
        """
        raise NotImplementedError

    def setReplicaMetaDataAttribute(self):
        """
        ToDo
        """
        raise NotImplementedError

    def verifyFilesInDataset(self):
        """
        ToDo
        """
        raise NotImplementedError
