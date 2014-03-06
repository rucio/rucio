# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

'''
Compatibility Wrapper for DQ2 and Rucio.
     http://svnweb.cern.ch/world/wsvn/dq2/trunk/dq2.clients/lib/dq2/clientapi/DQ2.py
'''

from datetime import datetime

from rucio.db.constants import RuleState
from rucio.client.client import Client
from rucio.common.utils import generate_uuid
from rucio.common.exception import InvalidMetadata, RSENotFound


class DQ2Client:

    def __init__(self):
        self.client = Client()

    def finger(self, userId=None):
        """
        User information lookup program.
        :param userId: The userId (Distinguished Name or account/nickname).
        :return: A dictionary with the name nickname, email, dn.

        B{Exceptions:}
            - AccountNotFound is raised in case the dataset name doesn't exist.
        """
        result = {}
        account = userId
        if not userId:
            ret = self.client.whoami()
            account = ret['account']
        result['nickname'] = account
        for id in self.client.list_identities(account):
            if id['type'] == 'GSS':
                result['email'] = id['identity']
            elif id['type'] == 'X509':
                result['dn'] = id['identity']
        return result

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

    def checkDatasetConsistency(self, location, dsn, version=0, threshold=None, scope=None):
        """
        This method does nothing in Rucio since there is no tracker. We just check if the dataset exist (by running a get metadata).

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        return True

    def closeDataset(self, scope, dsn):
        """
        Closes the latest dataset version.

        @since: 0.2.0

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - UnsupportedOperation is raised in case the dataset is already closed.

        @return True
        """
        return self.client.close(scope=scope, name=dsn)

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

    def deleteDatasetsFromContainer(self, name, datasets, scope):
        """
        Remove datasets from a container.

        @param name: name of the container.
        @type name: str
        @param datasets: list of datasets to be registered.
            [dataset_name1, ..., dataset_nameN]
        @type datasets: list

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the container or dataset name doesn't exist.

        @see: https://twiki.cern.ch/twiki/bin/view/Atlas/DonQuijote2ContainerCatalogUC0004
        ToDo Cedric
        """
        raise NotImplementedError

    def deleteFilesFromDataset(self):
        """
        ToDo Cedric
        """
        raise NotImplementedError

    def eraseDataset(self, dsn, scope):
        """
        Deletes the subscriptions and the locations

        @param dsn: is the dataset name
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: List of statuses for subscription and deletion deletions
        """
        result = {'location': {}, 'subscription': {}}
        will_erase = True
        for rep in self.client.list_replicas([{'scope': scope, 'name': dsn}]):
            for rse in rep['rses']:
                result[rse] = {'status': True}

        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            state, location, locked = rule['state'], rule['rse_expression'], rule['locked']
            if not location in result['location']:
                result[location] = {'status': True}
            if state == RuleState.REPLICATING:
                result[location]['status'] = False
                result[location]['error'] = 'Cannot delete replicating datasets'
                will_erase = False
        if will_erase:
            self.client.set_metadata(scope=scope, name=dsn, key='expired_at', value=datetime.now())
        return result

    def freezeDataset(self, dsn, scope):
        """
        Freezes a dataset.

        @since: 0.2.0

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - UnsupportedOperation is raised in case the dataset is already closed.

        @return True
        """
        return self.client.close(scope=scope, name=dsn)

    def getDatasetSize(self, dsn, scope):
        """
        Used to get the dataset size

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

       @return: Size as integer
        """
        size = 0
        for f in self.client.list_files(scope=scope, name=dsn):
            size += f['bytes']
        return size

    def getMasterReplicaLocation(self):
        """
        ToDo --> N/A ?
        """
        raise NotImplementedError

    def getMetaDataAttribute(self, dsn, attributes, version=0, scope=None):
        """
        Get the metadata information for the given dataset/dataset version. In Rucio the version is ignored.

        @param dsn: is the dataset name.
        @param attributes: is a list of dataset metadata attributes.
        @param version: is the dataset version (0 is the latest).
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - InvalidMetadata is raised in case the metadata doesn't exist.

        @return Dictionary in the following format:
            {'attribute_1': value_1, ..., 'attribute_N': value_N}
        """
        result = {}
        metadata = self.client.get_metadata(scope=scope, name=dsn)
        for key in attributes:
            if key in metadata:
                result[key] = metadata[key]
            else:
                raise InvalidMetadata
        return result

    def getNumberOfFiles(self, dsn, version, scope):
        """
        Returns the number of files in the given dataset (or dataversion). In Rucio the version is ignored.

        @param dsn: is the dataset name.
        @param version: is the dataset version number. Ignored in Rucio.
        @param scope: is the dataset scope.

        """
        nbfiles = 0
        for f in self.client.list_files(scope=scope, name=dsn):
            nbfiles += 1
        return nbfiles

    def getState(self, dsn, scope):
        """
        Returns the dataset state.

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: The dataset state (check L{dq2.common.DQConstants.DatasetState<common.DQConstants.DatasetState>}).

        """
        metadata = self.client.get_metadata(scope=scope, name=dsn)
        if metadata['is_open']:
            return 0
        else:
            return 2

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

    def queryStorageUsage(self, key=None, value=None, site=None, metaDataAttributes={}, locations=[]):
        """
        Returns a tuple containing storage usage infos .

        @since: 0.4.6
        """
        result = []
        if site is None and locations == []:
            #Loop over all locations
            rses = [rse['rse'] for rse in self.client.list_rses()]
        elif site:
            rses = [site, ]
            try:
                d = self.client.get_rse_usage(site)
            except RSENotFound:
                pass
        else:
            rses = locations

        if key == 'srm' or 'srm' in metaDataAttributes:
            for rse in rses:
                try:
                    d = self.client.get_rse_usage(rse)
                    result.append({'files': None, 'key': 'srm', 'datasets': None, 'tera': d['total']/1024./1024./1024./1024, 'giga': d['total']/1024./1024./1024,
                                   'mega': d['total']/1024./1024., 'bytes': d['total'], 'timestamp': str(d['updated_at']), 'value': 'total', 'location': rse})
                except StopIteration:
                    print 'Error'
                except RSENotFound:
                    #In DQ2 it does not fail if the site does not exist
                    pass
        elif key == 'owner':
            # Need mapping DN to account
            # Right now, only work with account.
            raise NotImplementedError
        elif key == 'group':
            raise NotImplementedError
        return result

    def queryStorageUsageHistory(self, site, key='GRID', value='total'):
        """
        Returns a tuple containing storage usage evolution.
        @since: 0.4.*
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
