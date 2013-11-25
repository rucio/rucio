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
'''

from rucio.client.client import Client


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
        ToDo
        """
        raise NotImplementedError

    def cancelReplicaDeletions(self):
        """
        ToDo
        """
        raise NotImplementedError

    def checkDatasetConsistency(self):
        """
        ToDo
        """
        raise NotImplementedError

    def closeDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def declareBadFiles(self):
        """
        ToDo
        """
        raise NotImplementedError

    def declareSuspiciousFiles(self):
        """
        ToDo
        """
        raise NotImplementedError

    def deleteDatasetReplicas(self):
        """
        ToDo
        """
        raise NotImplementedError

    def deleteDatasetSubscription(self):
        """
        ToDo
        """
        raise NotImplementedError

    def deleteDatasetSubscriptions(self):
        """
        ToDo
        """
        raise NotImplementedError

    def deleteDatasetVersionSubscriptions(self):
        """
        ToDo
        """
        raise NotImplementedError

    def deleteDatasetsFromContainer(self):
        """
        ToDo
        """
        raise NotImplementedError

    def deleteFilesFromDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def eraseDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def freezeDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def getDatasetSize(self):
        """
        ToDo
        """
        raise NotImplementedError

    def getMasterReplicaLocation(self):
        """
        ToDo
        """
        raise NotImplementedError

    def getMetaDataAttribute(self):
        """
        ToDo
        """
        raise NotImplementedError

    def getNumberOfFiles(self):
        """
        ToDo
        """
        raise NotImplementedError

    def getState(self):
        """
        ToDo
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

    def registerContainer(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerDatasetLocation(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerDatasetSubscription(self):
        """
        ToDo
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

    def registerNewDataset(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerNewDataset2(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerNewVersion(self):
        """
        ToDo
        """
        raise NotImplementedError

    def registerNewVersion2(self):
        """
        ToDo
        """
        raise NotImplementedError

    def resetSubscription(self):
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

    def updateCompleteness(self):
        """
        ToDo
        """
        raise NotImplementedError

    def verifyFilesInDataset(self):
        """
        ToDo
        """
        raise NotImplementedError
