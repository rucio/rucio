# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - JingYa You, <jingya.you@twgrid.org>, 2014
# - ChengHsi Chao, <chenghsi.chao@twgrid.org>, 2014
# - Ookey Lai, <ookey.lai@twgird.org>, 2014
# - HuoHao Ho, <luke.ho@twgrid.org>, 2014

'''
Compatibility Wrapper for DQ2 and Rucio.
     http://svnweb.cern.ch/world/wsvn/dq2/trunk/dq2.clients/lib/dq2/clientapi/DQ2.py
'''

import copy
import hashlib
import re
import string

from datetime import datetime, timedelta
from rucio.client.client import Client
from rucio.common.exception import DataIdentifierNotFound, Duplicate, InvalidMetadata, RSENotFound, NameTypeError, InputValidationError, UnsupportedOperation, ScopeNotFound, ReplicaNotFound, RuleNotFound, FileAlreadyExists, FileConsistencyMismatch


def validate_time_formats(time_string):
    try:
        d = re.match(r'((?P<days>\d+) days?)?'
                     r'(, )?'
                     r'((?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d+))?',
                     str(time_string))

        if not filter(lambda r: r[1], d.groupdict().items()):
            err_msg = 'Parameter value [%s] is not a valid time delta !' % (time_string)
            raise InputValidationError(err_msg)

            delta = timedelta(**dict([(key, (value and int(value) or 0)) for key, value in d.groupdict(0).items()]))
            return delta
    except:
        err_msg = 'Parameter value [%s] is not a valid time delta !' % (time_string)
        raise InputValidationError(err_msg)


def extract_scope(dsn):
    # Try to extract the scope from the DSN
    if dsn.find(':') > -1:
        return dsn.split(':')[0], dsn.split(':')[1]
    else:
        scope = dsn.split('.')[0]
        if dsn.startswith('user') or dsn.startswith('group'):
            scope = ".".join(dsn.split('.')[0:2])
        if scope.find('*') > -1:
            if scope.endswith('*'):
                scope = scope.rstrip('*')
            client = Client()
            if scope not in client.list_scopes():
                raise ScopeNotFound('%s is not a valid scope' % scope)
        return scope, dsn


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
        result['email'] = None
        result['dn'] = None
        for id in self.client.list_identities(account):
            if id['type'] == 'GSS':
                result['email'] = id['identity']
            elif id['type'] == 'X509':
                if not result['dn']:
                    result['dn'] = []
                result['dn'].append(id['identity'])
        return result

    def bulkDeleteDatasetReplicas(self):
        """
        ToDo MARTIN
        """
        raise NotImplementedError

    def cancelReplicaDeletions(self, dsn, locations, scope=None):
        """
        Cancel deletion request for a replica. In Rucio does nothing.

        @param dsn: is the dataset.
        @param locations: is a list with the dataset replica locations.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        result = {}
        for location in locations:
            if location not in result:
                result[location] = {'status': False, 'error': UnsupportedOperation}
        return result

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

    def deleteDatasetReplicas(self, dsn, locations, version=0, force=False, deep=False, logical=False, ignore_lifetime=False,  all=False, grace_period=None, ignore_pin=False, scope=None):
        """
        Delete the dataset replica from the given site.

        @param dsn: is the dataset name.
        @param locations: is a list with the dataset replica locations.
        @param version: is the dataset version number.
        @param ignore_pin: is an option to ignore the replica pin.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - AccessDenied in case the account cannot delete the rule.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        # account = self.client.account
        result = {}
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['rse_expression'] in locations:  # or [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]:
                # if rule['account'] == account:
                # print 'Will delete %s:%s from %s ruleid %s' % (scope, dsn, rule['rse_expression'], rule['id'])
                self.client.delete_replication_rule(rule['id'])
                result['rse_expression'] = {'status': True}
        for location in locations:
            if location not in result:
                result[location] = {'status': False, 'error': RuleNotFound}
        return result

    def deleteDatasetSubscription(self, dsn, site, version=None, scope=None):
        """
        Removes the dataset/dataset version subscription of the given dataset name from the given site. In Rucio does nothing.

        @param dsn: is the dataset name.
        @param site: is the subscription dq2.location.
        @param version: is the dataset version number (None is passed the duid will be used).
        @param scope: is the dataset scope.

        B{Exceptions}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        return

    def deleteDatasetSubscriptions(self, dsn, scope=None):
        """
        Marks all dataset/dataset version subscriptions of the given dataset. In Rucio does nothing.

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        return

    def deleteDatasetVersionSubscriptions(self, dsn, version, scope=None):
        """
        Removes all subscriptions of the given dataset version. In Rucio does nothing

        @param dsn: is the dataset name.
        @param version: is the dataset version number
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        return

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

    def deleteFilesFromDataset(self, dsn, guids=[], scope=None):
        """
        Removes files from an existing dataset. Files are
        removed from the latest open version only.

        @param dsn: is the dataset name.
        @param guids: is a list of file unique identifiers (GUID).
            Note: the GUID is typically assigned by external tools
            (e.g. POOL) and must be passed along as is.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: List of lfns that failed to be added since they are duplicates?
        """
        dids = []
        # create rucio parameter
        for fn in guids:
            did = {'scope': scope, 'name': fn}
            dids.append(did)
        self.client.detach_dids(scope=scope, name=dsn, dids=dids)

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
            state, location = rule['state'], rule['rse_expression']
            if location not in result['location']:
                result[location] = {'status': True}
            if state == 'REPLICATING':
                result[location]['status'] = False
                result[location]['error'] = 'Cannot delete replicating datasets'
                will_erase = False
        if will_erase:
            self.client.set_metadata(scope=scope, name=dsn, key='expired_at', value=datetime.now())
        return result

    def freezeDataset(self, dsn, scope):
        """
        Freezes a dataset.

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

    def getMasterReplicaLocation(self, dsn, version=0, scope=None):
        """
        Returns the master replicas location, in Rucio, this is the oldest rule.

        @param dsn: is the dataset name.
        @param version: the version (not used in Rucio.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
        self.client.get_metadata(scope=scope, name=dsn)
        oldest_rule = datetime.now()
        rse = None
        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            if rule['created_at'] < oldest_rule:
                oldest_rule = rule['created_at']
                rse = rule['rse_expression']
        return rse

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
        metadata_mapping = {'owner': 'account', 'creationdate': 'created_at', 'deleteddate': 'deleted_at', 'lifetime': 'expired_at', 'hidden': 'hidden', 'versioncreationdate': 'created_at'}
        metadata_static = {'latestversion': 1, 'lastoperationdn': None, 'lastoperationip': None, 'closeddate': None, 'frozendate': None, 'freezingdate': None, 'group': None, 'provenance': None,
                           'version': 1, 'origin': None, 'physicsgroup': None, 'temperature': None, 'tier0state': None, 'tier0type': None}
        for key in attributes:
            if key in metadata_mapping:
                result[key] = metadata[metadata_mapping[key]]
            elif key in metadata_static:
                result[key] = metadata_static[key]
            elif key in ['duid', 'vuid', 'latestvuid']:
                result[key] = hashlib.md5(scope+':'+dsn).hexdigest()
            elif key == 'state':
                result[key] = 2
                if metadata['is_open']:
                    result[key] = 0
            elif key == 'type':
                if metadata['did_type'] == 'DATASET':
                    result[key] = 1
                elif metadata['did_type'] == 'CONTAINER':
                    result[key] = 2
            elif key in ['nbfiles', 'length']:
                nbfiles, length = 0, 0
                for did in self.client.list_files(scope=scope, name=dsn):
                    nbfiles += 1
                    length += did['bytes']
                if key == 'nbfiles':
                    result[key] = nbfiles
                else:
                    result[key] = length
            elif key == '#replicas':
                replicas = []
                for reps in self.client.list_replicas([{'scope': scope, 'name': dsn}]):
                    for rep in reps['rses']:
                        if rep not in replicas:
                            replicas.append(rep)
                result[key] = len(replicas)
            else:
                raise InvalidMetadata
        return result

    def getNumberOfFiles(self, dsn, version, scope):
        """
        Returns the number of files in the given dataset (or dataversion). In Rucio the version is ignored.

        @param dsn: is the dataset name.
        @param version: is the dataset version number. Ignored in Rucio.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: Number of files (integer)
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

    def getVersionMetadata(self, dsn, version=0, scope=None):
        """
        Retrieve data set version metadata.

        @param dsn: is the dataset name.
        @param version: is the dataset version number. Ignored in Rucio.
        @param scope: is the dataset scope.


        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: duid_10, vuid_10, version, versioncreationdate, tier0state, tier0type, numberfiles, size
        @rtype: tuple
        """
        metadata = self.client.get_metadata(scope=scope, name=dsn)
        vuid = hashlib.md5(scope+':'+dsn).hexdigest()
        vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
        duid = vuid
        nbfiles = 0
        bytes = 0
        for f in self.client.list_files(scope=scope, name=dsn):
            nbfiles += 1
            bytes += f['bytes']
        return (duid, vuid, 1, metadata['created_at'], '', '', nbfiles, bytes)

    def listDatasetReplicas(self, dsn, version=0, complete=None, old=True, scope=None):
        """
        List the dataset replicas.

        @param dsn
        @param version: 0, no version in Rucio
        @param complete:
        @param old: if old=True, call list_data_locks(), otherwise call list_replicas()
        @param scope:

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - InvalidMetadata is raised in case the metadata doesn't exist.
        @return Dictionary in the following format:
            {'rse_1':[{'attribute_1': value_1, ..., 'attribute_N': value_N}],'rse_2':[{...}]}

        @Rucio
        @pdn: always be ''
        @archived: should be always 'primary' for replicas without lifetime and 'secondary' for replicas with lifetime.
        @version: always be 0
        @transferState: If one the files is replicating, transferState=1, otherwise 0
        @chekState: always be 6
        @immutable: should be 0 for open datasets and 1 for closed datasets.

        @get_dataset_locks will help when option old=True is used

        """
        result = {}
        files = []
        dq2attrs = {'pdn': '', 'archived': 'primary', 'version': 0, 'checkstate': 6, 'transferState': 0, 'found': 0, 'total': 0, 'immutable': 0}
        metadata = self.client.get_metadata(scope, name=dsn)
        # @immutable
        if not metadata['is_open']:
            dq2attrs['immutable'] = 1
        # @archived
        if metadata['expired_at'] is not None:
            dq2attrs['archived'] = 'secondary'

        # @transferState
        replicating_rses = []
        if not old:
            for rule in self.client.list_did_rules(scope, dsn):
                if rule['state'] == 'REPLICATING':
                    for item in self.client.list_rses(rule['rse_expression']):
                        replicating_rses.append(item['rse'])
        else:
            pass
            # will call self.client.get_dataset_locks() for LockState if old=True

        # list_replicas()
        for f in self.client.list_replicas(dids=[{'scope': scope, 'name': dsn}], schemes=['srm']):
            rses = f['rses'].keys()
            if not f['name'] in files:
                files.append(f['name'])
                for rse in rses:
                    if rse not in result:
                        result[rse] = [copy.deepcopy(dq2attrs)]
                        result[rse][-1]['found'] = 0
                    result[rse][-1]['found'] += 1
        for rse in result:
            result[rse][-1]['total'] = len(files)
            if rse in replicating_rses:
                result[rse][-1]['transferState'] = 1

        if old:
            replicas = {0: [], 1: []}
            for rse in result:
                if result[rse][0]['found'] == result[rse][0]['total']:
                    replicas[1].append(rse)
                else:
                    replicas[0].append(rse)
            vuid = hashlib.md5(scope+':'+dsn).hexdigest()
            vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
            return {vuid: replicas}

        return result

    def listDatasetReplicasInContainer(self, cn, scope=None):
        """
        ToDo -> Jingya You

        @return: a dictionary containing all dataset replicas for the container.
        { <dataset_1>:
                   {<vuid>: {0: [<site_1>], 1: [<site_2>,<site_3>]}},
        <dataset_2>:
                  {<vuid>: {0: [<site_1>], 1: [<site_2>,<site_3>]}},
        ...}
        @0:Incomplete, 1:Complete

        ({'rse_id': row.rse_id,
          'scope': row.scope,
          'name': row.name,
          'rule_id': row.rule_id,
          'account': row.account,
          'state': row.state})

        """
        result = {}
        replicas = {0: [], 1: []}
        self.client.get_metadata(scope=scope, name=cn)
        for i in self.client.list_content(scope, cn):
            if i['type'] == 'DATASET' and i['name'] not in result:
                vuid = hashlib.md5(scope+':'+i['name']).hexdigest()
                vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
                result[i['name']] = {vuid: replicas}

        for dsn in result.keys():
            replicas = self.listDatasetReplicas(scope=scope, dsn=dsn, old=True)
            result[dsn] = replicas

        return result

    def listDatasets(self, dsn, version=0, onlyNames=False, p=None, rpp=None, scope=None):
        """
        ToDo -> Jingya You

        Used to return a list of datasets matching the given
        pattern and version.

        @param dsn: is the dataset name.
        @param version: is the dataset version number.
        @param onlyNames: Option to return only the dataset names.
        @param rpp: Print rrp first results.
        @param p: Specify page to print.
        @param scope: is the dataset scope.

        @DQ2
        B{Exceptions:}
            - DQDaoException is raised,
                in case there is a python or database error in the central catalogs.

        usage::
            listDatasets('myname') - returns all versions of the given dataset
            listDatasets('myname*') - returns all versions of the datasets that start by 'myname'.
            listDatasets('*myname') - returns all versions of the datasets that end by 'myname'. -> this should be avoid

            listDatasets('myname', 2) - returns the version 2 of dataset 'myname'.
            listDatasets('myname', 0) - returns the latest version of the dataset 'myname'.
            listDatasets('myname', <0) - returns all the versions of the dataset 'myname'.
            listDatasets('myname', ]-infinite, 0[) - returns all the versions of the dataset 'myname'.

            listDatasets('myname*', 2) - returns the version 2 of the datasets that start by 'myname'.
            listDatasets('*myname', None) - returns all the versions of the datasets that end with 'myname'.

        @return: Dictionary containing the dataset versions information.
            {
                'dataset_nameA': {'duid': duid, 'vuids': ['A_vuid_for_version1+X', ..., 'A_vuid_for_version1']}
                'dataset_nameB': {'duid': duid, 'vuids': ['B_vuid_for_version1']}
            }, where X > 0

        @Rucio
        @return: No version in Rucio
           {
                'dataset_nameA': {'duid': rucio_did, 'vuids': [rucio_did]},
                'dataset_nameB': {'duid': rucio_did, 'vuids': [rucio_did]}...
           }
        """
        match = re.match(r'^\*', dsn)
        if not match:
            filters = {'name': dsn}
            result = {}
            for dsn in self.client.list_dids(scope, filters, type='dataset'):
                vuid = hashlib.md5(scope+':'+dsn).hexdigest()
                vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
                duid = vuid
                if dsn not in result:
                    result[dsn] = {'duid': duid, 'vuids': [vuid]}
            return result
        else:
            raise InputValidationError

    def listDatasets2(self, metaDataAttributes, long=False, all=False, p=None, rpp=None, scope=None):
        """
        ToDo -> Jingya You

        Used to return a list of datasets matching the given
        pattern and version.
        In DQ2 the autorized metadata are :
        state, type, name, duid, duid_10, vuid, version, creationdate, closeddate, deleteddate, frozendate,
        modifieddate, tier0state, origin, tier0state, tier0type, physicsgroup
        In Rucio the authorized metadata are :
        state, type, name

        @param metaDataAttributes: metadata attibutes for the sorting
        @param long: List dataset in long format (total sum for all the file sizes + total num of files).
        @param all: List all datasets, including the hidden ones.
        @param rpp: Print rrp first results.
        @param p: Specify page to print.

        B{Exceptions:}
            - InvalidMetadata is raised in case the metadata doesn't exist.

        usage::
            listDatasets(metaDataAttributes={name:'myname'}) - returns all datasets matching the pattern

        @return: Dictionary containing the dataset information.
            {
                'dataset_nameA': {}
                'dataset_nameB': {}
            }
        """
        result = {}
        filters = {}
        if (scope is None) and 'name' in metaDataAttributes:
            try:
                scope, dsn = extract_scope(metaDataAttributes['name'])
            except ScopeNotFound:
                return result
            type = 'collection'
            metadata = ['state', 'type', 'name']
            for key in metaDataAttributes:
                if key not in metadata:
                    raise InvalidMetadata
                if key == 'name':
                    filters['name'] = metaDataAttributes[key]
                elif key == 'state':
                    if metaDataAttributes[key] == 0:
                        filters['is_open'] = 1
                    else:
                        filters['is_open'] = 0
                elif key == 'type':
                    if metaDataAttributes[key] == 1:
                        type = 'dataset'
                    elif metaDataAttributes[key] == 2:
                        type = 'container'
            print scope, dsn, filters
            if long:
                for name in self.client.list_dids(scope, filters, type):
                    meta = {'totalSize': 0, 'totalFiles': 0}
                    # Can take very long. Bulk method is needed !!!
                    for did in self.client.list_files(scope=scope, name=name):
                        meta['totalSize'] += did['bytes']
                        meta['totalFiles'] += 1
                    result[name] = meta
            else:
                for name in self.client.list_dids(scope, filters, type):
                    result[name] = {}
            return result
        else:
            return result
        #    raise ScopeNotFound('Please specify a valid scope')

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

    def listDatasetsByMetaData(self, filter):
        """
        List the dataset versions that match the given criteria.
        In DQ2 the autorized metadata are :
        state, type, name, duid, duid_10, vuid, version, creationdate, closeddate, deleteddate, frozendate,
        modifieddate, tier0state, origin, tier0state, tier0type, physicsgroup
        In Rucio the authorized metadata are :
        state, type, name

        @param filter: list containing dictionaries of metadata attributes and values
            ({'attrname_0': attrvalue_0, ..., 'attrname_N': attrvalue_N}).

        B{Exceptions:}
            - InvalidMetadata is raised in case the metadata doesn't exist.

        @return: List of tuples with (dataset name, version).
            [
                ('dataset_name_1', 'vuid_1'),
                (...),
                ('dataset_name_N', 'vuid_N')
            ]
        """
        metadata = ['state', 'type', 'name']
        for key in filter:
            if key not in metadata:
                raise InvalidMetadata
        raise NotImplementedError

    def listDatasetsByNameInSite(self, site, complete=None, name=None, p=None, rpp=None, group=None):
        """
        List datasets at site

        @param site: is the location to be searched for.
        @param complete: is the location state of the dataset at a site and may have
            the following values: None: in which case the
            location state is ignore; LocationState.COMPLETE: lists only datasets
            fully present at the site (no files missing);
            LocationState.INCOMPLETE: lists only datasets partially present at the
            site (some files missing).
        @param page: is the page to be displayed.
        @param rpp: are the results per page.
        @param group: Not used

        B{Exceptions:}
            - RSENotFound is raised in case the site doesn't exist.

        @return: Tuple of dataset.
            ('dsn1', 'dsn2'... )
        """
        result = []
        pattern = None
        if name:
            pattern = string.replace(name, '*', '.*')
        for did in self.client.get_dataset_locks_by_rse(site):
            scope = did['scope']
            dsn = did['name']
            state = did['state']
            if pattern:
                if re.match(pattern, dsn):
                    match = True
                else:
                    match = False
            else:
                match = True
            if complete == 1:
                if state == 'OK' and match:
                    result.append('%s:%s' % (scope, dsn))
            elif complete == 0:
                if state != 'OK' and match:
                    result.append('%s:%s' % (scope, dsn))
            elif match:
                result.append('%s:%s' % (scope, dsn))
        return tuple(result)

    def listDatasetsInContainer(self, cn, scope):
        """
        ToDo -> Jingya You
        @param cn: container name
        @return: Not found in DQ2
        @Rucio's return
        [{u'adler32': None, u'name': u'2013-12-30_11', u'bytes': None, u'scope': u'ams-2014-ISS.B700-pass5', u'type': u'DATASET', u'md5': None}, \
        {u'adler32': None, u'name': u'2013-12-30_12', u'bytes': None, u'scope': u'ams-2014-ISS.B700-pass5', u'type': u'DATASET', u'md5': None}, ....]

        """
        ret = []
        try:
            if self.client.get_metadata(scope, cn)['did_type'] == 'CONTAINER':
                for i in self.client.list_content(scope, cn):
                    if i['type'] == 'DATASET':
                        ret.append('%s:%s' % (i['scope'], i['name']))
                return ret
            else:
                raise NameTypeError
        except DataIdentifierNotFound:
            if cn.endswith('/'):
                cn = cn.rstrip('/')
                if self.client.get_metadata(scope, cn)['did_type'] == 'CONTAINER':
                    for i in self.client.list_content(scope, cn):
                        if i['type'] == 'DATASET':
                            ret.append('%s:%s' % (i['scope'], i['name']))
                    return ret
                else:
                    raise NameTypeError
        raise DataIdentifierNotFound

    def listDatasetsInSite(self, site, complete=None, page=1, rpp=100):
        """
        List all the datasets and their versions available on
        the given site.

        @param site: is the location to be searched for.
        @param complete: is the location state of the dataset at a site and may have
            the following values: None: in which case the
            location state is ignore; LocationState.COMPLETE: lists only datasets
            fully present at the site (no files missing);
            LocationState.INCOMPLETE: lists only datasets partially present at the
            site (some files missing).
        @param page: is the page to be displayed.
        @param rpp: are the results per page.

        B{Exceptions:}
            - RSENotFound is raised in case the site doesn't exist.

        @return: List of dataset versions.
            {'dsn': [version_numberX,... version_numberY]}
        """
        result = {}
        for did in self.client.get_dataset_locks_by_rse(site):
            scope = did['scope']
            name = did['name']
            state = did['state']
            if complete == 1:
                if state == 'OK':
                    result['%s:%s' % (scope, name)] = [1]
            elif complete == 0:
                if state != 'OK':
                    result['%s:%s' % (scope, name)] = [1]
            else:
                result['%s:%s' % (scope, name)] = [1]
        return result

    def listFileReplicas(self, location, dsn, version=0, scope=None):
        """

        @param dsn is the dataset name.
        @param version is the dataset version number.
        @param scope: is the dataset scope.
        @param location is the location place of the dataset
        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        @ return dictionnary e.g.:
        {'content': [guid1,...], 'transferState': 1, 'length': 46018142, 'checkstate': 6, 'found': 200, 'total': 200, 'immutable': 1}]
        """
        lfn_to_guid = {}
        total = 0
        length = 0
        found = 0
        guids = []
        immutable = 1
        if self.client.get_metadata(scope, dsn)['is_open']:
            immutable = 1
        for x in self.client.list_files(scope, dsn, long=True):
            guid = '%s-%s-%s-%s-%s' % (x['guid'][0:8], x['guid'][8:12], x['guid'][12:16], x['guid'][16:20], x['guid'][20:32])
            lfn_to_guid[(scope, x['name'])] = guid
            total += 1
        for replica in self.client.list_replicas([{'scope': scope, 'name': dsn}], schemes=['srm']):
            if location in replica['rses']:
                length += replica['bytes']
                found += 1
                guids.append(lfn_to_guid[(replica['scope'], replica['name'])])
        return {'content': guids, 'transferState': 1, 'length': length, 'checkstate': 6, 'found': found, 'total': total, 'immutable': immutable}

    def listFileReplicasBySites(self, dsn, version=0, locations=[], threshold=None, timeout=None, scope=None):
        """
        Iterator to list file replica with info refresh if needed.

        @param dsn: String - Dataset name to check.
        @param version: Number - Dataset version to check, don't need to be implanted in Rucio.
        @param locations: List of locations. Restrict result to a subset of locations.
        @param threshold:  in seconds. Refresh info if checkdate < sysdate - threshold. #not implanted
        @param timeout:  in seconds. #neccessary? There's no timeout exception in rucio.common.exception
        @param scope: is the dataset scope.

        @raise No replicas found, timeout

        @Rucio
        @version: always be 0
        @transferState: If the files are replicating, transferState=1, otherwise 0
        @checkState: always be 6
        @immutable: should be 0 for open datasets and 1 for closed datasets.
        @get_dataset_locks will help when option old=True is used

        """
        attrList = ['total', 'found']
        # template dict for dq2 attributes
        dq2attrs = {'content': [], 'transferState': 0, 'length': 0, 'checkstate': 6, 'found': 0, 'total': 0, 'immutable': 0}
        # @transferState
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['state'] == 'REPLICATING':
                dq2attrs['transferState'] = 1
        # @immutable
        if not self.client.get_metadata(scope, dsn)['is_open']:
            dq2attrs['immutable'] = 1
        if locations:
            rse_dict = dict((rse, copy.deepcopy(dq2attrs)) for rse in locations)
        else:
            rse_dict = {}
        for f in self.client.list_replicas(dids=[{'scope': scope, 'name': dsn}]):
            # rses the file is in
            in_rse = f['rses'].keys()
            for rse in in_rse:
                rse = str(rse)
                if rse not in rse_dict and not locations:
                    rse_dict[rse] = copy.deepcopy(dq2attrs)
                try:
                    # @content
                    rse_dict[rse]['content'].append(str(f['name']))
                    # @length
                    rse_dict[rse]['length'] = rse_dict[rse]['length'] + f['bytes']
                    # @total,found
                    for attrs in attrList:
                        if attrs not in rse_dict[rse]:
                            rse_dict[rse][attrs] = 0
                        rse_dict[rse][attrs] += 1
                except KeyError:
                    continue
        for rse in rse_dict:
            if rse_dict[rse]['content']:
                yield (rse, rse_dict[rse])

    def listFilesInDataset(self, dsn, version=None, scope=None):
        """
        Given a dataset name, and optional version, the guids
        and lfns of the files in the dataset are returned.

        @param dsn: is the dataset name.
        @param version: is the dataset version number (0 => the latest version). not in Rucio
        @param scope: is the dataset scope.

        B{Exceptions}:
            - DQDaoException is raised,
                in case there is a python or database error in the central catalogs.
            - DQUnknownDatasetException is raised,
                in case there is no dataset with the given name.

        """
        return_dict = {}
        metadata = self.client.get_metadata(scope=scope, name=dsn)
        lastdate = str(metadata['updated_at'])
        for x in self.client.list_files(scope, dsn, long=True):
            dq2attrs = {}
            dq2attrs['checksum'] = "ad:" + str(x['adler32'])
            dq2attrs['filesize'] = x['bytes']
            dq2attrs['scope'] = str(x['scope'])
            dq2attrs['lfn'] = str(x['name'])
            guid = '%s-%s-%s-%s-%s' % (x['guid'][0:8], x['guid'][8:12], x['guid'][12:16], x['guid'][16:20], x['guid'][20:32])
            return_dict[guid] = dq2attrs
        return (return_dict, lastdate)

    def listMetaDataAttributes(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listMetaDataReplica(self, location, dsn, version=0, scope=None):
        """
        Returns a list containing all metadata attributes for dataset replicas.

        @param scope: is the dataset scope.

        @since: 0.4.0
        """
        creationdate = datetime.now()
        transferdate = datetime.now()
        transferState = 0
        checkdate = datetime.now()
        atime = 'None'
        owner = 'None'
        expirationdate = 'None'
        archived = 'secondary'
        immutable = 1
        metadata = self.client.get_metadata(scope=scope, name=dsn)
        if metadata['is_open']:
            immutable = 0
        exists = False
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['rse_expression'] == location or [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]:
                exists = True
                if rule['created_at'] < creationdate:
                    creationdate = rule['created_at']
                    transferdate = rule['updated_at']
                    owner = rule['account']
                    if rule['expires_at'] is None:
                        archived = 'primary'
                    else:
                        expirationdate = rule['expires_at']
        if not exists:
            raise ReplicaNotFound
        result = {'transferdate': transferdate, 'owner': owner, 'atime': atime, 'archived': archived, 'group': ' None', 'transferState': transferState,
                  'checkdate': checkdate, 'version': 1, 'checkState': 6, 'pin_expirationdate': 'None', 'creationdate': creationdate, 'immutable': immutable, 'expirationdate': expirationdate}
        return result

    def listSubscriptionInfo(self, dsn, location, version, scope=None):
        """
        @param dsn: the dataset name.
        @version: the dataset version. Ignored in Rucio.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: tuple containing the dataset subscription information is returned.::
            (uid, owner, location, destination, creationdate, modifieddate, callbacks, archived, sources_policy, wait_for_sources, sources, query_more_sources, share)
        """
        self.client.get_metadata(scope=scope, name=dsn)
        result = ()
        creationdate = datetime.now()
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['state'] != 'OK' and (location == rule['rse_expression'] or location in [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]):
                print rule
                if rule['created_at'] < creationdate:
                    id = rule['id']
                    id = '%s-%s-%s-%s-%s' % (id[0:8], id[8:12], id[12:16], id[16:20], id[20:32])
                    owner = rule['account']
                    destination = None
                    creationdate = rule['created_at']
                    modifieddate = rule['updated_at']
                    callbacks = {}
                    archived = 'primary'
                    sources_policy = 1
                    wait_for_sources = 0
                    sources = {}
                    query_more_sources = 0
                    share = 'secondary'
                    group = 'None'
                    replica_lifetime = rule['expires_at']
                    activity = 'Rucio'
                    parentId = 'None'
                    requestId = hashlib.md5('%s:%s:%s' % (scope, dsn, location)).hexdigest()
                    requestId = '%s-%s-%s-%s-%s' % (requestId[0:8], requestId[8:12], requestId[12:16], requestId[16:20], requestId[20:32])
                    result = (id, owner, location, destination, creationdate, modifieddate, callbacks, archived, sources_policy, wait_for_sources, sources, query_more_sources, share, group, replica_lifetime, activity, parentId, requestId)
            elif rule['state'] == 'OK' and (location == rule['rse_expression'] or location in [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]):
                return ()
        return result

    def listSubscriptions(self, dsn, version=None, archived=None, scope=None):
        """
        Return a list of sites that have subscribed the given dataset.

        @param dsn: is the dataset name.
        @param version: is the dataset version number (0 is the latest).
        @param archived: is the dataset subscription state.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.

        @return: List containing the sites that subscribed, at least, a version of the dataset.
        """
        self.client.get_did(scope, dsn)
        rse_expressions = []
        list_rses = []
        result = []
        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            if (rule['state'] != 'OK') and (rule['rse_expression'] not in rse_expressions):
                rse_expressions.append(rule['rse_expression'])
        for rse_expression in rse_expressions:
            for rse in self.client.list_rses(rse_expression):
                if rse not in list_rses:
                    list_rses.append(rse['rse'])
        for replica in self.client.list_replicas([{'scope': scope, 'name': dsn}], unavailable=True):
            for rse in replica['rses']:
                if (rse in list_rses) and (rse not in result):
                    result.append(rse)
        return result

    def listSubscriptionsInSite(self, site, long=False):
        """
        Returns a dict of all subscribed uids in a site containing all attributes.

        @param site: is the dataset subscription dq2.location.
        @param long: List dataset in long format (total sum for all the file sizes + total num of files).

        B{Exceptions:}
            - RSENotFound is raised in case the site doesn't exist.

        @return: Returns a list of all subscribed uids in a site containing all attributes.
            {'dsn': [versionX, versionY]}
        """
        result = {}
        for did in self.client.get_dataset_locks_by_rse(site):
            scope = did['scope']
            name = did['name']
            state = did['state']
            if long:
                if state != 'OK':
                    result['%s:%s' % (scope, name)] = {'totalSize': 0, 'version': 1, 'totalFiles': 0}
                    for i in self.client.list_files(scope=scope, name=name):
                        result['%s:%s' % (scope, name)]['totalFiles'] += 1
                        result['%s:%s' % (scope, name)]['totalSize'] += i['bytes']
            else:
                if state != 'OK':
                    result['%s:%s' % (scope, name)] = [1]
        return result

    def listSuspiciousFiles(self):
        """
        ToDo
        """
        raise NotImplementedError

    def ping(self):
        """
        Checks if the Rucio clients are well configured.

        @return: dictionary containing the client's configuration settings.::
            {
                'rucio'      : (url_insecure, url_secure, alive),
            }
        """
        try:
            self.client.ping()
            return {'rucio': (self.client.host, self.client.host, True)}
        except:
            return {'rucio': (self.client.host, self.client.host, False)}

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
            # Loop over all locations
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
                    # In DQ2 it does not fail if the site does not exist
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
            # self.client.add_datasets_to_container(scope=scope, name=name, datasets=datasets)
            # is the parameter name change from datasets to dsn?
            self.client.add_datasets_to_container(scope=scope, name=name, dsn=datasets)

    def registerDatasetLocation(self, dsn, location, version=0, complete=0, group=None, archived=None, acl_alias=None, lifetime=None, pin_lifetime=None, scope=None):
        """
        ToDo -->KuoHao
        Register new replica of a dataset(which must already defined in the repository)

        @param dsn: is the dataset name.
        @param location: is the dataset dq2.location.(map to rucio RSE?)
        @param version: is the dataset version number.
        @param complete: is the location state of the dataset at a site and may have the following values:
            None: in which case the location state is ignore;
            LocationState.COMPLETE: lists only datasets fully present at the site (no files missing);
            LocationState.INCOMPLETE: lists only datasets partially present at the site (some files missing).
        @param acl_alias: is the  acl_alias, e.g. custodial which will be assocaited with the replica.
        @param archived: Obsolete argument (still here to maintain backward compatibility).
        @param lifetime: Dataset replica lifetime. Acceptable formats are: "X days" or "X days, HH:MM:SS" or "HH:MM:SS".
        @param pin_lifetime: Pin replica lifetime. Acceptable formats are: "X days" or "X days, HH:MM:SS" or "HH:MM:SS".
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - UnsupportedOperation is raised in case the location does not exist.
        """
        if location in [loc['rse'] for loc in self.client.list_rses()]:
            dids = []
            did = {'scope': scope, 'name': dsn}
            dids.append(did)
            # Add replication rule
            self.client.add_replication_rule(dids=dids, copies=1, rse_expression=location, weight=None, lifetime=lifetime, grouping='DATASET', account=None, locked=False)
        else:
            raise UnsupportedOperation('Unknown RSE [%s]' % (location))
        return True

    def registerDatasetSubscription(self, dsn, location, version=0, archived=None,
                                    callbacks={}, sources={}, sources_policy=None,
                                    wait_for_sources=0, destination=None, query_more_sources=0, sshare=None,
                                    group=None, owner=None, activity=None, acl_alias=None, replica_lifetime=None,
                                    check_destination=False, parentId=None, pin_lifetime=None, scope=None):
        """
        Register a new subscription in the location catalog. If the
        version is not specified a duid is used.

        @since: 0.2.0

        @param dsn: is the dataset name.
        @param location: is the location where the dataset should be subscribed.
        @param version: not used.
        @param archive: not used.
        @param callbacks: is a dictionary which specifies, per subscription callback.
        @sources: not used.
        @destination: not used.
        @query_more_sources: not used.
        @sshare: not used yet.
        @group: not used.
        @owner: not used yet.
        @activity: not used.
        @acl_alias: not used.
        @replica_lifetime: not used.
        @check_destination: not used.
        @parentId: not used.
        @pin_lifetime: not used.
        @param scope: is the dataset scope.
        """
        self.client.get_did(scope, dsn)
        if not owner:
            owner = 'root'
        else:
            l = [i for i in self.client.list_accounts('user', owner)]
            if l != []:
                owner = l[0]['account']
        dids = [{'scope': scope, 'name': dsn}]
        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            if (rule['rse_expression'] == location) and (rule['account'] == owner):
                raise Duplicate('A rule for %s:%s at %s already exists' % (scope, dsn, location))
        self.client.add_replication_rule(dids, copies=1, rse_expression=location, weight=None, lifetime=replica_lifetime, grouping='DATASET', account=owner, locked=False)

    def registerDatasetsInContainer(self, name, datasets, scope=None):
        """
        ToDo Ookey
        Register datasets into a container.

        @param name: name of the container.
        @type name: str
        @param datasets: list of datasets to be registered.
            [dataset_name1, ..., dataset_nameN]
        @type datasets: list
        @param scope: is the dataset scope.

        @since: 1.0

        @raise DQContainerIsInStateException:
            in case the container is closed or archived.
        @raise DQContainerNotOwner:
            in case the user is not the owner of the container.
        @raise DQContainerUnknownException:
            in case the container does not exist.

        @see: https://twiki.cern.ch/twiki/bin/view/Atlas/DonQuijote2ContainerCatalogUC0003
        @see: https://twiki.cern.ch/twiki/bin/view/Atlas/DonQuijote2ContainerCatalogUC0010
        @see: https://twiki.cern.ch/twiki/bin/view/Atlas/DonQuijote2ContainerCatalogUC0011

        """
        dsns = []
        # create rucio parameter
        for ds in datasets:
            dsn = {'scope': scope, 'name': ds}
            dsns.append(dsn)
        self.client.add_datasets_to_container(scope=scope, name=name, dsns=dsns)

    def registerFilesInDataset(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], ignore=False, scope=None, rse=None):
        """
        ToDo-->KuoHao

        Add existing files to an existing dataset.(attach file to dataset)

        @param dsn: is the dataset name.
        @param lfns: is a list of logical filenames (LFN).
        @param guids: is a list of file unique identifiers (GUID).
        @param sizes: is a list of the file sizes.
        @param checksums: is a list of the file checksums.
            [md5:<md5_32_character_string>, ...]
        @param ignore: is a boolean to ignore errors.
        @param scope: is the dataset scope.
        @param rse: is the rse.

        """
        result = {}
        # check dataset status (not closed)
        info = self.client.get_did(scope, dsn)
        if not (info['open']):
            raise UnsupportedOperation

        # merge lfn, guid, size, checksum into rucio file format
        files = []
        for lfn, guid, size, checksum in zip(lfns, guids, sizes, checksums):
            if lfn.find(':') > -1:
                s, lfn = lfn.split(':')[0], lfn.split(':')[1]
            else:
                s = scope
            file = {'scope': s, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}}
            if checksum.startswith('md5:'):
                file['md5'] = checksum[4:]
            elif checksum.startswith('ad:'):
                file['adler32'] = checksum[3:]
            files.append(file)
        # add new file to dataset(rse need assign), in rucio rse is pre-assign(by user or group
        try:
            self.client.add_files_to_dataset(scope=scope, name=dsn, files=files, rse=rse)
            for lfn in lfns:
                result[lfn] = {'status': True}
        except (FileAlreadyExists, Duplicate):
            for did in files:
                try:
                    self.client.add_files_to_dataset(scope=scope, name=dsn, files=[did], rse=rse)
                    result[lfn] = {'status': True}
                except (FileAlreadyExists, Duplicate):
                    meta = self.client.get_metadata(did['scope'], did['name'])
                    guid = meta['guid']
                    guid = '%s-%s-%s-%s-%s' % (guid[0:8], guid[8:12], guid[12:16], guid[16:20], guid[20:32])
                    if guid != did['meta']['guid']:
                        result[lfn] = {'status': False, 'error': FileConsistencyMismatch('guid mismatch DDM %s vs user %s' % (guid, did['meta']['guid']))}
                    elif meta['adler32'] != did['adler32']:
                        result[lfn] = {'status': False, 'error': FileConsistencyMismatch('adler32 mismatch DDM %s vs user %s' % (meta['adler32'], did['adler32']))}
                    elif meta['bytes'] != did['bytes']:
                        result[lfn] = {'status': False, 'error': FileConsistencyMismatch('filesize mismatch DDM %s vs user %s' % (meta['bytes'], did['bytes']))}
        return result

    def registerFilesInDatasets(self, datasets):
        """
        ToDo-->KuoHao

        Add existing files to an existing dataset.(attach file to dataset)

        @param dataset: is a dictionary containing the dataset name and a list of its files.
            {'dsn': [{'guid', 'vuid', 'lfn', 'size', 'checksum', 'scope'}]}
            where checksum is 'md5:<md5_32_character_string>'
        """
        # Scope information need to be recorded in file information
        # ckeck dataset status (not closed)
        for dsn in datasets:
            scope, dsn = extract_scope(dsn)
            info = self.client.get_did(scope, dsn)
            if not (info['open']):
                raise UnsupportedOperation

        for dataset in datasets:
            scope, dsn = extract_scope(dataset)
            # get file information
            lfns = []
            guids = []
            sizes = []
            checksums = []
            scopes = []
            for file in datasets[dataset]:
                lfns.append(file['lfn'])
                guids.append(file['guid'])
                sizes.append(file['size'])
                checksums.append(file['checksum'])
                scopes.append(file['scope'])

            # merge lfn, guid, size, checksum into rucio file format
            files = []
            for lfn, guid, size, checksum, scope in zip(lfns, guids, sizes, checksums, scopes):
                file = {'scope': scope, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}}
                if checksum.startswith('md5:'):
                    file['md5'] = checksum[4:]
                elif checksum.startswith('ad:'):
                    file['adler32'] = checksum[3:]
                files.append(file)
            # attach files to dataset
            for scope in scopes:
                self.client.attach_dids(scope=scope, name=dataset, dids=files)
        return True

    def registerNewDataset(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], cooldown=None, provenance=None, group=None, hidden=False, scope=None, rse=None):
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
        @param rse: is the location of the files if lfns is not empty.


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
            for lfn, guid, size, checksum in zip(lfns, guids, sizes, checksums):
                if lfn.find(':') > -1:
                    s, lfn = lfn.split(':')[0], lfn.split(':')[1]
                else:
                    s = scope
                file = {'scope': s, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}}
                if checksum.startswith('md5:'):
                    file['md5'] = checksum[4:]
                elif checksum.startswith('ad:'):
                    file['adler32'] = checksum[3:]
                files.append(file)
            try:
                self.client.add_files_to_dataset(scope=scope, name=dsn, files=files, rse=rse)
            except FileAlreadyExists:
                for f in files:
                    try:
                        self.client.add_files_to_dataset(scope=scope, name=dsn, files=[f], rse=rse)
                    except FileAlreadyExists:
                        pass
        vuid = hashlib.md5(scope+':'+dsn).hexdigest()
        vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
        duid = vuid
        self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=1, rse_expression=rse, weight=None, lifetime=7*86400, grouping='DATASET', account=None, locked=False)
        return {'duid': duid, 'version': 1, 'vuid': vuid}

    def registerNewDataset2(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], cooldown=None,  provenance=None, group=None, hidden=False, ignore=False, scope=None, rse=None):
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
        @param rse: is the location of the files if lfns is not empty.


        B{Exceptions:}
            - DQDaoException is raised,
                in case there is a python or database error in the central catalogs.
            - DQDatasetExistsException is raised,
                in case there is a dataset with the given name.

        @return: Dictionary containing the dataset duid, vuid and version information.::
            {'duid': '...', 'vuid': '...', 'version': ...}
        """
        self.client.add_dataset(scope=scope, name=dsn)
        vuid = hashlib.md5(scope+':'+dsn).hexdigest()
        vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
        duid = vuid
        statuses = {}
        if lfns:
            files = []
            for lfn, guid, size, checksum in zip(lfns, guids, sizes, checksums):
                statuses[lfn] = {'status': True, 'duid': duid}
                if lfn.find(':') > -1:
                    s, lfn = lfn.split(':')[0], lfn.split(':')[1]
                else:
                    s = scope
                file = {'scope': s, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}}
                if checksum.startswith('md5:'):
                    file['md5'] = checksum[4:]
                elif checksum.startswith('ad:'):
                    file['adler32'] = checksum[3:]
                files.append(file)
            try:
                self.client.add_files_to_dataset(scope=scope, name=dsn, files=files, rse=rse)
            except FileAlreadyExists:
                for f in files:
                    try:
                        self.client.add_files_to_dataset(scope=scope, name=dsn, files=[f], rse=rse)
                    except FileAlreadyExists:
                        statuses[f['name']] = {'status': False, 'error': FileAlreadyExists, 'duid': duid}
        self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=1, rse_expression=rse, weight=None, lifetime=7*86400, grouping='DATASET', account=None, locked=False)
        return {'duid': duid, 'version': 1, 'vuid': vuid}, statuses

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
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - UnsupportedOperation otherwise.
        """
        # If DID not in Rucio, raise execption
        self.client.get_metadata(scope=scope, name=dsn)
        raise UnsupportedOperation('New version of a dataset cannot be created in Rucio')

    def registerNewVersion2(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], ignore=False, scope=None):
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
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - UnsupportedOperation otherwise.
        """
        # If DID not in Rucio, raise execption
        self.client.get_metadata(scope=scope, name=dsn)
        raise UnsupportedOperation('New version of a dataset cannot be created in Rucio')

    def resetSubscription(self, dsn, location, version=0, scope=None):
        """
        Reset the dataset subscription registered at the given dq2.location. In Rucio does nothing.

        @since: 0.3.0

        @param dsn: is the dataset name.
        @param location: is the location where the dataset is subscribed.
        @param version: is the dataset version number.
        @param scope: is the dataset scope.

        """
        self.client.get_metadata(scope=scope, name=dsn)

    def resetSubscriptionsInSite(self, site):
        """
        Resets the subscriptions registered in the given site. In Rucio does nothing.

        @since: 0.3.0

        @param site: is the dataset subscription dq2.location.

        B{Exceptions:}
            - DQDaoException is raised,
                in case there is a python or database error in the central catalogs.
            - DQUnknownSubscriptionException is raised,
                in case there are no subscriptions at the given site.
        """
        return 0

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

    def setMetaDataAttribute(self, dsn, attrname, attrvalue, scope=None):
        """
        ToDo Ookey

        Set the value of the given attribute to the given
        value for the given dataset. Operates on the current version.

        @since: 0.2.0

        @param dsn: is the dataset name.
        @param attrname: is the metadata dataset attribute name.
        @param attrvalue: is the metadata dataset attribute value.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DQDaoException is raised,
                in case there is a python or database error in the central catalogs.
            - DQInvalidRequest is raised,
                in case the given parameters aren't valid.
            - DQSecurityException is raised,
                in case the user has no permissions to set metadata attributes on the dataset.
            - DQInvalidRequestException is raised,
                in case of an invalid attribute name.
            - DQUnknownDatasetException is raised,
                in case there is no dataset with the given name.

        """
        metadata_mapping = {'owner': 'account', 'lifetime': 'expired_at', 'hidden': 'hidden'}
        if attrname in metadata_mapping:
            self.client.set_metadata(scope=scope, name=dsn, key=attrname, value=attrvalue)
        metadata_static = ['duid', 'state', 'creationdate', 'latestversion', 'lastoperationdn', 'lastoperationip', 'closeddate', 'frozendate', 'deleteddate', 'type',
                           'freezingdate', 'group', 'provenance', 'nbfiles', 'length', 'vuid', 'version', 'versioncreationdate', 'latestvuid', 'origin', 'physicsgroup', 'temperature', '#replicas', 'tier0state', 'tier0type']
        if attrname in metadata_static:
            raise InvalidMetadata('%s is a static metadata and cannot be updated' % (attrname))
        raise InvalidMetadata('%s is not a valid DQ2 metadata' % (attrname))

    def setReplicaMetaDataAttribute(self, dsn, location, attrname, attrvalue, scope=None):
        """
        Set the value of the given attribute to the given
        value for the given dataset replica. Operates on the current version.

        @param dsn: is the dataset name.
        @param location: is the location name.
        @param attrname: is the metadata dataset attribute name.
        @param attrvalue: is the metadata dataset attribute value.
        @param scope: is dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - InvalidMetadata is is raised in case of non valid attrname
            - InputValidationError is case of non valid attrvalue
            - UnsupportedOperation if the replica doesn't exist.
        """
        attributes = ['group', 'owner', 'archived', 'pin_lifetime', 'lifetime']
        if attrname not in attributes:
            raise InvalidMetadata('%s is not a valid DQ2 replica metadata' % (attrname))
        self.client.get_metadata(scope=scope, name=dsn)
        is_at_site = False
        account = self.client.account
        if attrname == 'owner':
            account = attrvalue
        elif attrname == 'group':
            account = attrvalue
        lifetime = None
        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            if rule['rse_expression'] == location:
                is_at_site = True
                if attrname == 'owner' or attrname == 'group':
                    if rule['account'] == attrvalue:
                        return 0
                elif attrname == 'archived':
                    # Does nothing
                    pass
                elif attrname == 'lifetime':
                    lifetime = validate_time_formats([attrvalue, ])[0]
                    if lifetime == timedelta(days=0, seconds=0, microseconds=0):
                        errMsg = 'lifetime must be greater than O!' % locals()
                        raise InputValidationError(errMsg)

                    self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=rule['copies'], rse_expression=location, weight=rule['weight'], lifetime=lifetime, grouping=rule['grouping'], account=account, locked=False)
                    self.client.delete_replication_rule(rule['id'])
                elif attrname == 'pin_lifetime':
                    if attrvalue is None or attrvalue is '':
                        self.client.update_lock_state(rule['id'], lock_state=False)
                    else:
                        pin_lifetime = validate_time_formats([attrvalue, ])[0]
                        if pin_lifetime == timedelta(days=0, seconds=0, microseconds=0):
                            errMsg = 'pin_lifetime must be greater than O!' % locals()
                            raise InputValidationError(errMsg)
                        self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=rule['copies'], rse_expression=location, weight=rule['weight'], lifetime=pin_lifetime, grouping=rule['grouping'], account=account, locked=True)
        if not is_at_site:
            raise UnsupportedOperation('Replicas for %s:%s at %s does not exist' % (scope, dsn, location))
        self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=1, rse_expression=location, weight=None, lifetime=lifetime, grouping='DATASET', account=account, locked=False)
        return 0

    def verifyFilesInDataset(self, dsn, guids, version=None, scope=None):
        """
        Verifies if the given files' global unique identifiers (GUIDS) are registered on the dataset.

        (since 0.4.0)

        @param dsn: is the dataset name.
        @param guids: is a list of file unique identifiers (GUID).
            Note: the GUID is typically assigned by external tools
            (e.g. POOL) and must be passed along as is.
        @param version: is the dataset version number (0 => the latest version).
        @param scope: is the dataset scope.

        B{Exceptions}:
            - DQDaoException is raised,
                in case there is a python or database error in the central catalogs.
            - DQUnknownDatasetException is raised,
                in case there is no dataset with the given name.

        @return: Dictionary with the following format:
            {
                GUIDX: True, # exist
                (...)
                GUIDY: False # don't exist
            }
        """
        result = {}
        for guid in guids:
            result[guid] = False
        for did in self.client.list_files(scope=scope, name=dsn):
            guid = self.client.get_metadata(scope=did['scope'], name=did['name'])['guid']
            if guid in guids:
                result[guid] = True
                continue
            if guid.upper() in guids:
                result[guid.upper()] = True
                continue
            guid = '%s-%s-%s-%s-%s' % (guid[0:8], guid[8:12], guid[12:16], guid[16:20], guid[20:32])
            if guid in guids:
                result[guid] = True
                continue
            if guid.upper() in guids:
                result[guid.upper()] = True
                continue
        return result
