# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2015
# - WeiJen Chang <e4523744@gmail.com>, 2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

'''
Compatibility Wrapper for DQ2 and Rucio.
     http://svnweb.cern.ch/world/wsvn/dq2/trunk/dq2.clients/lib/dq2/clientapi/DQ2.py
'''

from __future__ import print_function

import copy
import hashlib
import re

from datetime import datetime, timedelta
from rucio.client.client import Client
from rucio.common.exception import (AccountNotFound, DataIdentifierNotFound, Duplicate, InvalidMetadata, RSENotFound, NameTypeError,
                                    InputValidationError, UnsupportedOperation, ScopeNotFound, ReplicaNotFound, RuleNotFound, FileAlreadyExists, FileConsistencyMismatch)


def validate_time_formats(time_string):
    try:
        d = re.match(r'((?P<days>\d+) days?)?'
                     r'(, )?'
                     r'((?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d+))?',
                     str(time_string))

        if not filter(lambda r: r[1], list(d.groupdict().items())):
            err_msg = 'Parameter value [%s] is not a valid time delta !' % (time_string)
            raise InputValidationError(err_msg)

        delta = timedelta(**dict([(key, (value and int(value) or 0)) for key, value in list(d.groupdict(0).items())]))
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
            client = Client(user_agent='dq2-clients')
            if scope not in client.list_scopes():
                raise ScopeNotFound('%s is not a valid scope' % scope)
        return scope, dsn


class DQ2Client:
    def __init__(self):
        self.client = Client(user_agent='dq2-clients')

    def finger(self, userId=None):
        """
        User information lookup program.
        :param userId: The userId (Distinguished Name or account/nickname).
        :return: A dictionary with the name nickname, email, dn.

        B{Exceptions:}
            - AccountNotFound is raised in case the account doesn't exist.
        """
        result = {}
        account = userId
        nickname = userId
        if not userId:
            ret = self.client.whoami()
            nickname = ret['account']
            account = nickname
        result['email'] = None
        result['dn'] = None
        if len(account) < 30:
            result['nickname'] = nickname
            for id in self.client.list_identities(account):
                if id['type'] == 'GSS':
                    result['email'] = id['identity']
                elif id['type'] == 'X509':
                    if not result['dn']:
                        result['dn'] = []
                    result['dn'].append(id['identity'])
        else:
            result['dn'] = userId
            nicknames, emails = [], []
            for ac in self.client.list_accounts('USER', account):
                nicknames.append(ac['account'])
                emails.append(ac['email'])
            if nicknames == []:
                raise AccountNotFound
            elif len(nicknames) > 1:
                raise Exception('This DN is mapped to more than one account')
            result['nickname'] = nicknames[0]
            result['email'] = emails[0]
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

    def deleteDatasetReplicas(self, dsn, locations, version=0, force=False, deep=False, logical=False, ignore_lifetime=False, all=False, grace_period=None, ignore_pin=False, scope=None):
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
        result = {}
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['rse_expression'] in locations:  # or [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]:
                self.client.delete_replication_rule(rule['id'])
                result[rule['rse_expression']] = {'status': True}
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
        return

    def deleteDatasetSubscriptions(self, dsn, scope=None):
        """
        Marks all dataset/dataset version subscriptions of the given dataset. In Rucio does nothing.

        @param dsn: is the dataset name.
        @param scope: is the dataset scope.

        B{Exceptions}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
        """
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
        """
        if name.endswith('/'):
            name = name[:-1]
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
        for file in self.client.list_files(scope=scope, name=dsn):
            guid = file['guid']
            guid = '%s-%s-%s-%s-%s' % (guid[0:8], guid[8:12], guid[12:16], guid[16:20], guid[20:32])
            if guid in guids or guid.upper() in guids:
                did = {'scope': file['scope'], 'name': file['name']}
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
            # self.client.set_metadata(scope=scope, name=dsn, key='expired_at', value=str(datetime.now()))
            self.client.set_metadata(scope=scope, name=dsn, key='lifetime', value=0.0001)
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
        metadata_mapping = {'owner': 'account', 'creationdate': 'created_at', 'deleteddate': 'deleted_at', 'lifetime': 'expired_at', 'hidden': 'hidden', 'versioncreationdate': 'created_at',
                            'events': 'events', 'lumiblocknr': 'lumiblocknr', 'provenance': 'provenance', 'physicsgroup': 'phys_group', 'transient': 'transient'}
        metadata_static = {'latestversion': 1, 'lastoperationdn': None, 'lastoperationip': None, 'closeddate': None, 'frozendate': None, 'freezingdate': None, 'group': None,
                           'version': 1, 'origin': None, 'temperature': None, 'tier0state': None, 'tier0type': None}
        for key in attributes:
            if key in metadata_mapping:
                result[key] = metadata[metadata_mapping[key]]
            elif key in metadata_static:
                result[key] = metadata_static[key]
            elif key in ['duid', 'vuid', 'latestvuid']:
                result[key] = hashlib.md5(scope + ':' + dsn).hexdigest()
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
        vuid = hashlib.md5(scope + ':' + dsn).hexdigest()
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
        @archived: should be 'primary' or 'custodial' for replicas without lifetime and 'secondary' for replicas with lifetime.
        @version: always be 0
        @transferState: If one the files is replicating, transferState=1, otherwise 0
        @chekState: always be 6
        @immutable: should be 0 for open datasets and 1 for closed datasets.

        @get_dataset_locks will help when option old=True is used

        """
        result = {}
        dict_rses = {}
        files = []
        locked = False
        dq2attrs = {'pdn': '', 'archived': 'secondary', 'version': 1, 'checkstate': 6, 'transferState': 1, 'found': 0, 'total': 0, 'immutable': 0}
        metadata = self.client.get_metadata(scope, name=dsn)
        # @immutable
        if not metadata['is_open']:
            dq2attrs['immutable'] = 1
        # @archived
        if metadata['expired_at'] is not None:
            dq2attrs['archived'] = 'secondary'
            if abs(metadata['expired_at'] - datetime.now()) < timedelta(days=1):
                dq2attrs['archived'] = 'tobedeleted'

        # @transferState
        replicating_rses = []
        if not old:
            for rule in self.client.list_did_rules(scope, dsn):
                locked = False
                if rule['locked']:
                    locked = True
                rses = []
                if rule['rse_expression'].find('\\') > -1 or rule['rse_expression'].find('|') > -1 or rule['rse_expression'].find('&') > -1 or rule['rse_expression'].find('=') > -1:
                    for item in self.client.list_rses(rule['rse_expression']):
                        rses.append(item['rse'])
                else:
                    rses.append(rule['rse_expression'])

                for rse in rses:
                    if rule['state'] == 'REPLICATING':
                        replicating_rses.append(rse)
                    if rse not in dict_rses:
                        dict_rses[rse] = 'secondary'
                        if rule['expires_at'] and abs(rule['expires_at'] - datetime.now()) < timedelta(days=1):
                            dict_rses[rse] = 'tobedeleted'
                    if rule['expires_at'] is None:
                        if locked:
                            dict_rses[rse] = 'custodial'
                        else:
                            dict_rses[rse] = 'primary'

        else:
            pass

        if old:
            replicas = {0: [], 1: []}
            incomplete = []
            for lock in self.client.get_dataset_locks(scope, dsn):
                if lock['state'] == 'OK':
                    if lock['rse'] not in replicas[1]:
                        replicas[1].append(lock['rse'])
                elif lock['rse'] not in incomplete:
                    incomplete.append(lock['rse'])
            for lock in incomplete:
                if lock not in replicas[1]:
                    replicas[0].append(lock)
            vuid = hashlib.md5(scope + ':' + dsn).hexdigest()
            vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
            return {vuid: replicas}
        elif False:
            # The old way
            for f in self.client.list_replicas(dids=[{'scope': scope, 'name': dsn}], schemes=['srm']):
                rses = list(f['rses'].keys())
                if not f['name'] in files:
                    files.append(f['name'])
                    for rse in rses:
                        if rse not in result:
                            result[rse] = [copy.deepcopy(dq2attrs)]
                            result[rse][-1]['found'] = 0
                            try:
                                result[rse][-1]['archived'] = dict_rses[rse]
                            except KeyError:
                                result[rse][-1]['archived'] = 'secondary'
                        result[rse][-1]['found'] += 1
            for rse in result:
                result[rse][-1]['total'] = len(files)
                if rse in replicating_rses:
                    result[rse][-1]['transferState'] = 0
        else:
            for rep in self.client.list_dataset_replicas(scope, dsn):
                result[rep['rse']] = [copy.deepcopy(dq2attrs)]
                result[rep['rse']][-1]['found'] = rep['available_length']
                result[rep['rse']][-1]['total'] = rep['length']
                try:
                    result[rep['rse']][-1]['archived'] = dict_rses[rse]
                except KeyError:
                    result[rep['rse']][-1]['archived'] = 'secondary'
                if rep['state'] != 'AVAILABLE':
                    result[rep['rse']][-1]['transferState'] = 0
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
        if cn.endswith('/'):
            cn = cn[:-1]
        result = {}
        replicas = {0: [], 1: []}
        rse = self.client.get_metadata(scope=scope, name=cn)
        if rse['did_type'] != 'CONTAINER':
            raise NameTypeError("Container name must end with a '/'.")

        for i in self.client.list_content(scope, cn):
            if i['type'] == 'DATASET' and i['name'] not in result:
                vuid = hashlib.md5(scope + ':' + i['name']).hexdigest()
                vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
                result['%s:%s' % (i['scope'], i['name'])] = {vuid: replicas}

        for dsn in list(result.keys()):
            dscope, name = dsn.split(':')
            replicas = self.listDatasetReplicas(scope=dscope, dsn=name, old=True)
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
            collection = 'dataset'
            filters = {'name': dsn}
            result = {}
            mscope, dataset = extract_scope(dsn)
            if not scope:
                scope = mscope
            if dataset.endswith('/'):
                dataset = dataset[:-1]
                collection = 'container'
            filters = {'name': dataset}
            for name in self.client.list_dids(scope, filters, type=collection):
                vuid = hashlib.md5(scope + ':' + name).hexdigest()
                vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
                duid = vuid
                if name not in result:
                    result[str('%s:%s' % (scope, name))] = {'duid': duid, 'vuids': [vuid]}
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
            scope, dsn = extract_scope(metaDataAttributes['name'])
            type = 'collection'
            metadata = ['state', 'type', 'name']
            for key in metaDataAttributes:
                if key not in metadata:
                    raise InvalidMetadata
                if key == 'name':
                    filters['name'] = dsn
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
            if long:
                for name in self.client.list_dids(scope, filters, type):
                    meta = {'totalSize': 0, 'totalFiles': 0}
                    # Can take very long. Bulk method is needed !!!
                    for did in self.client.list_files(scope=scope, name=name):
                        meta['totalSize'] += did['bytes']
                        meta['totalFiles'] += 1
                    result['%s:%s' % (scope, name)] = meta
            else:
                if type == 'collection':
                    for name in self.client.list_dids(scope, filters, 'dataset'):
                        result['%s:%s' % (scope, name)] = {}
                    if filters['name'].endswith('/'):
                        filters['name'] = filters['name'].rstrip('/')
                    for name in self.client.list_dids(scope, filters, 'container'):
                        result['%s:%s/' % (scope, name)] = {}
                else:
                    for name in self.client.list_dids(scope, filters, type):
                        if type == 'container':
                            result['%s:%s/' % (scope, name)] = {}
                        elif type == 'datasets':
                            result['%s:%s' % (scope, name)] = {}
            return result
        else:
            return result
        #    raise ScopeNotFound('Please specify a valid scope')

    def listDatasetsByCreationDate(self):
        """
        ToDo
        """
        raise NotImplementedError

    def listDatasetsByGUIDs(self, guids):
        """
        Returns a dictionary mapping guid to dataset names.
        @since: 0.3.1

        @param guids: a list of guids

        B{Exceptions:}
            - RucioException is raised in case of exception.

        @return: Returns the guid->dataset names mapping.::
            {'guid': [dsnX, dsnY]}
            or
            {}
        """
        result = {}
        for guid in guids:
            datasets = [str('%s:%s' % (i['scope'], i['name'])) for i in self.client.get_dataset_by_guid(guid)]
            result[guid] = datasets
        return result

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
            pattern = str.replace(name, '*', '.*')
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
        if cn.endswith('/'):
            cn = cn[:-1]
        ret = []
        try:
            if self.client.get_metadata(scope, cn)['did_type'] == 'CONTAINER':
                for i in self.client.list_content(scope, cn):
                    if i['type'] == 'DATASET':
                        ret.append('%s:%s' % (i['scope'], i['name']))
                return ret
            else:
                raise NameTypeError("Container name must end with a '/'.")
        except DataIdentifierNotFound:
            if cn.endswith('/'):
                cn = cn.rstrip('/')
                if self.client.get_metadata(scope, cn)['did_type'] == 'CONTAINER':
                    for i in self.client.list_content(scope, cn):
                        if i['type'] == 'DATASET':
                            ret.append('%s:%s' % (i['scope'], i['name']))
                    return ret
                else:
                    raise NameTypeError("Container name must end with a '/'.")
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
        for x in self.client.list_files(scope, dsn):
            guid = str('%s-%s-%s-%s-%s' % (x['guid'][0:8], x['guid'][8:12], x['guid'][12:16], x['guid'][16:20], x['guid'][20:32]))
            lfn_to_guid[(scope, x['name'])] = guid
            total += 1
        for replica in self.client.list_replicas([{'scope': scope, 'name': dsn}], schemes=['srm']):
            if location in replica['rses']:
                length += replica['bytes']
                found += 1
                guids.append(lfn_to_guid[(replica['scope'], replica['name'])])
        return [{'content': guids, 'transferState': 1, 'length': length, 'checkstate': 6, 'found': found, 'total': total, 'immutable': immutable}]

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
            in_rse = list(f['rses'].keys())
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

    def listFilesInDataset(self, dsn, version=None, scope=None, long=False):
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
        for x in self.client.list_files(scope, dsn, long=long):
            dq2attrs = {}
            dq2attrs['checksum'] = "ad:" + str(x['adler32'])
            dq2attrs['filesize'] = x['bytes']
            dq2attrs['scope'] = str(x['scope'])
            dq2attrs['lfn'] = str(x['name'])
            dq2attrs['events'] = str(x['events'])
            if long:
                dq2attrs['lumiblocknr'] = str(x['lumiblocknr'])
            guid = str('%s-%s-%s-%s-%s' % (x['guid'][0:8], x['guid'][8:12], x['guid'][12:16], x['guid'][16:20], x['guid'][20:32]))
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
        atime = metadata['accessed_at']
        if metadata['is_open']:
            immutable = 0
        exists = False
        locked = False
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['rse_expression'] == location:  # or location in [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]:
                exists = True
                if rule['created_at'] < creationdate:
                    creationdate = rule['created_at']
                    transferdate = rule['updated_at']
                    owner = rule['account']
                    if rule['locked']:
                        locked = True
                    if rule['expires_at'] is None:
                        if locked:
                            archived = 'custodial'
                        else:
                            archived = 'primary'
                    else:
                        expirationdate = rule['expires_at']
        if not exists:
            raise ReplicaNotFound
        result = {'transferdate': str(transferdate), 'owner': owner, 'atime': str(atime), 'archived': archived, 'group': ' None', 'transferState': transferState,
                  'checkdate': str(checkdate), 'version': 1, 'checkState': 6, 'pin_expirationdate': 'None', 'creationdate': str(creationdate), 'immutable': immutable, 'expirationdate': expirationdate}
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
        result = ()
        creationdate = datetime.now()
        for rule in self.client.list_did_rules(scope, dsn):
            if rule['state'] != 'OK' and (location == rule['rse_expression']):  # or location in [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]):
                print(rule)
                if rule['created_at'] < creationdate:
                    id = rule['id']
                    id = '%s-%s-%s-%s-%s' % (id[0:8], id[8:12], id[12:16], id[16:20], id[20:32])
                    owner = rule['account']
                    destination = None
                    creationdate = rule['created_at']
                    modifieddate = rule['updated_at']
                    callbacks = {}
                    if rule['expires_at']:
                        if rule['locked']:
                            archived = 'custodial'
                        else:
                            archived = 'primary'
                    else:
                        archived = 'secondary'
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
            elif rule['state'] == 'OK' and (location == rule['rse_expression']):  # or location in [i['rse'] for i in self.client.list_rses(rule['rse_expression'])]):
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
        result = list_rses
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
                    result.append({'files': None, 'key': 'srm', 'datasets': None, 'tera': d['total'] / 1024. / 1024. / 1024. / 1024, 'giga': d['total'] / 1024. / 1024. / 1024,
                                   'mega': d['total'] / 1024. / 1024., 'bytes': d['total'], 'timestamp': str(d['updated_at']), 'value': 'total', 'location': rse})
                except StopIteration:
                    print('Error')
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
        if name.endswith('/'):
            name = name[:-1]
        self.client.add_container(scope=scope, name=name)
        if datasets:
            self.client.add_datasets_to_container(scope=scope, name=name, dsns=datasets)

    def registerDatasetLocation(self, dsn, location, version=0, complete=0, group=None, archived=None, acl_alias=None, lifetime=None, pin_lifetime=None, activity=None, scope=None):
        """
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
        @param activity: is the activity.
        @param scope: is the dataset scope.

        B{Exceptions:}
            - DataIdentifierNotFound is raised in case the dataset name doesn't exist.
            - UnsupportedOperation is raised in case the location does not exist.
        """
        if lifetime:
            lifetime = validate_time_formats(lifetime)
            if lifetime == timedelta(days=0, seconds=0, microseconds=0):
                errMsg = 'lifetime must be greater than O!' % locals()
                raise InputValidationError(errMsg)
            lifetime = lifetime.days * 86400 + lifetime.seconds
        if pin_lifetime:
            pin_lifetime = validate_time_formats(pin_lifetime)
            if pin_lifetime == timedelta(days=0, seconds=0, microseconds=0):
                errMsg = 'pin_lifetime must be greater than O!' % locals()
                raise InputValidationError(errMsg)
            pin_lifetime = pin_lifetime.days * 86400 + pin_lifetime.seconds

        dids = []
        did = {'scope': scope, 'name': dsn}
        dids.append(did)
        # Check if a replication rule for scope:name, location, account already exists
        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            if (rule['rse_expression'] == location) and (rule['account'] == self.client.account):
                return True
        try:
            if location.find('SCRATCHDISK') > -1:
                if lifetime:
                    lifetime = min(lifetime, 14 * 86400)
                else:
                    lifetime = 14 * 86400
            ignore_availability = (self.client.account == 'panda')
            self.client.add_replication_rule(dids=dids, copies=1, rse_expression=location, weight=None, lifetime=lifetime,
                                             grouping='DATASET', account=self.client.account, locked=False, notify='N',
                                             ignore_availability=ignore_availability, activity=activity)
        except Duplicate:
            return True
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
        @param archived: to define rule type.
        @param callbacks: is a dictionary which specifies, per subscription callback.
        @sources: not used.
        @destination: not used.
        @query_more_sources: not used.
        @sshare: not used yet.
        @group: not used.
        @owner: not used yet.
        @activity: is the activity.
        @acl_alias: not used.
        @replica_lifetime: is the replica lifetime.
        @check_destination: not used.
        @parentId: not used.
        @pin_lifetime: not used.
        @param scope: is the dataset scope.
        """
        if replica_lifetime:
            replica_lifetime = validate_time_formats(replica_lifetime)
            if replica_lifetime == timedelta(days=0, seconds=0, microseconds=0):
                errMsg = 'replica_lifetime must be greater than O!' % locals()
                raise InputValidationError(errMsg)
            replica_lifetime = replica_lifetime.days * 86400 + replica_lifetime.seconds

        if pin_lifetime:
            pin_lifetime = validate_time_formats(pin_lifetime)
            if pin_lifetime == timedelta(days=0, seconds=0, microseconds=0):
                errMsg = 'pin_lifetime must be greater than O!' % locals()
                raise InputValidationError(errMsg)
            pin_lifetime = pin_lifetime.days * 86400 + pin_lifetime.seconds
        if not owner:
            owner = self.client.account
        else:
            accounts_l = [i for i in self.client.list_accounts('user', owner)]
            if accounts_l != []:
                owner = accounts_l[0]['account']
        dids = [{'scope': scope, 'name': dsn}]

        notify = 'N'
        if callbacks != {}:
            notify = 'C'

        locked = False
        if acl_alias == 'secondary':
            if not replica_lifetime:
                replica_lifetime = 14 * 86400
        elif acl_alias == 'custodial':
            locked = True

        list_sources = list(sources.keys())
        if len(list_sources) == 1 and list_sources[0] == location:
            # This is a staging request
            attr = self.client.list_rse_attributes(location)
            if 'istape' in attr and attr['istape']:
                ignore_availability = (self.client.account == 'panda')
                self.client.add_replication_rule(dids, copies=1, rse_expression=attr['staging_buffer'], weight=None, lifetime=replica_lifetime, grouping='DATASET', account=owner, locked=locked, activity=activity,
                                                 notify=notify, ignore_availability=ignore_availability)
        else:
            for rule in self.client.list_did_rules(scope=scope, name=dsn):
                if (rule['rse_expression'] == location) and (rule['account'] == owner):
                    raise Duplicate('A rule for %s:%s at %s already exists' % (scope, dsn, location))
            if location.find('SCRATCHDISK') > -1:
                if replica_lifetime:
                    replica_lifetime = min(replica_lifetime, 14 * 86400)
                else:
                    replica_lifetime = 14 * 86400
            ignore_availability = (self.client.account == 'panda')
            self.client.add_replication_rule(dids, copies=1, rse_expression=location, weight=None, lifetime=replica_lifetime, grouping='DATASET', account=owner, locked=locked, activity=activity, notify=notify, ignore_availability=ignore_availability)

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
        if name.endswith('/'):
            name = name[:-1]
        dsns = []
        # create rucio parameter
        for ds in datasets:
            ds_scope, ds_name = extract_scope(ds)
            if ds_scope:
                dsn = {'scope': ds_scope, 'name': ds_name}
            else:
                dsn = {'scope': scope, 'name': ds}
            dsns.append(dsn)
        self.client.add_datasets_to_container(scope=scope, name=name, dsns=dsns)

    def registerFilesInDataset(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], ignore=False, scope=None, rse=None, pfns=[], events=[], lumiblocknrs=[]):
        """
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
        @param pfns: is a list of PFN.
        @param events: is a list of number of events.
        @param lumiblocknrs: is a list of lumiblocks.

        """
        result = {}
        # check dataset status (not closed)
        info = self.client.get_did(scope, dsn)
        if not (info['open']):
            raise UnsupportedOperation

        # merge lfn, guid, size, checksum into rucio file format
        files = []
        index = 0
        if (events != [] and len(events) != len(lfns)):
            raise Exception('events must be provided for every files')
        if (lumiblocknrs != [] and len(lumiblocknrs) != len(lfns)):
            raise Exception('lumiblocknrs must be provided for every files')
        for lfn, guid, size, checksum in zip(lfns, guids, sizes, checksums):
            if lfn.find(':') > -1:
                s, lfn = lfn.split(':')[0], lfn.split(':')[1]
            else:
                s = scope
            try:
                pfn = pfns[index]
                file = {'scope': s, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}, 'pfn': pfn}
            except IndexError:
                file = {'scope': s, 'name': lfn, 'bytes': size, 'meta': {'guid': guid}}
            if events != []:
                file['meta']['events'] = events[index]
            if lumiblocknrs != []:
                file['meta']['lumiblocknr'] = lumiblocknrs[index]
            if checksum.startswith('md5:'):
                file['md5'] = checksum[4:]
            elif checksum.startswith('ad:'):
                file['adler32'] = checksum[3:]
            files.append(file)
            index += 1
        # add new file to dataset(rse need assign), in rucio rse is pre-assign(by user or group
        try:
            self.client.add_files_to_dataset(scope=scope, name=dsn, files=files, rse=rse)
            for lfn in lfns:
                result[lfn] = {'status': True}
        except (FileAlreadyExists, Duplicate, UnsupportedOperation):
            for did in files:
                lfn = did['name']
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
                    else:
                        result[lfn] = {'status': False, 'error': FileAlreadyExists('File %s:%s already exists' % (did['scope'], did['name']))}
                except UnsupportedOperation as e:
                    result[lfn] = {'status': False, 'error': e}
        return result

    def registerFilesInDatasets(self, datasets, rse=None):
        """
        Add existing files to an existing dataset.(attach file to dataset)

        @param dataset: is a dictionary containing the dataset name and a list of its files.
            {'dsn': [{'guid', 'vuid', 'lfn', 'size', 'checksum', 'scope'}]}
            where checksum is 'md5:<md5_32_character_string>'
        """
        # Scope information need to be recorded in file information
        # ckeck dataset status (not closed)
        for dataset in datasets:
            scope, dsn = extract_scope(dataset)
            info = self.client.get_did(scope, dsn)
            if not (info['open']):
                raise UnsupportedOperation

        result = {}
        for dataset in datasets:
            scope, dsn = extract_scope(dataset)
            vuid = hashlib.md5(scope + ':' + dsn).hexdigest()
            vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
            result[vuid] = None
            # get file information
            lfns, guids, sizes, checksums, pfns, events, lumiblocknrs = [], [], [], [], [], [], []
            for file in datasets[dataset]:
                guids.append(file['guid'])
                sizes.append(file['size'])
                checksums.append(file['checksum'])
                if 'surl' in file:
                    pfns.append(file['surl'])
                if 'scope' not in file:
                    if file['lfn'].find(':') > -1:
                        lfns.append(file['lfn'])
                    else:
                        lfns.append('%s:%s' % (scope, file['lfn']))
                else:
                    lfns.append('%s:%s' % (file['scope'], file['lfn']))
                if 'events' in file:
                    events.append(file['events'])
                if 'lumiblocknr' in file:
                    lumiblocknrs.append(file['lumiblocknr'])
            result[vuid] = self.registerFilesInDataset(dsn, lfns=lfns, guids=guids,
                                                       sizes=sizes, checksums=checksums,
                                                       ignore=False, scope=scope, rse=rse,
                                                       pfns=pfns, events=events,
                                                       lumiblocknrs=lumiblocknrs)
        errorlist = []
        for vuid in result:
            for lfn in result[vuid]:
                if 'error' in result[vuid][lfn]:
                    if type(result[vuid][lfn]['error']) not in errorlist:
                        errorlist.append(type(result[vuid][lfn]['error']))
        if FileConsistencyMismatch in errorlist:
            raise FileConsistencyMismatch
        elif UnsupportedOperation in errorlist:
            raise UnsupportedOperation
        elif FileAlreadyExists in errorlist:
            raise FileAlreadyExists
        elif errorlist != []:
            raise Exception

    def registerNewDataset(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], cooldown=None, provenance=None, group=None, hidden=False, scope=None, rse=None, pfns=[], events=[], lumiblocknrs=[], activity=None):
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
        @param pfns: is a list of PFN.
        @param events: is a list of number of events.
        @param lumiblocknrs: is a list of lumiblocks.
        @param activity: is the activity


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
            index = 0
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
                if pfns != []:
                    file['pfn'] = pfns[index]
                if events != []:
                    file['meta']['events'] = events[index]
                if lumiblocknrs != []:
                    file['meta']['lumiblocknr'] = lumiblocknrs[index]
                index += 1
                files.append(file)
            try:
                self.client.add_files_to_dataset(scope=scope, name=dsn, files=files, rse=rse)
            except FileAlreadyExists:
                for f in files:
                    try:
                        self.client.add_files_to_dataset(scope=scope, name=dsn, files=[f], rse=rse)
                    except FileAlreadyExists:
                        pass
        vuid = hashlib.md5(scope + ':' + dsn).hexdigest()
        vuid = '%s-%s-%s-%s-%s' % (vuid[0:8], vuid[8:12], vuid[12:16], vuid[16:20], vuid[20:32])
        duid = vuid
        if rse:
            try:
                lifetime = None
                if rse.find('SCRATCHDISK') > -1:
                    if lifetime:
                        lifetime = min(lifetime, 14 * 86400)
                    else:
                        lifetime = 14 * 86400
                ignore_availability = (self.client.account == 'panda')
                self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=1, rse_expression=rse, weight=None, lifetime=lifetime,
                                                 grouping='DATASET', account=self.client.account, locked=False,
                                                 notify='N', ignore_availability=ignore_availability, activity=activity)
            except Duplicate:
                pass
        return {'duid': duid, 'version': 1, 'vuid': vuid}

    def registerNewDataset2(self, dsn, lfns=[], guids=[], sizes=[], checksums=[], cooldown=None, provenance=None, group=None, hidden=False, ignore=False, scope=None, rse=None):
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
        vuid = hashlib.md5(scope + ':' + dsn).hexdigest()
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
        if rse:
            try:
                lifetime = None
                if rse.find('SCRATCHDISK') > -1:
                    if lifetime:
                        lifetime = min(lifetime, 14 * 86400)
                    else:
                        lifetime = 14 * 86400
                ignore_availability = (self.client.account == 'panda')
                self.client.add_replication_rule(dids=[{'scope': scope, 'name': dsn}], copies=1, rse_expression=rse, weight=None, lifetime=lifetime, grouping='DATASET', account=self.client.account, locked=False,
                                                 notify='N', ignore_availability=ignore_availability)
            except Duplicate:
                pass
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
        return

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
        metadata_mapping = {'owner': 'account', 'lifetime': 'expired_at', 'hidden': 'hidden', 'events': 'events', 'lumiblocknr': 'lumiblocknr'}
        if attrname in metadata_mapping:
            return self.client.set_metadata(scope=scope, name=dsn, key=metadata_mapping[attrname], value=attrvalue)
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
        is_at_site = False
        account = self.client.account
        if attrname == 'owner':
            account = attrvalue
        elif attrname == 'group':
            account = attrvalue
        lifetime = None
        is_updated = False
        for rule in self.client.list_did_rules(scope=scope, name=dsn):
            if rule['rse_expression'] == location:
                is_at_site = True
                if rule['account'] == account:
                    is_updated = True
                    if attrname == 'owner' or attrname == 'group':
                        if rule['account'] == attrvalue:
                            return 0
                    elif attrname == 'archived':
                        if attrvalue == 'custodial':
                            self.client.update_replication_rule(rule['id'], {'locked': True, 'lifetime': None})
                        elif attrvalue == 'secondary':
                            self.client.update_replication_rule(rule['id'], {'locked': False, 'lifetime': 14 * 86400})
                        elif attrvalue == 'primary':
                            self.client.update_replication_rule(rule['id'], {'locked': False, 'lifetime': None})
                    elif attrname == 'lifetime':
                        if attrvalue == '':
                            lifetime = None
                        else:
                            lifetime = validate_time_formats(attrvalue)
                        if lifetime == timedelta(days=0, seconds=0, microseconds=0):
                            errMsg = 'lifetime must be greater than O!' % locals()
                            raise InputValidationError(errMsg)
                        elif lifetime:
                            lifetime = lifetime.days * 86400 + lifetime.seconds
                        self.client.update_replication_rule(rule['id'], {'lifetime': lifetime})
                    elif attrname == 'pin_lifetime':
                        if attrvalue is None or attrvalue == '':
                            self.client.update_replication_rule(rule['id'], {'locked': False})
                        else:
                            pin_lifetime = validate_time_formats(attrvalue)
                            if pin_lifetime == timedelta(days=0, seconds=0, microseconds=0):
                                errMsg = 'pin_lifetime must be greater than O!' % locals()
                                raise InputValidationError(errMsg)
                            pin_lifetime = pin_lifetime.days * 86400 + pin_lifetime.seconds
                            if rule['expires_at'] and ((rule['expires_at'] - datetime.now()) < timedelta(seconds=pin_lifetime)):
                                self.client.update_replication_rule(rule['id'], {'lifetime': pin_lifetime})
        if not is_at_site:
            raise UnsupportedOperation('Replicas for %s:%s at %s does not exist' % (scope, dsn, location))
        if not is_updated:
            owner = self.client.account
            lifetime = None
            locked = False
            if attrname == 'owner' or attrname == 'group':
                owner = attrvalue
            elif attrname == 'archived':
                if attrvalue == 'custodial':
                    locked = True
                elif attrvalue == 'secondary':
                    lifetime = 14 * 86400
                elif attrvalue == 'primary':
                    lifetime = None
            elif attrname == 'lifetime':
                if attrvalue == '':
                    lifetime = None
                else:
                    lifetime = validate_time_formats(attrvalue)
                    if lifetime == timedelta(days=0, seconds=0, microseconds=0):
                        errMsg = 'lifetime must be greater than O!' % locals()
                        raise InputValidationError(errMsg)
                    elif lifetime:
                        lifetime = lifetime.days * 86400 + lifetime.seconds
            elif attrname == 'pin_lifetime':
                if attrvalue is None or attrvalue == '':
                    locked = False
                else:
                    lifetime = validate_time_formats(attrvalue)
                    if lifetime == timedelta(days=0, seconds=0, microseconds=0):
                        errMsg = 'pin_lifetime must be greater than O!' % locals()
                        raise InputValidationError(errMsg)
                    lifetime = lifetime.days * 86400 + lifetime.seconds
            dids = [{'scope': scope, 'name': dsn}, ]
            ignore_availability = (self.client.account == 'panda')
            self.client.add_replication_rule(dids=dids, copies=1, rse_expression=location, weight=None, lifetime=lifetime, grouping='DATASET', account=account, locked=locked, notify='N', ignore_availability=ignore_availability)
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
