# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2018
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2015
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class RuleClient(BaseClient):

    """RuleClient class for working with replication rules"""

    RULE_BASEURL = 'rules'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, dq2_wrapper=False, vo=None):
        super(RuleClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, dq2_wrapper, vo=vo)

    def add_replication_rule(self, dids, copies, rse_expression, weight=None, lifetime=None, grouping='DATASET', account=None,
                             locked=False, source_replica_expression=None, activity=None, notify='N', purge_replicas=False,
                             ignore_availability=False, comment=None, ask_approval=False, asynchronous=False, priority=3,
                             meta=None):
        """
        :param dids:                       The data identifier set.
        :param copies:                     The number of replicas.
        :param rse_expression:             Boolean string expression to give the list of RSEs.
        :param weight:                     If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
        :param lifetime:                   The lifetime of the replication rules (in seconds).
        :param grouping:                   ALL -  All files will be replicated to the same RSE.
                                           DATASET - All files in the same dataset will be replicated to the same RSE.
                                           NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
        :param account:                    The account owning the rule.
        :param locked:                     If the rule is locked, it cannot be deleted.
        :param source_replica_expression:  RSE Expression for RSEs to be considered for source replicas.
        :param activity:                   Transfer Activity to be passed to FTS.
        :param notify:                     Notification setting for the rule (Y, N, C).
        :param purge_replicas:             When the rule gets deleted purge the associated replicas immediately.
        :param ignore_availability:        Option to ignore the availability of RSEs.
        :param ask_approval:               Ask for approval of this replication rule.
        :param asynchronous:               Create rule asynchronously by judge-injector.
        :param priority:                   Priority of the transfers.
        :param comment:                    Comment about the rule.
        :param meta:                       Metadata, as dictionary.
        """
        path = self.RULE_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        # TODO remove the subscription_id from the client; It will only be used by the core;
        data = dumps({'dids': dids, 'copies': copies, 'rse_expression': rse_expression,
                      'weight': weight, 'lifetime': lifetime, 'grouping': grouping,
                      'account': account, 'locked': locked, 'source_replica_expression': source_replica_expression,
                      'activity': activity, 'notify': notify, 'purge_replicas': purge_replicas,
                      'ignore_availability': ignore_availability, 'comment': comment, 'ask_approval': ask_approval,
                      'asynchronous': asynchronous, 'priority': priority, 'meta': meta})
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_replication_rule(self, rule_id, purge_replicas=None):
        """
        Deletes a replication rule and all associated locks.

        :param rule_id:         The id of the rule to be deleted
        :param purge_replicas:  Immediately delete the replicas.
        :raises:                RuleNotFound, AccessDenied
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)

        data = dumps({'purge_replicas': purge_replicas})

        r = self._send_request(url, type='DEL', data=data)

        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_replication_rule(self, rule_id, estimate_ttc=False):
        """
        Get a replication rule.

        :param rule_id:  The id of the rule to be retrieved.
        :param estimate_ttc: bool, if rule_info should return ttc information
        :raises:         RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'estimate_ttc': estimate_ttc})
        r = self._send_request(url, type='GET', data=data)
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_replication_rule(self, rule_id, options):
        """
        :param rule_id:   The id of the rule to be retrieved.
        :param options:   Options dictionary.
        :raises:          RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': options})
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def reduce_replication_rule(self, rule_id, copies, exclude_expression=None):
        """
        :param rule_id:             Rule to be reduced.
        :param copies:              Number of copies of the new rule.
        :param exclude_expression:  RSE Expression of RSEs to exclude.
        :raises:                    RuleReplaceFailed, RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id + '/reduce'
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'copies': copies, 'exclude_expression': exclude_expression})
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.ok:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def move_replication_rule(self, rule_id, rse_expression):
        """
        Move a replication rule to another RSE and, once done, delete the original one.

        :param rule_id:             Rule to be moved.
        :param rse_expression:      RSE expression of the new rule.
        :raises:                    RuleNotFound, RuleReplaceFailed
        """

        path = self.RULE_BASEURL + '/' + rule_id + '/move'
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'rule_id': rule_id, 'rse_expression': rse_expression})
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def approve_replication_rule(self, rule_id):
        """
        :param rule_id:             Rule to be approved.
        :raises:                    RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': {'approve': True}})
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def deny_replication_rule(self, rule_id):
        """
        :param rule_id:             Rule to be denied.
        :raises:                    RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': {'approve': False}})
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_replication_rule_full_history(self, scope, name):
        """
        List the rule history of a DID.

        :param scope: The scope of the DID.
        :param name: The name of the DID.
        """
        path = '/'.join([self.RULE_BASEURL, quote_plus(scope), quote_plus(name), 'history'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def examine_replication_rule(self, rule_id):
        """
        Examine a replication rule for errors during transfer.

        :param rule_id:             Rule to be denied.
        :raises:                    RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/analysis'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def list_replica_locks(self, rule_id):
        """
        List details of all replica locks for a rule.

        :param rule_id:             Rule to be denied.
        :raises:                    RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/locks'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def list_replication_rules(self, filters=None):
        """
        List all replication rules which match a filter
        :param filters: dictionary of attributes by which the rules should be filtered

        :returns: True if successful, otherwise false.
        """
        filters = filters or {}
        path = self.RULE_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET', params=filters)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
