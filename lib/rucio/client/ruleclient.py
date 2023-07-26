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

from json import dumps, loads
from typing import Any, Optional, Union
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class RuleClient(BaseClient):

    """RuleClient class for working with replication rules"""

    RULE_BASEURL = 'rules'

    def add_replication_rule(
        self,
        dids: list[str],
        copies: int,
        rse_expression: str,
        priority: int = 3,
        lifetime: Optional[int] = None,
        grouping: str = 'DATASET',
        notify: str = 'N',
        source_replica_expression: Optional[str] = None,
        activity: Optional[str] = None,
        account: Optional[str] = None,
        meta: Optional[str] = None,
        ignore_availability: bool = False,
        purge_replicas: bool = False,
        ask_approval: bool = False,
        asynchronous: bool = False,
        locked: bool = False,
        delay_injection=None,
        comment=None,
        weight=None,
    ):
        """
        :param dids:                       The data identifier set.
        :param copies:                     The number of replicas.
        :param rse_expression:             Boolean string expression to give the list of RSEs.
        :param priority:                   Priority of the transfers.
        :param lifetime:                   The lifetime of the replication rules (in seconds).
        :param grouping:                   ALL -  All files will be replicated to the same RSE.
                                           DATASET - All files in the same dataset will be replicated to the same RSE.
                                           NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
        :param notify:                     Notification setting for the rule (Y, N, C).
        :param source_replica_expression:  RSE Expression for RSEs to be considered for source replicas.
        :param activity:                   Transfer Activity to be passed to FTS.
        :param account:                    The account owning the rule.
        :param meta:                       Metadata, as dictionary.
        :param ignore_availability:        Option to ignore the availability of RSEs.
        :param purge_replicas:             When the rule gets deleted purge the associated replicas immediately.
        :param ask_approval:               Ask for approval of this replication rule.
        :param asynchronous:               Create rule asynchronously by judge-injector.
        :param locked:                     If the rule is locked, it cannot be deleted.
        :param delay_injection:
        :param comment:                    Comment about the rule.
        :param weight:                     If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
        """
        path = self.RULE_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        # TODO remove the subscription_id from the client; It will only be used by the core;
        data = dumps({'dids': dids, 'copies': copies, 'rse_expression': rse_expression,
                      'weight': weight, 'lifetime': lifetime, 'grouping': grouping,
                      'account': account, 'locked': locked, 'source_replica_expression': source_replica_expression,
                      'activity': activity, 'notify': notify, 'purge_replicas': purge_replicas,
                      'ignore_availability': ignore_availability, 'comment': comment, 'ask_approval': ask_approval,
                      'asynchronous': asynchronous, 'delay_injection': delay_injection, 'priority': priority, 'meta': meta})
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_replication_rule(
        self, rule_id: str, purge_replicas: Optional[bool] = None
    ):
        """
        Deletes a replication rule and all associated locks.

        :param rule_id:         The id of the rule to be deleted
        :param purge_replicas:  Immediately delete the replicas.
        :raises:                RuleNotFound, AccessDenied
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)

        data = dumps({'purge_replicas': purge_replicas})

        r = self._send_request(url, type_='DEL', data=data)

        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_replication_rule(self, rule_id: str):
        """
        Get a replication rule.

        :param rule_id:  The id of the rule to be retrieved.
        :raises:         RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_replication_rule(self, rule_id: str, options: dict[str, Any]):
        """
        :param rule_id:   The id of the rule to be retrieved.
        :param options:   Options dictionary.
        :raises:          RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': options})
        r = self._send_request(url, type_='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def reduce_replication_rule(
        self, rule_id: str, copies: int, exclude_expression=None
    ):
        """
        :param rule_id:             Rule to be reduced.
        :param copies:              Number of copies of the new rule.
        :param exclude_expression:  RSE Expression of RSEs to exclude.
        :raises:                    RuleReplaceFailed, RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id + '/reduce'
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'copies': copies, 'exclude_expression': exclude_expression})
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.ok:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def move_replication_rule(
        self, rule_id: str, rse_expression: str, override
    ):
        """
        Move a replication rule to another RSE and, once done, delete the original one.

        :param rule_id:                    Rule to be moved.
        :param rse_expression:             RSE expression of the new rule.
        :param override:                   Configurations to update for the new rule.
        :raises:                           RuleNotFound, RuleReplaceFailed
        """

        path = self.RULE_BASEURL + '/' + rule_id + '/move'
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({
            'rule_id': rule_id,
            'rse_expression': rse_expression,
            'override': override,
        })
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def approve_replication_rule(self, rule_id: str):
        """
        :param rule_id:             Rule to be approved.
        :raises:                    RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': {'approve': True}})
        r = self._send_request(url, type_='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def deny_replication_rule(self, rule_id: str, reason: Optional[str] = None):
        """
        :param rule_id:             Rule to be denied.
        :param reason:              Reason for denying the rule.
        :raises:                    RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        options: dict[str, Union[bool, str]] = {'approve': False}
        if reason:
            options['comment'] = reason
        data = dumps({'options': options})
        r = self._send_request(url, type_='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_replication_rule_full_history(
            self, scope: Union[str, bytes], name: Union[str, bytes]
    ):
        """
        List the rule history of a DID.

        :param scope: The scope of the DID.
        :param name: The name of the DID.
        """
        path = '/'.join([self.RULE_BASEURL, quote_plus(scope), quote_plus(name), 'history'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def examine_replication_rule(self, rule_id: str):
        """
        Examine a replication rule for errors during transfer.

        :param rule_id:             Rule to be denied.
        :raises:                    RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/analysis'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def list_replica_locks(self, rule_id: str):
        """
        List details of all replica locks for a rule.

        :param rule_id:             Rule to be denied.
        :raises:                    RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/locks'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
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
        r = self._send_request(url, type_='GET', params=filters)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
