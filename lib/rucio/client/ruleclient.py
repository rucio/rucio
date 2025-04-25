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
from typing import TYPE_CHECKING, Any, Literal, Optional, Union
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


class RuleClient(BaseClient):

    """RuleClient class for working with replication rules"""

    RULE_BASEURL = 'rules'

    def add_replication_rule(
        self,
        dids: "Sequence[dict[str, str]]",
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
        delay_injection: Optional[int] = None,
        comment: Optional[str] = None,
        weight: Optional[int] = None,
    ) -> Any:
        """
        Add a replication rule.

        Parameters
        ----------
        dids : sequence of dictionaries
            The data identifier set.
        copies : int
            The number of replicas.
        rse_expression : str
            Boolean string expression to give the list of RSEs.
        priority : optional
            Priority of the transfers. Default is 3.
        lifetime : optional
            The lifetime of the replication rules (in seconds).
        grouping : optional
            ALL - All files will be replicated to the same RSE.
            DATASET - All files in the same dataset will be replicated to the same RSE.
            NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
            Default is 'DATASET'.
        notify : optional
            Notification setting for the rule (Y, N, C). Default is 'N'.
        source_replica_expression : optional
            RSE Expression for RSEs to be considered for source replicas.
        activity : optional
            Transfer Activity to be passed to FTS.
        account : optional
            The account owning the rule.
        meta : optional
            Metadata, as dictionary.
        ignore_availability : optional
            Option to ignore the availability of RSEs. Default is False.
        purge_replicas : optional
            When the rule gets deleted purge the associated replicas immediately. Default is False.
        ask_approval : optional
            Ask for approval of this replication rule. Default is False.
        asynchronous : optional
            Create rule asynchronously by judge-injector. Default is False.
        locked : optional
            If the rule is locked, it cannot be deleted. Default is False.
        delay_injection : optional
            Delay the rule injection.
        comment : optional
            Comment about the rule.
        weight : optional
            If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.

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
    ) -> Literal[True]:
        """
        Deletes a replication rule and all associated locks.

        Parameters
        ----------
        rule_id : str
            The id of the rule to be deleted.
        purge_replicas : bool, optional
            Immediate delete the replicas

        Raises
        -------
        RuleNotFound
        AccessDenied
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)

        data = dumps({'purge_replicas': purge_replicas})

        r = self._send_request(url, type_='DEL', data=data)

        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_replication_rule(self, rule_id: str) -> Any:
        """
        Get a replication rule.

        Parameters
        ----------
        rule_id : str
            The id of the rule to be retrieved.

        Raises
        -------
        RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_replication_rule(self, rule_id: str, options: dict[str, Any]) -> Literal[True]:
        """
        Parameters
        ----------
        rule_id :
            The id of the rule to be retrieved.
        options :
            Options dictionary.

        Raises
        -------
        RuleNotFound
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
        self,
        rule_id: str,
        copies: int,
        exclude_expression: Optional[str] = None
    ) -> Any:
        """
        Parameters
        ----------
        rule_id :
            The id of the rule to be reduced.
        copies :
            Number of copies of the new rule.
        exclude_expression :
            RSE Expression of RSEs to exclude.

        Raises
        -------
        RuleNotFound
        RuleReplaceFailed
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
        self,
        rule_id: str,
        rse_expression: str,
        override: "Mapping[str, Any]"
    ) -> Any:
        """
        Move a replication rule to another RSE and, once done, delete the original one.

        Parameters
        ----------
        rule_id :
            Rule to be moved.
        rse_expression :
            RSE expression of the new rule.
        override :
            Configurations to update for the new rule.
        Raises
        -------
        RuleNotFound
        RuleReplaceFailed
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

    def approve_replication_rule(self, rule_id: str) -> Literal[True]:
        """
        Parameters
        ----------
        rule_id :
            Rule to be approved.

        Raises
        -------
        RuleNotFound
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': {'approve': True}})
        r = self._send_request(url, type_='PUT', data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def deny_replication_rule(self, rule_id: str, reason: Optional[str] = None) -> Literal[True]:
        """
        Parameters
        ----------
        rule_id :
            Rule to be denied.
        reason :
            Reason for denying the rule.

        Raises
        -------
        RuleNotFound

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
    ) -> "Iterator[dict[str, Any]]":
        """
        List the rule history of a DID.

        Parameters
        ----------
        scope :
            The scope of the DID.
        name :
            The name of the DID.
        """
        path = '/'.join([self.RULE_BASEURL, quote_plus(scope), quote_plus(name), 'history'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def examine_replication_rule(self, rule_id: str) -> Any:
        """
        Examine a replication rule for errors during transfer.

        Parameters
        ----------
        rule_id :
            The rule to be denied
        Raises
        -------
        RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/analysis'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def list_replica_locks(self, rule_id: str) -> Any:
        """
        List details of all replica locks for a rule.

        Parameters
        ----------
        rule_id :
            The rule to be denied
        Raises
        -------
        RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/locks'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def list_replication_rules(self, filters: Optional[dict[str, Any]] = None) -> "Iterator[dict[str, Any]]":
        """
        List all replication rules which match a filter
        Parameters
        ----------
        filers:
            dictionary of attributes by which the rules should be filtered

        Returns
        -------
        True if successful, otherwise false.
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
