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
from rucio.common.constants import HTTPMethod
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
        A replication rule can be used to ensure availability of a replica at different RSEs,
        functionally submitting a transfer request.

        Parameters
        ----------
        dids :
            The data identifier set. Format as
            [{"scope": scope, "name": did_name1}, {"scope": scope, "name": did_name2}, ...]
        copies :
            The number of replicas.
        rse_expression :
            Boolean string expression to give the list of RSEs.
        priority :
            Priority of the transfers. Default is 3.
        lifetime :
            The lifetime of the replication rules (in seconds).
        grouping :
            ALL - All files will be replicated to the same RSE.
            DATASET - All files in the same dataset will be replicated to the same RSE.
            NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
            Default is 'DATASET'.
        notify :
            Notification setting for the rule (Y [Yes], N [No], C [Close, notify when rule is closed.], P [Progress]). Default is 'N'.
        source_replica_expression :
            RSE Expression for RSEs to be considered for source replicas.
        activity :
            Transfer Activity to be passed to FTS.
        account :
            The account owning the rule.
        meta :
            Metadata, as dictionary.
        ignore_availability :
            Option to ignore the availability of RSEs. Default is False.
        purge_replicas :
            When the rule gets deleted purge the associated replicas immediately. Default is False.
        ask_approval :
            Ask for approval of this replication rule. Default is False.
        asynchronous :
            Create rule asynchronously by judge-injector. Default is False.
        locked :
            If the rule is locked, it cannot be deleted. Default is False.
        delay_injection :
            Delay the rule injection.
        comment :
            Comment about the rule.
        weight :
            If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.

        Returns
        ----------
        Rule ID. Can be used to check the status of the rule.

        Raises
        ----------
        InvalidRSEExpression
            The rse expression provided doesn't match any RSEs.
        DataIdentifierNotFound
            Requested DID does not exist or is otherwise specified incorrectly.
        InsufficentAccountLimit
            The account used to create the rule does not have sufficent quota on the target RSE.
        DuplicateRule
            Rule already exists with the same DID, RSE, and number of copies.
        InsufficentTargetRSEs
            There are not enough RSEs that match the RSE expression to fulfil the 'copies' requirement
        InvalidValueForKey
            Requested '0' or negative copies of a replica.

        Examples
        --------
        ??? Example

            Add a rule to create a replica of the DID myscope:did at a local RSE named "LocalRSE".

            ```python
            from rucio.client.client import Client
            client = Client()
            rule_id = client.add_replication_rule([{"scope": "myscope", "name": "mydid"}], copies=1, rse_expression="LocalRSE)
            print(rule_id)
            ```

        See Also
        ---------
        rucio.client.rseclient.RSEClient.list_rses
        rucio.client.replicaclient.ReplicaClient.list_replicas
        rucio.client.ruleclient.RuleClient.delete_replication_rule
        rucio.client.ruleclient.RuleClient.get_replication_rule

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
        r = self._send_request(url, method=HTTPMethod.POST, data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_replication_rule(
        self, rule_id: str, purge_replicas: Optional[bool] = None
    ) -> Literal[True]:
        """
        Deletes a replication rule and all associated replica locks.

        Parameters
        ----------
        rule_id :
            The id of the rule to be deleted.
        purge_replicas :
            Immediate delete the replicas

        Raises
        -------
        RuleNotFound
            Rule ID does not exist.
        AccessDenied
            Rule does not belong, to the user associated with the client, or user has insufficent permissions.
        UnsupportedOperation
            Rule is either locked, or is a parent of child rules with "delete_parent=False" set.

        Returns
        -------
            True if rule is successfully deleted
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)

        data = dumps({'purge_replicas': purge_replicas})

        r = self._send_request(url, method=HTTPMethod.DELETE, data=data)

        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_replication_rule(self, rule_id: str) -> Any:
        """
        Get a replication rule.

        Parameters
        ----------
        rule_id :
            The id of the rule to be retrieved.

        Raises
        -------
        RuleNotFound

        Returns
        -------
        Dictionary of rule attributes.
            'id'
                ID of the rule
            'scope'
                DID scope
            'name'
                DID name
            'did_type'
                Type of the DID (FILE, DATASET, CONTAINER)
            'account'
                Owner of the rule
            'rse_expression'
                RSE Expression
            'copies'
                Number of replica copies
            'grouping'
                How replicas are grouped (ALL, DATASET, NONE)
            'lifetime'
                The lifetime of the replication rules (in seconds)
            'locked'
                If the rule is locked, it cannot be deleted
            'source_replica_expression'
                RSE Expression for RSEs to be considered for source replicas
            'activity'
                Transfer Activity to be passed to FTS
            'notify'
                Notification setting for the rule (Y, N, C, P)
            'purge_replicas'
                When the rule gets deleted purge the associated replicas immediately
            'ignore_availability'
                Option to ignore the availability of RSEs
            'comment'
                Comment about the rule
            'ask_approval'
                Ask for approval of this replication rule
            'asynchronous'
                Create rule asynchronously by judge-injector
            'delay_injection'
                Delay the rule injection
            'priority'
                Priority of the transfers
            'weight'
                Weighting scheme to be used
            'meta'
                Metadata as dictionary
            'state'
                State of the replication rule (OK, REPLICATING, STUCK, SUSPENDED, WAITING_APPROVAL, INJECT)
            'error'
                Any error raised when creating replicas for the rule.
            'created_at'
                Rule creation date.
            'updated_at'
                Last modified date of rule.
            'expires_at'
                Expiration date of the rule
            'eol_at'
                End of life date for the replicas
            'deleted_at'
                Date when the rule was deleted
            'stuck_at'
                Date when the rule entered STUCK state
            'child_rule_id'
                ID of the child rule (if this rule was replaced)
            'subscription_id'
                ID of the subscription that created this rule
            'split_container'
                Whether the rule was split from a container rule
            'ignore_account_limit'
                Whether account limits were ignored when creating the rule
            'notification'
                Notification setting for the rule (YES, NO, CLOSE, PROGRESS)
            'locks_ok_cnt'
                Number of locks in OK state
            'locks_replicating_cnt'
                Number of locks in REPLICATING state
            'locks_stuck_cnt'
                Number of locks in STUCK state
            'bytes'
                Total bytes of the DID
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
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
            Options dictionary. Options dictionary can contain any of the keys used to add a rule.

        Raises
        -------
        RuleNotFound
            Rule ID was not found.
        InputValidationError
            An invalid key was passed in "options".

        Returns
        -------
        True if the rule was sucessfully updated.

        Examples
        --------
        ??? Example

            Update a rule with a lifetime of 0, so the rule expires.

            ```python
            from rucio.client.client import Client
            client = Client()
            rule_id = "Existing Rule ID"
            client.update_replication_rule(rule_id, options={"lifetime":0})
            ```

        See Also
        ---------
        rucio.client.ruleclient.RuleClient.add_replication_rule
        rucio.client.ruleclient.RuleClient.reduce_replication_rule


        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': options})
        r = self._send_request(url, method=HTTPMethod.PUT, data=data)
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
        Downgrade the number of replica copies a rule creates.
        Creates a new rule and deletes the old one.

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
            Rule ID does not exist
        RuleReplaceFailed
            The target rule is either not in an OK state, or requested copies is larger than current copies.
        AccessDenied
            User does not have sufficent premissions.
        InvalidRSEExpression
            The Expression (<rule ID rse expression>)\\(<exclude_expression>) does not resolve to RSEs.

        Returns
        -------
        New rule ID.

        See Also
        ---------
        rucio.client.ruleclient.RuleClient.update_replication_rule
        """

        path = self.RULE_BASEURL + '/' + rule_id + '/reduce'
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'copies': copies, 'exclude_expression': exclude_expression})
        r = self._send_request(url, method=HTTPMethod.POST, data=data)
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
        Move a replication rule to another RSE and, once done, sets the lifetime of the original rule to 0.
        Creates the new rule as a child rule of the supplied rule.

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
            Rule ID does not exist.
        RuleReplaceFailed
            Rule already has a child rule.
        UnsupportedOperation
            Key in override is invalid.

        Returns
        -------
        New rule ID.

        See Also
        ---------
        rucio.client.ruleclient.RuleClient.update_replication_rule
        rucio.client.ruleclient.RuleClient.reduce_replication_rule

        """

        path = self.RULE_BASEURL + '/' + rule_id + '/move'
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({
            'rule_id': rule_id,
            'rse_expression': rse_expression,
            'override': override,
        })
        r = self._send_request(url, method=HTTPMethod.POST, data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def approve_replication_rule(self, rule_id: str) -> Literal[True]:
        """
        Admin tool used to approve pending rules.
        Rules with the "ask_approval" attribute can be approved this way.

        An email will be sent to the user who created the rule when the rule is approved.

        Parameters
        ----------
        rule_id :
            Rule to be approved.

        Raises
        -------
        RuleNotFound
            Rule ID does not exist
        AccessDenied
            User does not have premission to deny/approve rules.

        Returns
        --------
        True if rule was successfully approved.

        See Also
        ---------
            rucio.client.ruleclient.RuleClient.deny_replication_rule
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'options': {'approve': True}})
        r = self._send_request(url, method=HTTPMethod.PUT, data=data)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def deny_replication_rule(self, rule_id: str, reason: Optional[str] = None) -> Literal[True]:
        """
        Admin tool used to deny and delete pending rules.
        Rules with the "ask_approval" attribute can be denied this way.

        When a rule is denied, a message is sent to the user who created
        the rule via the email listed on their account.

        Parameters
        ----------
        rule_id :
            Rule to be denied.
        reason :
            Reason for denying the rule.

        Raises
        -------
        RuleNotFound
            Rule ID does not exist
        AccessedDenied
            User does not have premission to deny/approve rules.

        Returns
        -------
        True if the rule is sucessfully denied.

        See Also
        ---------
            rucio.client.ruleclient.RuleClient.approve_replication_rule
        """

        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        options: dict[str, Union[bool, str]] = {'approve': False}
        if reason:
            options['comment'] = reason
        data = dumps({'options': options})
        r = self._send_request(url, method=HTTPMethod.PUT, data=data)
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

        Returns
        -------
            Iterator of rule history dictionaries with the keys:
            'rule_id'
                ID of the rule
            'account'
                Owner of the rule
            'rse_expression'
                RSE Expression
            'created_at'
                Rule creation date.
            'updated_at'
                Last modified date of rule.
            'state'
                State of the rule. R [Replicating], O [Ok], S [Stuck], U [Suspended], W [Waiting Approval], I [Injecting]
            'locks_ok_cnt'
                Number of locks in OK state
            'locks_replicating_cnt'
                Number of locks in REPLICATING state
            'locks_stuck_cnt'
                Number of locks in STUCK state


        Raises
        -------
        RuleNotFound
            DID not found or no rules exist for the given scope and name.

        See Also
        --------
            rucio.client.ruleclient.RuleClient.list_replication_rules
            rucio.client.ruleclient.RuleClient.get_replication_rule

        """
        path = '/'.join([self.RULE_BASEURL, quote_plus(scope), quote_plus(name), 'history'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
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
            The rule to examine

        Returns
        --------
        Dictionary with the following keys:
            'rule_error': Error message from transfer error
            'transfers': List of ongoing transfer IDs

        Raises
        -------
        RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/analysis'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
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
            Rule ID

        Returns
        -------
        Iterator of dictionaries of replica information with the keys:
            'scope': DID Scope
            'name': DID Name
            'rse_id': RSE ID
            'rse': RSE Name
            'state': State of replica
            'rule_id': Passed rule ID

        Raises
        -------
        RuleNotFound

        See Also
        ---------
            rucio.client.ruleclient.RuleClient.examine_replication_rule
            rucio.client.ruleclient.RuleClient.get_replication_rule
        """
        path = self.RULE_BASEURL + '/' + rule_id + '/locks'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def list_replication_rules(self, filters: Optional[dict[str, Any]] = None) -> "Iterator[dict[str, Any]]":
        """
        List all replication rules which match a filter
        Parameters
        ----------
        filters:
            dictionary of attributes by which the rules should be filtered.
            Filters can be any of the attributes in the return dictionary.

        Returns
        -------
            Iterator of rule dictionaries with the keys:
            'id'
                ID of the rule
            'scope'
                DID scope
            'name'
                DID name
            'did_type'
                Type of the DID (FILE, DATASET, CONTAINER)
            'account'
                Owner of the rule
            'rse_expression'
                RSE Expression
            'copies'
                Number of replica copies
            'grouping'
                How replicas are grouped (ALL, DATASET, NONE)
            'lifetime'
                The lifetime of the replication rules (in seconds)
            'locked'
                If the rule is locked, it cannot be deleted
            'source_replica_expression'
                RSE Expression for RSEs to be considered for source replicas
            'activity'
                Transfer Activity to be passed to FTS
            'notify'
                Notification setting for the rule (Y, N, C, P)
            'purge_replicas'
                When the rule gets deleted purge the associated replicas immediately
            'ignore_availability'
                Option to ignore the availability of RSEs
            'comment'
                Comment about the rule
            'ask_approval'
                Ask for approval of this replication rule
            'asynchronous'
                Create rule asynchronously by judge-injector
            'delay_injection'
                Delay the rule injection
            'priority'
                Priority of the transfers
            'weight'
                Weighting scheme to be used
            'meta'
                Metadata as dictionary
            'state'
                State of the replication rule (OK, REPLICATING, STUCK, SUSPENDED, WAITING_APPROVAL, INJECT)
            'error'
                Any error raised when creating replicas for the rule.
            'created_at'
                Rule creation date.
            'updated_at'
                Last modified date of rule.
            'expires_at'
                Expiration date of the rule
            'eol_at'
                End of life date for the replicas
            'deleted_at'
                Date when the rule was deleted
            'stuck_at'
                Date when the rule entered STUCK state
            'child_rule_id'
                ID of the child rule (if this rule was replaced)
            'subscription_id'
                ID of the subscription that created this rule
            'split_container'
                Whether the rule was split from a container rule
            'ignore_account_limit'
                Whether account limits were ignored when creating the rule
            'notification'
                Notification setting for the rule (YES, NO, CLOSE, PROGRESS)
            'locks_ok_cnt'
                Number of locks in OK state
            'locks_replicating_cnt'
                Number of locks in REPLICATING state
            'locks_stuck_cnt'
                Number of locks in STUCK state
            'bytes'
                Total bytes of the DID

        Raises
        -------
        RucioException
            An invalid key is passed as a filter.

        See Also
        --------
            rucio.client.ruleclient.RuleClient.add_replication_rule
            rucio.client.ruleclient.RuleClient.get_replication_rule
        """
        filters = filters or {}
        path = self.RULE_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET, params=filters)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
