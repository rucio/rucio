# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014,2017
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class SubscriptionClient(BaseClient):

    """SubscriptionClient class for working with subscriptions"""

    SUB_BASEURL = 'subscriptions'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, user_agent='rucio-clients'):
        super(SubscriptionClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def add_subscription(self, name, account, filter, replication_rules, comments, lifetime, retroactive, dry_run, priority=3):
        """
        Adds a new subscription which will be verified against every new added file and dataset

        :param name: Name of the subscription
        :type:  String
        :param account: Account identifier
        :type account:  String
        :param filter: Dictionary of attributes by which the input data should be filtered
                       **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
        :type filter:  Dict
        :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
        :type replication_rules:  Dict
        :param comments: Comments for the subscription
        :type comments:  String
        :param lifetime: Subscription's lifetime (days); False if subscription has no lifetime
        :type lifetime:  Integer or False
        :param retroactive: Flag to know if the subscription should be applied on previous data
        :type retroactive:  Boolean
        :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
        :type dry_run:  Boolean
        :param priority: The priority of the subscription (3 by default)
        :type priority: Integer
        """
        path = self.SUB_BASEURL + '/' + account + '/' + name
        url = build_url(choice(self.list_hosts), path=path)
        if filter and type(filter) != dict:
            raise TypeError('filter should be a dict')
        if replication_rules and type(replication_rules) != list:
            raise TypeError('replication_rules should be a list')
        data = dumps({'options': {'filter': filter, 'replication_rules': replication_rules, 'comments': comments,
                      'lifetime': lifetime, 'retroactive': retroactive, 'dry_run': dry_run, 'priority': priority}})
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return r.text
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_subscriptions(self, name=None, account=None):
        """
        Returns a dictionary with the subscription information :
        Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

        :param name: Name of the subscription
        :type:  String
        :param account: Account identifier
        :type account:  String
        :returns: Dictionary containing subscription parameter
        :rtype:   Dict
        :raises: exception.NotFound if subscription is not found
        """
        path = self.SUB_BASEURL
        if account:
            path += '/%s' % (account)
            if name:
                path += '/%s' % (name)
        else:
            path += '/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_subscription(self, name, account=None, filter=None, replication_rules=None, comments=None, lifetime=None, retroactive=None, dry_run=None, priority=None):
        """
        Updates a subscription

        :param name: Name of the subscription
        :type:  String
        :param account: Account identifier
        :type account:  String
        :param filter: Dictionary of attributes by which the input data should be filtered
                       **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
        :type filter:  Dict
        :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
        :type replication_rules:  Dict
        :param comments: Comments for the subscription
        :type comments:  String
        :param lifetime: Subscription's lifetime (days); False if subscription has no lifetime
        :type lifetime:  Integer or False
        :param retroactive: Flag to know if the subscription should be applied on previous data
        :type retroactive:  Boolean
        :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
        :type dry_run:  Boolean
        :param priority: The priority of the subscription
        :type priority: Integer
        :raises: exception.NotFound if subscription is not found
        """
        if not account:
            account = self.account
        path = self.SUB_BASEURL + '/' + account + '/' + name
        url = build_url(choice(self.list_hosts), path=path)
        if filter and type(filter) != dict:
            raise TypeError('filter should be a dict')
        if replication_rules and type(replication_rules) != list:
            raise TypeError('replication_rules should be a list')
        data = dumps({'options': {'filter': filter, 'replication_rules': replication_rules, 'comments': comments,
                      'lifetime': lifetime, 'retroactive': retroactive, 'dry_run': dry_run, 'priority': priority}})
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_subscription_rules(self, account, name):
        """
        List the associated rules of a subscription.

        :param account: Account of the subscription.
        :param name:    Name of the subscription.
        """

        path = '/'.join([self.SUB_BASEURL, account, name, 'Rules'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
