# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2015

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class RuleClient(BaseClient):

    """RuleClient class for working with replication rules"""

    RULE_BASEURL = 'rules'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, dq2_wrapper=False):
        super(RuleClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, dq2_wrapper)

    def add_replication_rule(self, dids, copies, rse_expression, weight=None, lifetime=None, grouping='DATASET', account=None, locked=False, source_replica_expression=None, activity=None, notify='N'):
        """
        :param dids:                       The data identifier set.
        :param copies:                     The number of replicas.
        :param rse_expression:             Boolean string expression to give the list of RSEs.
        :param weight:                     If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
        :param lifetime:                   The lifetime of the replication rules (in hours).
        :param grouping:                   ALL -  All files will be replicated to the same RSE.
                                           DATASET - All files in the same dataset will be replicated to the same RSE.
                                           NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
        :param account:                    The account owning the rule.
        :param locked:                     If the rule is locked, it cannot be deleted.
        :param source_replica_expression:  RSE Expression for RSEs to be considered for source replicas.
        :param activity:                   Transfer Activity to be passed to FTS.
        :param notify:                     Notification setting for the rule (Y, N, C).
        """
        path = self.RULE_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        # TODO remove the subscription_id from the client; It will only be used by the core;
        data = dumps({'dids': dids, 'copies': copies, 'rse_expression': rse_expression,
                      'weight': weight, 'lifetime': lifetime, 'grouping': grouping,
                      'account': account, 'locked': locked, 'source_replica_expression': source_replica_expression, 'activity': activity, 'notify': notify})
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return loads(r.text)
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def delete_replication_rule(self, rule_id):
        """
        Deletes a replication rule and all associated locks.

        :param rule_id:  The id of the rule to be deleted
        :raises:         RuleNotFound, AccessDenied
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def get_replication_rule(self, rule_id):
        """
        Get a replication rule.

        :param rule_id:  The id of the rule to be retrieved.
        :raises:         RuleNotFound
        """
        path = self.RULE_BASEURL + '/' + rule_id
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r).next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
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
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)
