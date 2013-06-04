# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from random import uniform, shuffle

from rucio.common.exception import InvalidReplicationRule, InsufficientQuota
from rucio.core.quota import list_account_limits, list_account_usage
from rucio.core.rse import list_rse_attributes
from rucio.db.session import read_session


class RSESelector():
    """
    Representation of the RSE selector
    """

    @read_session
    def __init__(self, account, rse_ids, weight, copies, session=None):
        """
        Initialize the RSE Selector.

        :param account:  Account owning the rule.
        :param rse_ids:  List of rse_ids.
        :param weight:   Weighting to use.
        :param copies:   Number of copies to create.
        :param session:  DB Session in use.
        :raises:         InvalidReplicationRule
        """

        self.account = account
        self.rses = []
        self.copies = copies
        if weight is not None:
            for rse_id in rse_ids:
                attributes = list_rse_attributes(rse=None, rse_id=rse_id, session=session)
                if weight not in attributes:
                    continue  # The RSE does not have the required weight set, therefore it is ignored
                try:
                    self.rses.append({'rse_id': rse_id, 'weight': float(attributes[weight])})
                except ValueError:
                    raise InvalidReplicationRule('The RSE with id \'%s\' has a non-number specified for the weight \'%s\'' % (rse_id, weight))
        else:
            self.rses = [{'rse_id': rse_id, 'weight': 1} for rse_id in rse_ids]
        if not self.rses:
            raise InvalidReplicationRule('Target RSE set empty (Check if weight attribute is set for the specified RSEs)')

        for rse in self.rses:
            #TODO: Add RSE-space-left here!
            rse['quota_left'] = list_account_limits(account=account, rse_id=rse['rse_id'], session=session) - list_account_usage(account=account, rse_id=rse['rse_id'], session=session)

        self.rses = [rse for rse in self.rses if rse['quota_left'] > 0]

    def select_rse(self, size, preferred_rse_ids):
        """
        Select n RSEs to replicate data to.

        :param size:               Size of the block being replicated.
        :param preferred_rse_ids:  Ordered list of preferred rses. (If possible replicate to them)
        :returns:                  List of RSE ids.
        :raises:                   InsufficientQuota
        """

        result = []
        for copy in range(self.copies):
            #Only use RSEs which have enough quota
            rses = [rse for rse in self.rses if rse['quota_left'] > size and rse['rse_id'] not in result]
            if not rses:
                #No site has enough quota
                raise InsufficientQuota('There is insufficient quota on any of the RSE\'s to fullfill the operation')
            #Filter the preferred RSEs to those with enough quota
            #preferred_rses = [x for x in preferred_rse_ids if x in [rse['rse_id'] for rse in rses]]
            preferred_rses = [rse for rse in rses if rse['rse_id'] in preferred_rse_ids]
            if preferred_rses:
                rse_id = self.__choose_rse(preferred_rses)
            else:
                rse_id = self.__choose_rse(rses)
            result.append(rse_id)
            self.__update_quota(rse_id, size)
        return result

    def __update_quota(self, rse_id, size):
        """
        Update the internal quota value.

        :param rse_ids:  RSE-id to update.
        :param size:     Size to substract.
        """

        for element in self.rses:
            if element['rse_id'] == rse_id:
                element['quota_left'] -= size
                return

    def __choose_rse(self, rses):
        """
        Choose an RSE based on weighting.

        :param rses:  The rses to be considered for the choose.
        :return:      The id of the chosen rse
        """

        shuffle(rses)
        pick = uniform(0, sum([rse['weight'] for rse in rses]))
        weight = 0
        for rse in rses:
            weight += rse['weight']
            if pick <= weight:
                return rse['rse_id']
