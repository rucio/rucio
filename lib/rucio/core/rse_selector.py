# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2017
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

from random import uniform, shuffle

from rucio.common.exception import InsufficientAccountLimit, InsufficientTargetRSEs, InvalidRuleWeight
from rucio.core.account import has_account_attribute
from rucio.core.account_counter import get_counter
from rucio.core.account_limit import get_account_limit
from rucio.core.rse import list_rse_attributes, has_rse_attribute
from rucio.db.sqla.session import read_session


class RSESelector():
    """
    Representation of the RSE selector
    """

    @read_session
    def __init__(self, account, rses, weight, copies, ignore_account_limit=False, session=None):
        """
        Initialize the RSE Selector.

        :param account:               Account owning the rule.
        :param rses:                  List of rse dictionaries.
        :param weight:                Weighting to use.
        :param copies:                Number of copies to create.
        :param ignore_account_limit:  Flag if the quota should be ignored.
        :param session:               DB Session in use.
        :raises:                      InvalidRuleWeight, InsufficientAccountLimit, InsufficientTargetRSEs
        """
        self.account = account
        self.rses = []  # [{'rse_id':, 'weight':, 'staging_area'}]
        self.copies = copies
        if weight is not None:
            for rse in rses:
                attributes = list_rse_attributes(rse=None, rse_id=rse['id'], session=session)
                availability_write = True if rse.get('availability', 7) in (7, 3, 2) else False
                if weight not in attributes:
                    continue  # The RSE does not have the required weight set, therefore it is ignored
                try:
                    self.rses.append({'rse_id': rse['id'],
                                      'weight': float(attributes[weight]),
                                      'mock_rse': attributes.get('mock', False),
                                      'availability_write': availability_write,
                                      'staging_area': rse['staging_area']})
                except ValueError:
                    raise InvalidRuleWeight('The RSE with id \'%s\' has a non-number specified for the weight \'%s\'' % (rse['id'], weight))
        else:
            for rse in rses:
                mock_rse = has_rse_attribute(rse['id'], 'mock', session=session)
                availability_write = True if rse.get('availability', 7) in (7, 3, 2) else False
                self.rses.append({'rse_id': rse['id'],
                                  'weight': 1,
                                  'mock_rse': mock_rse,
                                  'availability_write': availability_write,
                                  'staging_area': rse['staging_area']})

        if len(self.rses) < self.copies:
            raise InsufficientTargetRSEs('Target RSE set not sufficient for number of copies. (%s copies requested, RSE set size %s)' % (self.copies, len(self.rses)))

        if has_account_attribute(account=account, key='admin', session=session) or ignore_account_limit:
            for rse in self.rses:
                rse['quota_left'] = float('inf')
        else:
            for rse in self.rses:
                if rse['mock_rse']:
                    rse['quota_left'] = float('inf')
                else:
                    # TODO: Add RSE-space-left here!
                    limit = get_account_limit(account=account, rse_id=rse['rse_id'], session=session)
                    if limit is None:
                        rse['quota_left'] = 0
                    else:
                        rse['quota_left'] = limit - get_counter(rse_id=rse['rse_id'], account=account, session=session)['bytes']

        self.rses = [rse for rse in self.rses if rse['quota_left'] > 0]

        if len(self.rses) < self.copies:
            raise InsufficientAccountLimit('There is insufficient quota on any of the target RSE\'s to fullfill the operation.')

    def select_rse(self, size, preferred_rse_ids, copies=0, blacklist=[], prioritize_order_over_weight=False):
        """
        Select n RSEs to replicate data to.

        :param size:                         Size of the block being replicated.
        :param preferred_rse_ids:            Ordered list of preferred rses. (If possible replicate to them)
        :param copies:                       Select this amount of copies, if 0 use the pre-defined rule value.
        :param blacklist:                    List of blacklisted rses. (Do not put replicas on these sites)
        :param prioritze_order_over_weight:  Prioritize the order of the preferred_rse_ids list over the picking done by weight.
        :returns:                            List of (RSE_id, staging_area, availability_write) tuples.
        :raises:                             InsufficientAccountLimit, InsufficientTargetRSEs
        """

        result = []
        rses = self.rses
        count = self.copies if copies == 0 else copies

        # Remove blacklisted rses
        if blacklist:
            rses = [rse for rse in self.rses if rse['rse_id'] not in blacklist]
        if len(rses) < count:
            raise InsufficientTargetRSEs('There are not enough target RSEs to fulfil the request at this time.')
        # Remove rses which do not have enough quota
        rses = [rse for rse in rses if rse['quota_left'] > size]
        if len(rses) < count:
            raise InsufficientAccountLimit('There is insufficient quota on any of the target RSE\'s to fullfill the operation.')

        for copy in range(count):
            # Remove rses already in the result set
            rses = [rse for rse in rses if rse['rse_id'] not in [item[0] for item in result]]
            rses_dict = {}
            for rse in rses:
                rses_dict[rse['rse_id']] = rse
            # Prioritize the preffered rses
            preferred_rses = [rses_dict[rse_id] for rse_id in preferred_rse_ids if rse_id in rses_dict]
            if prioritize_order_over_weight and preferred_rses:
                rse = (preferred_rses[0]['rse_id'], preferred_rses[0]['staging_area'], preferred_rses[0]['availability_write'])
            elif preferred_rses:
                rse = self.__choose_rse(preferred_rses)
            else:
                rse = self.__choose_rse(rses)
            result.append(rse)
            self.__update_quota(rse, size)
        return result

    def get_rse_dictionary(self):
        """
        Return the current dictionary of potential RSEs stored in the RSE selector

        :returns:  List of RSE dictionaries
        """
        rse_dict = {}
        for rse in self.rses:
            rse_dict[rse['rse_id']] = rse
        return rse_dict

    def __update_quota(self, rse, size):
        """
        Update the internal quota value.

        :param rse:      RSE tuple to update.
        :param size:     Size to substract.
        """

        for element in self.rses:
            if element['rse_id'] == rse[0]:
                element['quota_left'] -= size
                return

    def __choose_rse(self, rses):
        """
        Choose an RSE based on weighting.

        :param rses:  The rses to be considered for the choose.
        :return:      The (rse_id, staging_area) tuple of the chosen RSE.
        """

        shuffle(rses)
        pick = uniform(0, sum([rse['weight'] for rse in rses]))
        weight = 0
        for rse in rses:
            weight += rse['weight']
            if pick <= weight:
                return (rse['rse_id'], rse['staging_area'], rse['availability_write'])
