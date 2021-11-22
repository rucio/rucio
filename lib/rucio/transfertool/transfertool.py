# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Radu Carpa <radu.carpa@cern.ch>, 2021

import logging

from abc import ABCMeta, abstractmethod
from six import add_metaclass


class TransferToolBuilder(object):
    """
    Builder for Transfertool objects.
    Stores the parameters needed to create the Transfertool object of the given type/class.

    Implements __hash__ and __eq__ to allow using it as key in dictionaries and group transfers
    by common transfertool.
    """
    def __init__(self, transfertool_class, **kwargs):
        self.transfertool_class = transfertool_class
        self.fixed_kwargs = frozenset(kwargs.items())

    def __hash__(self):
        return hash(frozenset(self.__dict__.items()))

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__

    def make_transfertool(self, **additional_kwargs):
        all_kwargs = dict(self.fixed_kwargs)
        all_kwargs.update(additional_kwargs)
        return self.transfertool_class(**all_kwargs)


@add_metaclass(ABCMeta)
class Transfertool(object):
    """
    Interface definition of the Rucio transfertool
    """

    def __init__(self, external_host, logger=logging.log):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """

        self.external_host = external_host
        self.logger = logger

    def __str__(self):
        return self.external_host

    @staticmethod
    @classmethod
    def submission_builder_for_path(cls, transfer_path, logger=logging.log):
        """
        Analyze the transfer path. If this transfertool class can submit the given transfers, return
        a TransferToolBuilder instance capable to build transfertool objects configured for this
        particular submission.
        :param transfer_path:  List of DirectTransferDefinitions
        :param logger: logger instance
        :return: a TransfertoolBuilder instance or None
        """
        pass

    @abstractmethod
    def group_into_submit_jobs(self, transfer_paths):
        """
        Takes an iterable over transfer paths, and create groups which can be submitted in one call to submit()

        :param transfer_paths: Iterable over (potentially multihop) transfer paths.
        :return: list of dicts of the form {"transfers": <transfer list>, "job_params": <data blob>}
        """
        pass

    @abstractmethod
    def submit(self, transfers, job_params, timeout=None):
        """
        Submit transfers to the transfertool.

        :param transfers:    List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            Transfertool internal identifiers.
        """
        pass

    @abstractmethod
    def query(self, transfer_ids, details=False, timeout=None):
        """
        Query the status of transfers in the transfertool.

        :param transfer_ids: List of transfertool internal identifiers as a string.
        :param details:      Switch if detailed information should be listed.
        :param timeout:      Timeout in seconds.
        :returns:            Transfer status information as list of dictionaries.
        """
        pass

    @abstractmethod
    def cancel(self, transfer_ids, timeout=None):
        """
        Cancel transfers that have been submitted to the transfertool.

        :param transfer_ids: Transfertool internal transfer identifiers as list of strings.
        :param timeout:      Timeout in seconds.
        :returns:            True if cancellation was successful.
        """
        pass

    @abstractmethod
    def update_priority(self, transfer_id, priority, timeout=None):
        """
        Update the priority of a transfer that has been submitted to the transfertool.

        :param transfer_id: Transfertool internal transfer identifier as a string.
        :param priority:    Job priority as an integer from 1 to 5.
        :param timeout:     Timeout in seconds.
        :returns:           True if update was successful.
        """
        pass
