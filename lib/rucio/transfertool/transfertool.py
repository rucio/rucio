# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
#
# PY3K COMPATIBLE

from abc import ABCMeta, abstractmethod
from six import add_metaclass


@add_metaclass(ABCMeta)
class Transfertool(object):
    """
    Interface definition of the Rucio transfertool
    """

    def __init__(self, external_host):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """

        self.external_host = external_host

    @abstractmethod
    def submit(self, files, job_params, timeout=None):
        """
        Submit transfers to the transfertool.

        :param files:        List of dictionaries describing the file transfers.
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
