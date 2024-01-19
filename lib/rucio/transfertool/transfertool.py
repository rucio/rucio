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

import logging
from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

from rucio.common.constants import SUPPORTED_PROTOCOLS
from rucio.core.request import get_request

if TYPE_CHECKING:
    from typing import Optional

    from rucio.core.rse import RseData
    from rucio.core.request import DirectTransfer


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

    def __str__(self):
        return self.transfertool_class.__name__

    def __hash__(self):
        return hash(frozenset(self.__dict__.items()))

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__

    def make_transfertool(self, **additional_kwargs):
        all_kwargs = dict(self.fixed_kwargs)
        all_kwargs.update(additional_kwargs)
        return self.transfertool_class(**all_kwargs)


class TransferStatusReport(object, metaclass=ABCMeta):
    """
    Allows to compute the changes which have to be applied to the database
    to reflect the current status reported by the external transfertool into
    the database.
    """

    supported_db_fields = [
        'state',
    ]

    def __init__(self, request_id, request=None):
        self.request_id = request_id
        self.__request = request  # Optional: DB request. If provided, saves us a database call to fetch it by request_id
        self.__initialized = False

        # Supported db fields bellow
        self.state = None

    @abstractmethod
    def initialize(self, session, logger=logging.log):
        """
        Initialize all fields from self.supported_update_fields
        """
        pass

    @abstractmethod
    def get_monitor_msg_fields(self, session, logger=logging.log):
        """
        Return the fields which will be included in the message sent to hermes.
        """
        pass

    def ensure_initialized(self, session, logger=logging.log):
        if not self.__initialized:
            self.initialize(session, logger)
            self.__initialized = True

    def request(self, session):
        """
        Fetch the request by request_id if needed.
        """
        if not self.__request:
            self.__request = get_request(self.request_id, session=session)
        return self.__request

    def get_db_fields_to_update(self, session, logger=logging.log):
        """
        Returns the fields which have to be updated in the request
        """
        self.ensure_initialized(session, logger)

        updates = {}
        for field in self.supported_db_fields:
            field_value = getattr(self, field)
            if field_value:
                updates[field] = field_value
        return updates


class Transfertool(object, metaclass=ABCMeta):
    """
    Interface definition of the Rucio transfertool
    """

    external_name = ''
    required_rse_attrs = ()
    supported_schemes = set(SUPPORTED_PROTOCOLS).difference(('magnet', ))

    def __init__(self, external_host, logger=logging.log):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """

        self.external_host = external_host
        self.logger = logger

    def __str__(self):
        return self.external_host if self.external_host is not None else self.__class__.__name__

    @classmethod
    def can_perform_transfer(cls, source_rse: "RseData", dest_rse: "RseData"):
        """
        Return True if this transfertool is able to perform a transfer between the given source and destination rses
        """
        if (
                all(source_rse.attributes.get(attribute) is not None for attribute in cls.required_rse_attrs)
                and all(dest_rse.attributes.get(attribute) is not None for attribute in cls.required_rse_attrs)
        ):
            return True
        return False

    @classmethod
    @abstractmethod
    def submission_builder_for_path(cls, transfer_path, logger=logging.log) -> "tuple[list[DirectTransfer], Optional[TransferToolBuilder]]":
        """
        Analyze the transfer path. If this transfertool class can submit the given transfers, return
        a TransferToolBuilder instance capable to build transfertool objects configured for this
        particular submission.
        :param transfer_path:  List of DirectTransfer
        :param logger: logger instance
        :return: a tuple: a sub-path starting at the first node from transfer_path, and a TransfertoolBuilder instance
        capable to submit this sub-path. Returns ([], None) if submission is impossible.
        """
        pass

    @abstractmethod
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
    def bulk_query(self, requests_by_eid, timeout=None) -> dict[str, dict[str, TransferStatusReport]]:
        """
        Query the status of a bulk of transfers in FTS3 via JSON.

        :param requests_by_eid: dictionary {external_id1: {request_id1: request1, ...}, ...} of request to be queried
        :returns: Transfer status information as a dictionary.
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
