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

import itertools
import logging
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Optional

from rucio.db.sqla.constants import RequestState
from rucio.transfertool.transfertool import TransferStatusReport, Transfertool, TransferToolBuilder

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from rucio.common.types import LoggerFunction
    from rucio.core.request import DirectTransfer
    from rucio.db.sqla.session import Session


class MockTransferStatusReport(TransferStatusReport):

    supported_db_fields = [
        'state',
        'external_id'
    ]

    def __init__(self, request_id: str, external_id: str):
        super().__init__(request_id)
        self.state = RequestState.DONE
        self.external_id = external_id

    def initialize(self, session: "Session", logger: "LoggerFunction" = logging.log) -> None:
        pass

    def get_monitor_msg_fields(self, session: "Session", logger: "LoggerFunction" = logging.log) -> dict[str, Any]:
        return {}


class MockTransfertool(Transfertool):
    """
    Mock implementation of a Rucio transfertool

    This is not actually used anywhere at the moment
    """

    external_name = 'mock'
    required_rse_attrs = ()
    supported_schemes = {'mock', 'file'}

    def __init__(self, external_host: str, logger: "LoggerFunction" = logging.log):
        super(MockTransfertool, self).__init__(external_host, logger)

    @classmethod
    def submission_builder_for_path(
        cls,
        transfer_path: list["DirectTransfer"],
        logger: "LoggerFunction" = logging.log
    ) -> tuple[list["DirectTransfer"], "TransferToolBuilder"]:
        return transfer_path, TransferToolBuilder(cls, external_host='Mock Transfertool')

    def group_into_submit_jobs(self, transfers: "Iterable[list[DirectTransfer]]") -> list[dict[str, Any]]:
        return [{'transfers': list(itertools.chain.from_iterable(transfers)), 'job_params': {}}]

    def submit(self, transfers: "Iterable[DirectTransfer]", job_params: dict[str, str], timeout: Optional[int] = None) -> str:
        return str(uuid.uuid1())

    def bulk_query(self, requests_by_eid: "Mapping[str, Mapping[str, Any]]", timeout: Optional[int] = None) -> dict[str, dict[str, MockTransferStatusReport]]:
        response = {}
        for transfer_id, requests in requests_by_eid.items():
            for request_id in requests:
                response.setdefault(transfer_id, {})[request_id] = MockTransferStatusReport(request_id, transfer_id)
        return response

    def cancel(self, transfer_ids: Sequence[str], timeout: Optional[int] = None) -> bool:
        return True

    def update_priority(self, transfer_id: str, priority: int, timeout: Optional[int] = None) -> bool:
        return True
