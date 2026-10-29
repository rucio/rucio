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
from typing import TYPE_CHECKING, Any, Optional, Union

from rucio.common.constants import RseAttr
from rucio.common.utils import EXTRA_MODULES, chunks
from rucio.db.sqla.constants import RequestState
from rucio.transfertool.globus_library import GlobusTools
from rucio.transfertool.transfertool import TransferStatusReport, Transfertool, TransferToolBuilder

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from rucio.common.types import LoggerFunction
    from rucio.core.request import DirectTransfer
    from rucio.db.sqla.session import Session

    if EXTRA_MODULES['globus_sdk']:
        from globus_sdk import GlobusHTTPResponse


class GlobusTransferStatusReport(TransferStatusReport):

    supported_db_fields = [
        'state',
        'external_id',
    ]

    def __init__(self, request_id: str, external_id: str, globus_response: "Union[str, GlobusHTTPResponse]") -> None:
        super().__init__(request_id)

        if globus_response == 'FAILED':
            new_state = RequestState.FAILED
        elif globus_response == 'SUCCEEDED':
            new_state = RequestState.DONE
        else:
            new_state = RequestState.SUBMITTED

        self.state = new_state
        self.external_id = None
        if new_state in [RequestState.FAILED, RequestState.DONE]:
            self.external_id = external_id

    def initialize(self, session: "Session", logger: "LoggerFunction" = logging.log) -> None:
        pass

    def get_monitor_msg_fields(self, session: "Session", logger: "LoggerFunction" = logging.log) -> dict[str, Any]:
        return {'protocol': 'globus'}


class GlobusTransferTool(Transfertool):
    """
    Globus implementation of Transfertool abstract base class
    """

    external_name = 'globus'
    supported_schemes = set(['https'])
    required_rse_attrs = (RseAttr.GLOBUS_ENDPOINT_ID, RseAttr.GLOBUS_COLLECTION_ID)

    def __init__(self, external_host: str, logger: "LoggerFunction" = logging.log, group_bulk: int = 200, group_policy: str = 'single') -> None:
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """
        if not external_host:
            external_host = 'Globus Online Transfertool'
        super().__init__(external_host, logger)
        self.group_bulk = group_bulk
        self.group_policy = group_policy

        self.tools = GlobusTools()

    @classmethod
    def submission_builder_for_path(cls, transfer_path: list["DirectTransfer"], logger: "LoggerFunction" = logging.log) -> tuple[list["DirectTransfer"], "TransferToolBuilder"]:
        hop = transfer_path[0]
        if not cls.can_perform_transfer(hop.src.rse, hop.dst.rse):
            logger(logging.WARNING, "Source or destination globus_endpoint_id, globus_collection_id not set. Skipping {}".format(hop))
            return [], TransferToolBuilder(cls, external_host='Globus Online Transfertool')

        return [hop], TransferToolBuilder(cls, external_host='Globus Online Transfertool')

    def group_into_submit_jobs(self, transfer_paths: "Iterable[list[DirectTransfer]]") -> list[dict[str, Any]]:

        if self.group_policy == 'single':
            group_bulk = 1
        else:
            group_bulk = self.group_bulk

        grouped_jobs = []
        for chunk in chunks(transfer_paths, group_bulk):
            # Globus doesn't support multihop. Get the first hop only.
            transfers = [transfer_path[0] for transfer_path in chunk]

            grouped_jobs.append({
                'transfers': transfers,
                # Job params are not used by globus transfertool, but are needed for further common fts/globus code
                'job_params': {}
            })

        return grouped_jobs

    def submit(self, transfers: "Iterable[DirectTransfer]", job_params: dict[str, str], timeout: Optional[int] = None) -> str:
        """
        Submit a bulk transfer to globus API

        :param transfers:    List of dictionaries describing the file transfers.
        :param job_params:   Not used by Globus Transfsertool
        :param timeout:      Timeout in seconds.
        :returns:            Globus transfer identifier.
        """

        # Transfer data objects are a dict, we can place them all in an updated dictionary
        # And submit that obj instead
        transfer_data = {}
        for transfer in transfers:
            job_label = transfer.rws.request_id if transfer.rws.request_id is not None else ""
            for source in transfer.sources:

                source_endpoint_id = transfer.src.rse.attributes[RseAttr.GLOBUS_COLLECTION_ID]
                dest_endpoint_id = transfer.dst.rse.attributes[RseAttr.GLOBUS_COLLECTION_ID]

                tdata = self.tools.build_transfer_data(
                    {transfer.source_url(source): transfer.dest_url},
                    job_label,
                    source_endpoint_id=source_endpoint_id,
                    destination_endpoint_id=dest_endpoint_id
                )
                transfer_data.update(tdata)

        response = self.tools.submit_transfer(transfer_data)
        task_id = response['task_id']
        return task_id

    def bulk_query(self, requests_by_eid: "Mapping[str, Mapping[str, Any]]", timeout: Optional[int] = None) -> dict[str, dict[str, GlobusTransferStatusReport]]:
        """
        Query the status of a bulk of transfers in globus API

        :param requests_by_eid: dictionary {external_id1: {request_id1: request1, ...}, ...}
        :returns: Transfer status information as a dictionary.
        """

        job_responses = self.tools.check_transfer(list(requests_by_eid.keys()))

        response = {}
        for transfer_id, requests in requests_by_eid.items():
            for request_id in requests:
                response.setdefault(transfer_id, {})[request_id] = GlobusTransferStatusReport(request_id, transfer_id, job_responses[transfer_id])
        return response

    def bulk_update(self, resps, request_ids):
        pass

    def cancel(self):
        pass

    def update_priority(self):
        pass
