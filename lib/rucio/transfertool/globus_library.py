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

import datetime
import logging
import os
from typing import TYPE_CHECKING, Any, Literal, Union

from rucio.common.config import config_get, config_get_int
from rucio.common.extra import import_extras
from rucio.core.monitor import MetricManager

EXTRA_MODULES = import_extras(['globus_sdk'])

if EXTRA_MODULES['globus_sdk']:
    import globus_sdk
    from globus_sdk.scopes import TransferScopes

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rucio.common.types import LoggerFunction

METRICS = MetricManager(module=__name__)


class GlobusTools:
    def __init__(self, logger: "LoggerFunction" = logging.log) -> None:
        self.logger = logger
        self.auth_app_creds = config_get("conveyor", "globus_auth_app", raise_exception=True)
        self.sync_level: 'Literal["exists", "size", "mtime", "checksum"]' = config_get("conveyor", "globus_sync_level", raise_exception=False, default='checksum')  # type: ignore
        self.globus_task_deadline = config_get_int('conveyor', 'globus_task_deadline', False, 2880)

        self.auth_client = self.__auth_client()

    def __read_secrets(self) -> tuple[str, str]:
        if not os.path.exists(self.auth_app_creds):
            raise ValueError("Could not find client auth file")

        with open(self.auth_app_creds, 'r') as f:
            lines = f.read().strip().split('\n')

            if len(lines) < 2:
                raise ValueError("Auth file must contain at least 2 lines (client_id and client_secret)")

            client_id = lines[0].strip()
            client_secret = lines[1].strip()

        msg = f"Retrieved Globus auth from {self.auth_app_creds}"
        self.logger(logging.INFO, msg)
        return client_id, client_secret

    def __auth_client(self) -> "globus_sdk.ConfidentialAppAuthClient":
        client_id, client_secret = self.__read_secrets()
        return globus_sdk.ConfidentialAppAuthClient(client_id=client_id, client_secret=client_secret)

    def transfer_client(self) -> "globus_sdk.TransferClient":
        token_auth = self.auth_client.oauth2_client_credentials_tokens(TransferScopes.all)
        token = token_auth.by_resource_server["transfer.api.globus.org"]["access_token"]
        transfer_auth = globus_sdk.AccessTokenAuthorizer(token)
        return globus_sdk.TransferClient(authorizer=transfer_auth)

    def build_transfer_data(self, data_paths: dict[str, str], job_label: str, source_endpoint_id: str, destination_endpoint_id: str) -> "globus_sdk.TransferData":
        deadline = datetime.datetime.utcnow() + datetime.timedelta(minutes=self.globus_task_deadline)
        tdata = globus_sdk.TransferData(
            source_endpoint_id,
            destination_endpoint_id,
            label=job_label,
            sync_level=self.sync_level,
            deadline=deadline,
        )
        for source, dest in data_paths.items():
            tdata.add_item(source, dest)
        return tdata

    def build_delete_data(self, delete_items: "Iterable[str]", endpoint_id: str, recursive: bool = False) -> "globus_sdk.DeleteData":
        now = datetime.datetime.utcnow()
        deadline = now + datetime.timedelta(minutes=self.globus_task_deadline)
        ddata = globus_sdk.DeleteData(
            endpoint=endpoint_id,
            label=f"delete-{now.strftime('%Y%m%d%H%M%s')}",
            recursive=recursive,
            deadline=deadline
        )
        for item in delete_items:
            ddata.add_item(item)
        return ddata

    def submit_transfer(self, transfer_data: "Union[dict[str, Any], globus_sdk.TransferData]") -> "Union[dict[str, Any], globus_sdk.response.GlobusHTTPResponse]":
        try:
            with self.transfer_client() as tc:
                transfer_response = tc.submit_transfer(transfer_data)
            return transfer_response
        except globus_sdk.TransferAPIError as e:
            response_data = {"task_id": e.request_id, "code": e.code, "http_status": e.http_status, "data": e.text}
            return response_data

    def submit_deletion(self, deletation_data: "globus_sdk.DeleteData") -> "Union[dict[str, Any], globus_sdk.response.GlobusHTTPResponse]":
        try:
            with self.transfer_client() as tc:
                delete_response = tc.submit_delete(deletation_data)
            return delete_response
        except globus_sdk.TransferAPIError as e:
            response_data = {"task_id": e.request_id, "code": e.code, "http_status": e.http_status, "data": e.text}
            return response_data

    def check_transfer(self, transfer_ids: list[str]) -> dict[str, str]:
        responses = {}
        with self.transfer_client() as tc:
            for task_id in transfer_ids:
                try:
                    transfer = tc.get_task(str(task_id))
                    status = str(transfer["status"])
                    if status == 'SUCCEEDED':
                        METRICS.counter('bytes_transferred').inc(transfer['bytes_transferred'])
                        METRICS.counter('effective_bytes_per_second').inc(transfer['effective_bytes_per_second'])
                except globus_sdk.TransferAPIError:
                    status = "FAILED"

                responses[str(task_id)] = status
        return responses
