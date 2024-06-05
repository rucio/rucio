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

import copy
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from rucio.client.rcom.base_command import CLIClientBase
from rucio.client.rcom.utils import get_dids, resolve_to_contents
from rucio.common.utils import chunks

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class LifetimeException(CLIClientBase):
    PARSER_NAME = "lifetime_exception"

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)
        parser.add_argument("--input-file", help="File where the list of datasets requested to be extended are located.")
        parser.add_argument("--reason", help="The reason for the extension.")
        parser.add_argument("--expiration", help="The expiration date format YYYY-MM-DD")
        parser.add_argument("--exception-id", help="The id of the exception")
        parser.add_argument("--filter-states", help="States to include")

    def module_help(self) -> str:
        return "Add an exception to the lifetime model, prevent the dataset dids in the input_file from being acted on by the Rucio Lifetime limits."

    def usage_example(self) -> list[str]:
        add_cmd = f"$ {self.COMMAND_NAME} add lifetime_exception --input_file myfile.txt --reason 'Needed for my analysis' --expiration 2015-10-30"
        list_cmd = f"$ {self.COMMAND_NAME} list lifetime_exception --exception_id 12345"

        return [add_cmd, list_cmd]

    def list(self) -> list[dict[str, Any]]:
        return [exception for exception in self.client.list_exceptions(self.args.exception_id, states=self.args.filter_states)]

    def add(self) -> Optional[dict[str, Any]]:
        expiration = None if self.args.expiration is None else datetime.strptime(self.args.expiration, "%Y-%m-%d")
        with open(self.args.input_file) as f:
            dids = list(set(line.strip() for line in f))

        containers = []
        datasets = []

        info_summary = {}

        file_errors = 0
        container_exceptions_submitted = 0
        lifetime_campaign_error = 0
        did_exceptions_submitted = 0
        dids_list = get_dids(dids, self.client)

        info_summary["Total DIDS"] = len(dids_list)

        chunk_limit = 500  # Server should be able to accept 1000
        dids_list_copy = copy.deepcopy(dids_list)
        for chunk in chunks(dids_list_copy, chunk_limit):
            for meta in self.client.get_metadata_bulk(chunk):
                scope, name = meta["scope"], meta["name"]
                dids_list.remove({"scope": scope, "name": name})

                if meta["did_type"] == "FILE":
                    self.logger.warning(f"{scope}:{name} is a file. Will be ignored.")
                    file_errors += 1

                elif meta["did_type"] == "CONTAINER":
                    self.logger.warning(f"{scope}:{name} is a container. It needs to be resolved")
                    containers.append({"scope": scope, "name": name})
                    container_exceptions_submitted += 1

                elif not meta["eol_at"]:
                    self.logger.warning(f"{scope}:{name}is not affected by the lifetime model")
                    lifetime_campaign_error += 1

                else:
                    self.logger.info(f"{scope}:{name} will be declared.")
                    datasets.append({"scope": scope, "name": name})
                    did_exceptions_submitted += 1

        for did in dids_list:
            self.logger.warning(f'{did["scope"]}:{did["name"]} does not exist.')

        if containers:
            self.logger.warning("One or more DIDs are containers. They will be resolved into a list of datasets to request exception.")
            for container in containers:
                self.logger.info(f'Resolving {container["scope"]}:{container["name"]} into datasets')
                list_datasets = resolve_to_contents(container["scope"], container["name"], self.client, resolve_to="DATASET")
                for chunk in chunks(list_datasets, chunk_limit):
                    for meta in self.client.get_metadata_bulk(chunk):
                        scope, name = meta["scope"], meta["name"]
                        if not meta["eol_at"]:
                            self.logger.warning(f"{scope}:{name} is not affected by the lifetime model")
                            lifetime_campaign_error += 1
                        else:
                            self.logger.info(f"{scope}:{name}  will be declared")
                            datasets.append({"scope": scope, "name": name})

        if not datasets:
            self.logger.error("Nothing to submit")
            return None

        info_summary["DID not submitted because it is a file"] = file_errors
        info_summary["DID not submitted because it is not part of the lifetime campaign"] = lifetime_campaign_error
        info_summary["DID that are containers and were resolved"] = container_exceptions_submitted
        info_summary["DID successfully submitted including the one from containers resolved"] = did_exceptions_submitted

        self.client.add_exception(dids=datasets, account=self.client.account, pattern="", comments=self.args.reason, expires_at=expiration)
        self.logger.info("Exception successfully submitted.")
        return info_summary
