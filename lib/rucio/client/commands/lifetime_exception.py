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

from typing import TYPE_CHECKING

from rucio.client.bin.rucio import add_lifetime_exception
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class LifetimeException(CLIClientBase):
    PARSER_NAME = "lifetime-exception"

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)
        parser.add_argument("--input-file", dest='inputfile', help="File where the list of datasets requested to be extended are located.")
        parser.add_argument("--reason", help="The reason for the extension.")
        parser.add_argument("--expiration", help="The expiration date format YYYY-MM-DD")
        parser.add_argument("--exception-id", help="The id of the exception")
        parser.add_argument("--filter-states", help="States to include")

    def module_help(self) -> str:
        return "Add an exception to the lifetime model, prevent the dataset dids in the input_file from being acted on by the Rucio Lifetime limits."

    def usage_example(self) -> list[str]:
        add_cmd = f"$ {self.COMMAND_NAME} add lifetime_exception --input_file myfile.txt --reason 'Needed for my analysis' --expiration 2015-10-30"

        return [add_cmd]

    def add(self) -> None:
        add_lifetime_exception(self.args, self.logger)
