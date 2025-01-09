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

from rucio.client.commands.bin_legacy.rucio import add_lifetime_exception
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace
    from logging import Logger

    from rich.console import Console
    from rich.status import Status

    from rucio.client.client import Client
    from rucio.client.commands.utils import OperationDict


class LifetimeException(CommandBase):
    def __init__(self, client: "Client", args: "Namespace", logger: "Logger", console: "Console", spinner: "Status") -> None:
        super().__init__(client, args, logger, console, spinner)
        self.PARSER_NAME = "lifetime-exception"

    def module_help(self) -> str:
        return "Manage Lifetime Exceptions (to make protections against deletion from reaper daemons)"

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "add": {"call": self.add, "namespace": self.namespace},
        }

    def usage_example(self) -> list[str]:
        return ["$ rucio lifetime-exception add --file myfile.txt --reason 'Needed for my analysis' --expiration 2015-10-30  # Add exceptions for all DIDs listed in myfile.txt"]

    def namespace(self, parser: "ArgumentParser") -> None:
        self._add_positional_option(parser, "file", dest="inputfile", help="File where the list of datasets requested to be extended are located", abbr='f')
        parser.add_argument("--reason", help="The reason for the extension")
        parser.add_argument("-x", "--expiration", help="The expiration date format YYYY-MM-DD")

    def add(self):
        add_lifetime_exception(self.args, self.client, self.logger, self.console, self.spinner)
