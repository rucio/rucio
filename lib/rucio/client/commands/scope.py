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

from rucio.client.commands.bin_legacy.rucio import list_scopes
from rucio.client.commands.bin_legacy.rucio_admin import add_scope
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Scope(CommandBase):
    def module_help(self) -> str:
        return "Manage scopes - A namespace partition generally used to separate common data from user data"

    def _operations(self) -> dict[str, "OperationDict"]:
        return {"list": {"call": self.list_, "docs": "Show existing scopes", "namespace": self.list_namespace}, "add": {"call": self.add, "docs": "Create a new scope", "namespace": self.add_namespace}}

    def usage_example(self) -> list[str]:
        return [
            "$ rucio scope add --scope user.jdoe --account jdoe  # Add a new scope, 'user.jdoe' for use with the account jdoe",
            "$ rucio scope list --account jdoe  # List the existing scopes for account jdoe"
        ]

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", help="Account name for filtering, attribution")

    def add_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", help="Account name for filtering, attribution", required=True)
        parser.add_argument("-s", "--scope", help="Name of the new scope to add", required=True)

    def list_(self):
        list_scopes(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        add_scope(self.args, self.client, self.logger, self.console, self.spinner)
