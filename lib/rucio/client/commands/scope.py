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

from rucio.client.bin.rucio import list_scopes
from rucio.client.bin.rucio_admin import add_scope
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Scope(CLIClientBase):
    PARSER_NAME = "scope"

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]"):
        parser = super().parser(subparser)

        # The base class also needs to add the arguments for the subcommands in its argparse
        parser.add_argument("--account", help="Account name to assign a scope, or filter list")
        parser.add_argument("--scope", help="Scope name")

    def module_help(self) -> str:
        return "Add a new scope or list the existing scopes (either globally or for a account)."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} list scope --account jdoe", f"$ {self.COMMAND_NAME} add scope --account jdoe --scope new_scope"]

    def list(self):
        return list_scopes(self.args, self.logger)

    def add(self):
        return add_scope(self.args, self.logger)
