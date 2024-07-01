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

from typing import TYPE_CHECKING, Any

from rucio.client.rcom.base_command import CLIClientBase

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

    def list(self) -> list[dict[str, Any]]:
        if self.args.account is not None:
            scopes = self.client.list_scopes_for_account(self.args.account)
        else:
            scopes = self.client.list_scopes()

        # Previous version always hid "mock" scopes, which is annoying for testing
        # Is there not a teardown??
        # scopes = [{"scope": scope} for scope in scopes if "mock" not in scope]
        scopes = [{"scope": scope} for scope in scopes]
        return scopes

    def add(self) -> None:
        self.client.add_scope(account=self.args.account, scope=self.args.scope)
        self.logger.info(f"For account {self.args.account}, added new scope {self.args.scope}")
