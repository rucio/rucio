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

from rucio.client.bin.rucio_admin import delete_config_option, get_config, set_config_option
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Config(CLIClientBase):
    PARSER_NAME = "config"

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparser)

        parser.add_argument("--section", help="Section Name")
        parser.add_argument("--option", help="Option name")
        parser.add_argument("--value", help="String encoded value")

    def module_help(self) -> str:
        return "View or modify the configuration file being used by the local client."

    def usage_example(self) -> list[str]:
        examples = [f"$ {self.COMMAND_NAME} list config --section quota", f"$ {self.COMMAND_NAME} set config --section quota --option USERDISK --value 30", f"$ {self.COMMAND_NAME} unset config --section quota --option USERDISK"]
        return examples

    def list(self) -> None:
        get_config(self.args, self.logger)

    def set(self) -> None:
        set_config_option(self.args, self.logger)

    def unset(self) -> None:
        delete_config_option(self.args, self.logger)
