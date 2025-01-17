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

from rucio.client.commands.bin_legacy.rucio_admin import delete_config_option, get_config, set_config_option
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Config(CommandBase):
    def module_help(self) -> str:
        return "Manage the global settings.\nCAUTION: changing global configurations can have unintended consequences!"

    def namespace(self, parser: "ArgumentParser") -> "ArgumentParser":
        parser.add_argument("-s", "--section", help="Section name")
        parser.add_argument("-o", "--option", help="Option name")
        parser.add_argument("-v", "--value", help="String-encoded value")
        return parser

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show the existing config", "namespace": self.namespace},
            "add": {"call": self.add, "docs": "Update the existing configuration settings. WARNING: Changes the global config. Can overwrite existing settings!", "namespace": self.namespace},
            "remove": {"call": self.remove, "docs": "Remove a setting from the configuration. WARNING: Changes the global config", "namespace": self.namespace},
        }

    def usage_example(self) -> list[str]:
        return [
            "$ rucio config add --section limitsscratchdisk --option testlimit --value 30  # Change the existing limitstractdisk section",
            "$ rucio config list --section foo # Show the settings in section foo",
            "$ rucio config list # Show all the different sections of the config",
            "$ rucio config remove --section testsection --option test  # Remove the value in testsection/test",
        ]

    def list_(self):
        get_config(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        set_config_option(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_config_option(self.args, self.client, self.logger, self.console, self.spinner)
