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

    def list(self) -> list[dict[str, Any]]:
        response = self.client.get_config(section=self.args.section, option=self.args.option)

        if isinstance(response, dict):
            config_response = []
            for key, value in response.items():
                if isinstance(value, dict):
                    # Getting the whole config
                    for option, option_value in value.items():
                        config_response.append({"section": key, "option": option, "value": option_value})

                else:
                    # Getting a single section
                    config_response.append({"section": self.args.section, "option": key, "value": value})
            return config_response

        else:
            # Got a single option
            return [{"section": self.args.section, "option": self.args.option, "value": response}]

    def set(self) -> None:
        self.client.set_config_option(section=self.args.section, option=self.args.option, value=self.args.value)
        self.logger.info(f"Updated config section {self.args.section} with {self.args.option}={self.args.value}")

    def unset(self) -> None:
        self.client.delete_config_option(section=self.args.section, option=self.args.option)
        self.logger.info(f"Removed option {self.args.option} from {self.args.section}")
