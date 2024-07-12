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
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter, _ArgumentGroup, _SubParsersAction
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from logging import Logger

    from rucio.client.client import Client
    from rucio.client.commands.utils import MultiOutType


class CLIClientBase(ABC):
    def __init__(self, client: "Client", args: "Namespace", logger: "Logger") -> None:
        self.COMMAND_NAME = sys.argv[0].split("/")[-1]
        self.client = client
        self.args = args
        self.logger = logger

    @abstractmethod
    def module_help(self) -> str:
        """
        :return: str description of the module
        :rtype: str
        """
        return ""

    @abstractmethod
    def usage_example(self) -> list[str]:
        """
        :return: list of examples in the format $ {base command} {verb} {command} --options
        :rtype: list[str]
        """
        return ""

    def implemented_verbs(self) -> list[str]:
        """
        :return: List of the verbs implemented for the module - for the help menu
        :rtype: list[str]
        """
        included = []
        for method in [self.add, self.remove, self.list, self.set, self.unset]:
            try:
                method()
                included.append(method.__name__)  # Nothing should run without arguments but hey! Just in case

            except NotImplementedError:
                pass  # Don't add it to the included list if it's not implemented
            except Exception:
                included.append(method.__name__)
        return included

    def _help(self) -> str:
        examples = "\n".join(self.usage_example())
        return f"{self.module_help()}\nPossible Verbs: {self.implemented_verbs()}\nUsage Example:\n{examples}"

    @abstractmethod
    def parser(self, subparser: "_SubParsersAction[ArgumentParser]") -> "ArgumentParser":
        parser_name = self.__class__.__name__.lower() if not hasattr(self, "PARSER_NAME") else self.PARSER_NAME

        command_parser = subparser.add_parser(parser_name, description=self._help(), help=self.module_help(), formatter_class=RawDescriptionHelpFormatter)
        return command_parser

    def subcommand_parser(self, subparser: "ArgumentParser") -> "_ArgumentGroup":
        parser_name = self.__class__.__name__.lower() if not hasattr(self, "PARSER_NAME") else self.PARSER_NAME
        return subparser.add_argument_group(parser_name, description=self._help(), conflict_handler="resolve")

    def add(self) -> Optional["MultiOutType"]:
        raise NotImplementedError

    def remove(self) -> Optional["MultiOutType"]:
        raise NotImplementedError

    def set(self) -> Optional["MultiOutType"]:
        raise NotImplementedError

    def unset(self) -> Optional["MultiOutType"]:
        raise NotImplementedError

    def list(self) -> Optional["MultiOutType"]:
        raise NotImplementedError

    def __call__(self, verb: str) -> Optional["MultiOutType"]:
        command = {"set": self.set, "unset": self.unset, "add": self.add, "remove": self.remove, "list": self.list}[verb]
        return command()
