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
from argparse import ArgumentError, RawDescriptionHelpFormatter
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace, _SubParsersAction
    from collections.abc import Callable
    from logging import Logger

    from rich.console import Console
    from rich.status import Status

    from rucio.client.client import Client
    from rucio.client.commands.utils import OperationDict


class CommandBase(ABC):
    def __init__(self, client: "Client", args: "Namespace", logger: "Logger", console: "Console", spinner: "Status") -> None:
        self.COMMAND_NAME = sys.argv[0].split("/")[-1]
        self.PARSER_NAME = self.__class__.__name__.lower()
        self.client = client
        self.args = args
        self.logger = logger
        self.console = console
        self.spinner = spinner

    @abstractmethod
    def module_help(self) -> str:
        """
        Description of the command
        """
        raise NotImplementedError

    @abstractmethod
    def usage_example(self) -> list[str]:
        """
        List of examples. Examples should be in the form `$ rucio <command> ...  # A quick description of what this does`
        """
        raise NotImplementedError

    @abstractmethod
    def _operations(self) -> dict[str, "OperationDict"]:
        """
        Dictionary description of the different implemented operations with their associated call and documentation.
        Example:
            If you want to have: $ rucio do something --kwarg this

            class Do(CommandBase):
                ...

                def _operations(self):
                    return {"something": "call": self.something, "namespace": self.something_namespace, "docs": "Does Something"}

                def something(self):
                    ...

                def something_namespace(self, parser):
                    parser.add_argument("--kwarg", choices={"this", "that"})
        """
        raise NotImplementedError

    def default_operation(self) -> "Callable":
        """
        The operation that will be executed when no operational argument is added by the user. Can raise an error.
        """
        raise NotImplementedError

    def implemented_subcommands(self) -> dict[str, type["CommandBase"]]:
        """
        Provide a mapping of subcommands. Leave empty if command has no subcommands.
        Example:
          Running commands: $ rucio foo bar --kwarg

          class Foo(CommandBase):
            ...
            def implemented_subcommands(self):
                return {"bar": Bar}

          class Bar(Foo):
            ...
        """
        return {}

    def _help(self) -> str:
        """
        Create a help string including the module help, operation options, subcommand options, a usage example, and stating the default operation.
        """
        help = f"{self.module_help()}\n"

        try:
            default_operation = [name for name, operation in self._operations().items() if operation["call"] == self.default_operation()][0]
            help += f"Default Operation: {default_operation}\n"
        except (IndexError, NotImplementedError):
            default_operation = None

        help += "\nMatching Commands:\n"
        for operation_name in self._operations().keys():
            help += f"rucio {self.PARSER_NAME} {operation_name}\n"

        for subcommand_name, subcommand in self.implemented_subcommands().items():
            for operation_name in subcommand(self.client, self.args, self.logger, self.console, self.spinner)._operations().keys():
                help += f"rucio {self.PARSER_NAME} {subcommand_name} {operation_name}\n"

        examples = "\n".join(self.usage_example())
        help += f"\n\nUsage Example:\n{examples}"

        return help

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]") -> "ArgumentParser":
        """
        Create a parser for a given argument. Adds the positional arguments (operations and subcommands) and the namespaces for default operations
        """
        command_parser = subparser.add_parser(self.PARSER_NAME, description=self._help(), formatter_class=RawDescriptionHelpFormatter)
        subcommand_parser = command_parser.add_subparsers(dest=f"{self.PARSER_NAME}_subcommand")

        try:
            subcommands = self.implemented_subcommands()
            for _, subcommand in subcommands.items():
                # Subparsers are given their own call to avoid recursionErrors.
                subcommand(self.client, self.args, self.logger, self.console, self.spinner).subparser(subcommand_parser)
        # If the command has no subcommands
        except (NotImplementedError, TypeError):
            pass

        operations = self._operations()
        for name, operation in operations.items():
            help = operation.get("docs", "")
            parser = subcommand_parser.add_parser(name, help=help)
            namespace = operation.get("namespace")
            if namespace is not None:
                namespace(parser)

                # For the default_operations - include the args in the top level parser
                if operation.get("call") == self.default_operation():
                    namespace(command_parser)

            # Just get the namespace argument if there isn't a specific namespace for a operation
            elif hasattr(self, "namespace"):
                try:
                    self.namespace(command_parser)  # type: ignore
                except ArgumentError:  # Namespace has already been added
                    pass

        return command_parser

    def subparser(self, parser: "_SubParsersAction[ArgumentParser]"):
        """
        Create a parser for a new subcommand. Add the default operation namespace to the top level menu.
        """
        subparser = parser.add_parser(self.PARSER_NAME, description=self._help(), help=self.module_help(), formatter_class=RawDescriptionHelpFormatter)

        operations = self._operations()
        subsubparser = subparser.add_subparsers(dest=f"{self.PARSER_NAME}_subcommand")

        for name, operation in operations.items():
            help = operation.get("docs", "")
            operation_parser = subsubparser.add_parser(name, help=help)
            namespace = operation.get("namespace")
            if namespace is not None:
                namespace(operation_parser)
            elif hasattr(self, "namespace"):
                self.namespace(operation_parser)  # type: ignore

        return subparser

    def _execute_subcommand(self, subcommands: dict, requested_subcommand: str, requested_verb: Optional[str] = None):
        if requested_subcommand in subcommands.keys():
            subcommand_client = subcommands[requested_subcommand](self.client, self.args, self.logger, self.console, self.spinner)

            subcommand_operations = subcommand_client._operations()
            if requested_verb in subcommand_operations.keys():
                subcommand_operations[requested_verb]["call"]()
            elif requested_verb is not None:
                raise NotImplementedError
            else:
                subcommand_client.default_operation()()

    def __call__(self):
        subcommands = self.implemented_subcommands()
        operations = self._operations()

        requested_subcommand = vars(self.args).get(f"{self.PARSER_NAME}_subcommand")
        requested_verb = vars(self.args).get("verb")

        # If the subcommand has multiple positional args, they can be contained in the {name}_subcommand dict
        if (requested_verb is None) and (requested_subcommand is not None):
            requested_verb = vars(self.args).get(f"{requested_subcommand}_subcommand")

        if (requested_subcommand is not None) and (subcommands is not None):
            if requested_subcommand in operations.keys():
                # Treat the subcommand as the operational verb
                operations[requested_subcommand]["call"]()

            elif subcommands is not None:
                self._execute_subcommand(subcommands, requested_subcommand, requested_verb)

            else:  # Should not be possible, but better to catch the error than not.
                raise NotImplementedError
        else:
            # Do the default operation given by the None operation
            self.default_operation()()
