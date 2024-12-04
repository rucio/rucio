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
import argparse
import os
import signal
import sys
import time
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.status import Status
from rich.theme import Theme
from rich.traceback import install

import rucio.client.commands as commands
from rucio import version
from rucio.client.commands.bin_legacy.rucio import get_client, ping, test_server, whoami_account
from rucio.client.commands.command_base import CommandBase
from rucio.client.commands.utils import exception_handler, setup_gfal2_logger, signal_handler
from rucio.client.richclient import MAX_TRACEBACK_WIDTH, MIN_CONSOLE_WIDTH, CLITheme, get_cli_config, get_pager, setup_rich_logger
from rucio.common.extra import import_extras
from rucio.common.utils import setup_logger

if TYPE_CHECKING:
    from argparse import Namespace
    from logging import Logger

    from rucio.client.client import Client

EXTRA_MODULES = import_extras(["argcomplete"])

if EXTRA_MODULES["argcomplete"]:
    import argcomplete  # pylint: disable=E0401

SUCCESS, FAILURE = 0, 1


class Commands:
    def __init__(self, logger: "Logger", client: "Client", args: "Namespace", console: Console, spinner: Status) -> None:
        self.logger = logger
        self.args = args
        self.client = client
        self.console = console
        self.spinner = spinner

    @staticmethod
    def _all_commands() -> dict[str, type[commands.CommandBase]]:
        # Look for all the CommandBase'd child classes in this folder and add their parsers and child parsers
        command_map = {child.__name__.lower(): child for child in commands.CommandBase.__subclasses__() if child.__name__ != "LifetimeException"}
        command_map["lifetime-exception"] = commands.LifetimeException
        command_map["ping"] = Ping
        command_map["whoami"] = Whoami
        command_map["test-server"] = TestServer
        return command_map

    @staticmethod
    def _add_parsers() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description='CLI Rucio Client. (Use --legacy to view CLI from <36.0)')
        Commands._main_parser(parser)

        subparsers = parser.add_subparsers(dest="command", help="Command to execute, see `{command} -h` for more details and subcommands.")
        for command in Commands._all_commands().values():
            command(None, None, None, None, None).parser(subparsers)  # type: ignore

        return parser

    @staticmethod
    def _main_parser(parser: argparse.ArgumentParser) -> None:
        main_args = parser.add_argument_group("Main Arguments")

        main_args.add_argument("--version", action="version", version="%(prog)s " + version.version_string())

        main_args.add_argument("--config", help="The Rucio configuration file to use.")
        main_args.add_argument("--verbose", "-v", default=False, action="store_true", help="Print more verbose output.")
        main_args.add_argument("-H", "--host", metavar="ADDRESS", help="The Rucio API host.")
        main_args.add_argument("--auth-host", metavar="ADDRESS", help="The Rucio Authentication host.")
        main_args.add_argument("-a", "--account", dest="issuer", help="Rucio account to use.")
        main_args.add_argument("-S", "--auth-strategy", help="Authentication strategy (userpass, x509...)")
        main_args.add_argument("-T", "--timeout", type=float, help="Set all timeout values to seconds.")
        main_args.add_argument("--user-agent", "-U", dest="user_agent", default="rucio-clients", help="Rucio User Agent")
        main_args.add_argument("--vo", metavar="VO", help="VO to authenticate at. Only used in multi-VO mode.")
        main_args.add_argument("--no-pager", dest="no_pager", default=False, action='store_true', help=argparse.SUPPRESS)

        auth_args = parser.add_argument_group("Authentication Settings")

        auth_args.add_argument("-u", "--user", dest="username", help="username")
        auth_args.add_argument("-pwd", "--password", help="password")
        # Options for defining remaining OIDC parameters
        auth_args.add_argument("--oidc-user", dest="oidc_username", help="OIDC username")
        auth_args.add_argument("--oidc-password", help="OIDC password")
        auth_args.add_argument(
            "--oidc-scope",
            default="openid profile",
            help="Defines which (OIDC) information user will share with Rucio. "
            + 'Rucio requires at least -sc="openid profile". To request refresh token for Rucio, scope must include "openid offline_access" and '  # NOQA: W503
            + "there must be no active access token saved on the side of the currently used Rucio Client.",
        )  # NOQA: W503
        auth_args.add_argument("--oidc-audience", help="Defines which audience are tokens requested for.")
        auth_args.add_argument(
            "--oidc-auto",
            default=False,
            action="store_true",
            help="If not specified, username and password credentials are not required and users will be given a URL " + "to use in their browser. If specified, the users explicitly trust Rucio with their IdP credentials.",
        )  # NOQA: W503
        auth_args.add_argument(
            "--oidc-polling",
            default=False,
            action="store_true",
            help="If not specified, user will be asked to enter a code returned by the browser to the command line. "
            + "If --polling is set, Rucio Client should get the token without any further interaction of the user. This option is active only if --auto is *not* specified.",
        )  # NOQA: W503
        auth_args.add_argument(
            "--oidc-refresh-lifetime",
            help="Max lifetime in hours for this access token; the token will be refreshed by an asynchronous Rucio daemon. "
            + "If not specified, refresh will be stopped after 4 days. This option is effective only if --oidc-scope includes offline_access scope for a refresh token to be granted to Rucio.",
        )  # NOQA: W503
        auth_args.add_argument("--oidc-issuer", help="Defines which Identity Provider is going to be used. The issuer string must correspond " + "to the keys configured in the /etc/idpsecrets.json auth server configuration file.")  # NOQA: W503

        # Options for the x509  auth_strategy
        auth_args.add_argument("--certificate", help="Client certificate file.")
        auth_args.add_argument("--ca-certificate", help="CA certificate to verify peer against (SSL).")

    def _run_command(self) -> Optional[int]:
        try:
            command_class = Commands._all_commands()[self.args.command]
        except KeyError as e:
            if self.args.command is not None:
                self.logger.error(f"Cannot find command {self.args.command}: {e}")
            sys.exit(FAILURE)

        return exception_handler(command_class(self.client, self.args, self.logger, self.console, self.spinner))()

    def __call__(self) -> None:
        self.logger.debug("Running a command with the following arguments: %s" % vars(self.args))
        start_time = time.time()
        self._run_command()
        end_time = time.time()

        self.logger.debug("Completed in %-0.4f sec." % (end_time - start_time))


class Ping(CommandBase):
    def _operations(self):
        return {}

    def module_help(self) -> str:
        return ""

    def usage_example(self) -> list[str]:
        return []

    def parser(self, subparser):
        command_parser = subparser.add_parser("ping", description="Ping the server", formatter_class=argparse.RawDescriptionHelpFormatter)
        return command_parser

    def __call__(self):
        ping(self.args, self.client, self.logger, self.console, self.spinner)


class Whoami(CommandBase):
    def _operations(self):
        return {}

    def module_help(self) -> str:
        return ""

    def usage_example(self) -> list[str]:
        return []

    def parser(self, subparser):
        command_parser = subparser.add_parser("whoami", description="See login information, test credentials.", formatter_class=argparse.RawDescriptionHelpFormatter)
        return command_parser

    def __call__(self):
        whoami_account(self.args, self.client, self.logger, self.console, self.spinner)


class TestServer(CommandBase):
    def _operations(self):
        return {}

    def module_help(self) -> str:
        return ""

    def usage_example(self) -> list[str]:
        return []

    def parser(self, subparser):
        command_parser = subparser.add_parser("test-server", description="Test client against the server", formatter_class=argparse.RawDescriptionHelpFormatter)
        return command_parser

    def __call__(self):
        test_server(self.args, self.client, self.logger, self.console, self.spinner)


def main():
    cli_config = get_cli_config()
    console = Console(theme=Theme(CLITheme.LOG_THEMES), soft_wrap=True)
    console.width = max(MIN_CONSOLE_WIDTH, console.width)

    spinner = Status('Initializing spinner', spinner=CLITheme.SPINNER, spinner_style=CLITheme.SPINNER_STYLE, console=console)
    pager = get_pager()

    parser_object = Commands._add_parsers()
    if EXTRA_MODULES["argcomplete"]:
        argcomplete.autocomplete(parser_object)
    args = parser_object.parse_args()
    if args.config is not None:
        os.environ["RUCIO_CONFIG"] = args.config
    if args.command is None:
        parser_object.print_help()
        sys.exit(FAILURE)

    setup_gfal2_logger()

    if cli_config == 'rich':
        install(console=console, word_wrap=True, width=min(console.width, MAX_TRACEBACK_WIDTH))  # Make rich exception tracebacks the default.
        logger = setup_rich_logger(module_name=__name__, logger_name='user', verbose=args.verbose, console=console)

    else:
        logger = setup_logger(module_name=__name__, logger_name="user", verbose=args.verbose)

    client = get_client(args, logger)
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, logger))

    Commands(logger, client, args, console, spinner)()

    if cli_config == 'rich':
        spinner.stop()

    if console.is_terminal and not args.no_pager:
        command_output = console.end_capture()
        if command_output != '':
            signal.signal(signal.SIGINT, signal.SIG_IGN)  # Do not allow the user to
            pager(command_output)
