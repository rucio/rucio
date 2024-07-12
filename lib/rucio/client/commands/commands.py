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
import csv
import io
import json
import os
import sys
import time
from configparser import NoOptionError, NoSectionError
from typing import Any, Optional, Union

from tabulate import tabulate

from rucio import version
from rucio.client.client import Client
from rucio.client.commands.account import Account, AccountAttribute, AccountBan, AccountIdentities, AccountLimits
from rucio.client.commands.config import Config
from rucio.client.commands.did import DID, DIDAttachment, DIDHistory, DIDMetadata
from rucio.client.commands.download import Download
from rucio.client.commands.lifetime_exception import LifetimeException
from rucio.client.commands.replica import Replica, ReplicaPFN, ReplicaState, ReplicaTombstone
from rucio.client.commands.rse import RSE, RSEAttribute, RSEDistance, RSELimit, RSEProtocol, RSEQOSPolicy, RSEUsage
from rucio.client.commands.rule import Rule
from rucio.client.commands.scope import Scope
from rucio.client.commands.subscription import Subscription
from rucio.client.commands.upload import Upload
from rucio.client.commands.utils import exception_handler
from rucio.common.config import config_get
from rucio.common.exception import CannotAuthenticate
from rucio.common.extra import import_extras
from rucio.common.utils import setup_logger

EXTRA_MODULES = import_extras(["argcomplete"])

if EXTRA_MODULES["argcomplete"]:
    import argcomplete  # pylint: disable=E0401

SUCCESS = 0
FAILURE = 1


# TODO auto-generate this
COMMAND_MAP = {
    "account": {key: item for key, item in zip([None, "attribute", "limits", "ban", "identities"], [Account, AccountAttribute, AccountLimits, AccountBan, AccountIdentities])},
    "config": {None: Config},
    "did": {key: item for key, item in zip([None, "attachment", "history", "metadata"], [DID, DIDAttachment, DIDHistory, DIDMetadata])},
    "replica": {key: item for key, item in zip([None, "state", "pfn", "tombstone"], [Replica, ReplicaState, ReplicaPFN, ReplicaTombstone])},
    "rse": {key: item for key, item in zip([None, "usage", "distance", "attribute", "protocol", "limit", "qos-policy"], [RSE, RSEUsage, RSEDistance, RSEAttribute, RSEProtocol, RSELimit, RSEQOSPolicy])},
    "scope": {None: Scope},
    "subscription": {None: Subscription},
    "lifetime-exception": {None: LifetimeException},
    "rule": {None: Rule},
}


class Commands:
    def __init__(self, args) -> None:
        self.logger = setup_logger(module_name=__name__, logger_name="user", verbose=args.verbose)

        self.verb = args.verb if args.verb is not None else "list"
        self.command = args.command
        self.subcommand = None if not hasattr(args, "subcommand") else args.subcommand

        self.args = args
        self.client = None
        # self.client = self.get_client()

    @staticmethod
    def parse_command():
        main_parser = argparse.ArgumentParser()

        Commands.main_arguments(main_parser)
        Commands.auth_arguments(main_parser)

        # Verbs
        # TODO documentation table
        main_parser.add_argument(
            "verb",
            choices={"add", "remove", "set", "unset", "list"},
            nargs="?",
            default=None,
            help="Type of operation to execute. See <Table I'll link somewhere> for details."
        )

        # Main Commands:
        subparsers = main_parser.add_subparsers(
            dest="command",
            help="Command to execute, see `{command} -h` for more details and subcommands."
        )

        # Outlier Commands:
        subparsers.add_parser("ping", help="Ping the server")
        subparsers.add_parser("whoami", help="Get information about account whose token is used.")

        Download(client=None, args=None, logger=None).parser(subparsers)  # type: ignore
        Upload(client=None, args=None, logger=None).parser(subparsers)  # type: ignore

        # Add the parser for each verb/command
        for command in COMMAND_MAP.keys():
            # Ensure the main command shows up first
            base_command = COMMAND_MAP[command][None]
            base_command(client=None, args=None, logger=None).parser(subparsers)  # type: ignore

        return main_parser

    @staticmethod
    def main_arguments(parser_object):
        main_args = parser_object.add_argument_group("Main Arguments")

        main_args.add_argument("--version", action="version", version='%(prog)s ' + version.version_string())
        main_args.add_argument("--config", help="The Rucio configuration file to use.")
        main_args.add_argument("--verbose", "-v", default=False, action="store_true", help="Print more verbose output.")
        main_args.add_argument("-H", "--host", metavar="ADDRESS", help="The Rucio API host.")
        main_args.add_argument("--auth-host", metavar="ADDRESS", help="The Rucio Authentication host.")
        main_args.add_argument("-a", "--account", dest='issuer', metavar="ACCOUNT", help="Rucio account to use.")
        main_args.add_argument("-S", "--auth-strategy", help="Authentication strategy (userpass, x509...)")
        main_args.add_argument("-T", "--timeout", type=float, help="Set all timeout values to seconds.")
        main_args.add_argument("--user-agent", "-U", dest="user_agent", default="rucio-clients", help="Rucio User Agent")
        main_args.add_argument("--vo", metavar="VO", help="VO to authenticate at. Only used in multi-VO mode.")
        main_args.add_argument("--view", help='Which type of view to use', default=None, choices={None, "history", "info"})
        # TODO Change default to rich once rich tables are implemented
        # TODO Documentation table
        main_args.add_argument(
            "--format",
            default="json",
            choices={"text", "rich", "json", "csv"},
            help=argparse.SUPPRESS)

    @staticmethod
    def auth_arguments(parser_object):
        auth_args = parser_object.add_argument_group("Authentication Settings")

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
            help="Max lifetime in hours for this an access token will be refreshed by asynchronous Rucio daemon. "
            + "If not specified, refresh will be stopped after 4 days. This option is effective only if --oidc-scope includes offline_access scope for a refresh token to be granted to Rucio.",
        )  # NOQA: W503
        auth_args.add_argument("--oidc-issuer", help="Defines which Identity Provider is going to be used. The issuer string must correspond " + "to the keys configured in the /etc/idpsecrets.json auth server configuration file.")  # NOQA: W503

        # Options for the x509  auth_strategy
        auth_args.add_argument("--certificate", help="Client certificate file.")
        auth_args.add_argument("--ca-certificate", help="CA certificate to verify peer against (SSL).")

    def get_client(self):
        if not self.args.auth_strategy:
            if "RUCIO_AUTH_TYPE" in os.environ:
                auth_type = os.environ["RUCIO_AUTH_TYPE"].lower()
            else:
                try:
                    auth_type = config_get("client", "auth_type").lower()
                except (NoOptionError, NoSectionError):
                    self.logger.error("Cannot get AUTH_TYPE")
                    sys.exit(FAILURE)
        else:
            auth_type = self.args.auth_strategy.lower()

        if auth_type in ["userpass", "saml"] and self.args.username is not None and self.args.password is not None:
            creds = {"username": self.args.username, "password": self.args.password}
        elif auth_type == "oidc":
            if self.args.oidc_issuer:
                self.args.oidc_issuer = self.args.oidc_issuer.lower()
            creds = {
                "oidc_auto": self.args.oidc_auto,
                "oidc_scope": self.args.oidc_scope,
                "oidc_audience": self.args.oidc_audience,
                "oidc_polling": self.args.oidc_polling,
                "oidc_refresh_lifetime": self.args.oidc_refresh_lifetime,
                "oidc_issuer": self.args.oidc_issuer,
                "oidc_username": self.args.oidc_username,
                "oidc_password": self.args.oidc_password,
            }
        else:
            creds = None

        try:
            client = Client(
                rucio_host=self.args.host,
                auth_host=self.args.auth_host,
                account=self.args.issuer,
                auth_type=auth_type,
                creds=creds,
                ca_cert=self.args.ca_certificate,
                timeout=self.args.timeout,
                user_agent=self.args.user_agent,
                vo=self.args.vo,
                logger=self.logger,
            )

        except CannotAuthenticate as error:
            self.logger.error(error)
            if "alert certificate expired" in str(error):
                self.logger.error("The server certificate expired.")
            elif auth_type.lower() == "x509_proxy":
                self.logger.error("Please verify that your proxy is still valid and renew it if needed.")
            sys.exit(FAILURE)

        return client

    def ping(self):
        """
        Pings a Rucio server.
        """
        server_info = self.get_client().ping()
        if server_info:
            print(server_info["version"])
        else:
            self.logger.error("Ping failed")

    def whoami(self):
        """
        Show extended information of a given account
        """
        client = self.get_client()
        info = client.whoami()
        for k in info:
            print(k.ljust(10) + ' : ' + str(info[k]))
        return SUCCESS

    def run_command(self) -> tuple[int, Optional[Union[dict[str, Any], list[dict[str, Any]]]]]:
        oddball_commands = {
            "ping": self.ping,
            "whoami": self.whoami,
            "upload": Upload(self.client, self.args, self.logger),  # type: ignore
            "download": Download(self.client, self.args, self.logger)  # type: ignore
        }
        if self.command in oddball_commands.keys():
            return exception_handler(oddball_commands[self.command], logger=self.logger)()

        else:
            try:
                command_class = COMMAND_MAP[self.command][self.subcommand]
            except KeyError as e:
                if self.command is not None:
                    self.logger.error(f"Cannot find command/subcommand pair: {e}")
                sys.exit(FAILURE)

            return exception_handler(command_class(self.client, self.args, self.logger), logger=self.logger)(self.verb)

    def select_output(self, result):
        # TODO Future release
        return result

    def format_output(self, result):
        format = self.args.format
        formatted_result = {"json": _IOFormat.json, "csv": _IOFormat.csv, "rich": _IOFormat.rich, "text": _IOFormat.text}[format](result)

        print(formatted_result)

    def __call__(self):
        start_time = time.time()
        self.run_command()
        end_time = time.time()

        if self.args.verbose:
            print("Completed in %-0.4f sec." % (end_time - start_time))


class _IOFormat:
    @staticmethod
    def json(result: Union[dict[str, Any], list[dict[str, Any]]]):
        return json.dumps(result, default=str)

    @staticmethod
    def csv(result: Union[dict[str, Any], list[dict[str, Any]]]):
        string_output = io.StringIO()
        if isinstance(result, dict):
            result = [result]

        writer = csv.DictWriter(string_output, result[0].keys())
        writer.writeheader()
        for row in result:
            writer.writerow(row)
        return string_output.getvalue()

    @staticmethod
    def rich(result: Union[dict[str, Any], list[dict[str, Any]]]):
        raise NotImplementedError

    @staticmethod
    def text(result: Union[dict[str, Any], list[dict[str, Any]]]):
        table = []
        if isinstance(result, dict):
            result = [result]
        for row in result:
            table.append([value for value in row.values()])
        return tabulate(table, tablefmt="psql", headers=list(result[0].keys()))


def main():
    parser_object = Commands.parse_command()
    if EXTRA_MODULES["argcomplete"]:
        argcomplete.autocomplete(parser_object)

    args = parser_object.parse_args()
    if args.config is not None:
        os.environ["RUCIO_CONFIG"] = args.config

    if args.command is None:
        parser_object.print_help()
        sys.exit(FAILURE)

    Commands(args)()


if __name__ == "__main__":
    main()
