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

from rucio.client.bin.rucio import list_account_limits, list_account_usage
from rucio.client.bin.rucio_admin import (
    add_account,
    add_account_attribute,
    ban_account,
    delete_account,
    delete_account_attribute,
    delete_limits,
    identity_add,
    identity_delete,
    info_account,
    list_account_attributes,
    list_accounts,
    list_identities,
    set_limits,
    unban_account,
    update_account,
)
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Account(CLIClientBase):
    PARSER_NAME = "account"
    SUBCOMMAND_NAMES = ["attribute", "limits", "ban", "identities"]

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)

        parser.add_argument("--account-name", dest="account", help="Account name", default=None)

        # Each command arguments
        parser.add_argument("--type", dest="account_type", choices=[None, "USER", "GROUP", "SERVICE"], help="Account Type", default="USER")
        parser.add_argument("--id", dest="identity", help="Identity (e.g. DN)", default=None)
        parser.add_argument("--filters", dest="filters", help="Filter arguments in form `key=value,another_key=next_value`")
        parser.add_argument("--email", dest="accountemail", help="Email address associated with the account")
        parser.add_argument("--key", dest="key", help="Key to Update")
        parser.add_argument("--value", dest="value", help="Value to put in key")

        # Nest the other group
        parser.add_argument("subcommand", nargs="?", choices=self.SUBCOMMAND_NAMES, help="Fine grain control of accounts")
        AccountAttribute(client=None, args=None, logger=None).parser(parser)  # type: ignore
        AccountBan(client=None, args=None, logger=None).parser(parser)  # type: ignore
        AccountLimits(client=None, args=None, logger=None).parser(parser)  # type: ignore
        AccountIdentities(client=None, args=None, logger=None).parser(parser)  # type: ignore

    def module_help(self) -> str:
        return f"Modify or view an account. Subcommands: {self.SUBCOMMAND_NAMES}"

    def usage_example(self) -> list[str]:
        add_cmd = f"$ {self.COMMAND_NAME} add account --account-name jdoe --type USER  # Add jdoe as a new user account"
        list_cmd = f"$ {self.COMMAND_NAME} list account --accounttype USER # Show all existing user accounts"
        set_cmd = f"$ {self.COMMAND_NAME} set account --account-name jdoe --key email --value jdoe@email.com # Update jdoe's email"
        remove_cmd = f"$ {self.COMMAND_NAME} remove account --account-name jdoe --type USER # Remove jdoe"
        return [add_cmd, list_cmd, set_cmd, remove_cmd]

    def set(self):
        return update_account(self.args, self.logger)

    def remove(self):
        return delete_account(self.args, self.logger)

    def add(self):
        self.args.accounttype = self.args.account_type
        return add_account(self.args, self.logger)

    def list(self):
        if self.args.view == 'history':
            self.args.usage_account = self.args.account
        return {
            None: list_accounts,
            "history": list_account_usage,
            "info": info_account
        }[self.args.view](self.args, self.logger)


class AccountAttribute(CLIClientBase):
    PARSER_NAME = "attribute"

    def module_help(self) -> str:
        return "Modify the attributes of a specific account."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add account attribute --account-name jdoe --attr_key admin --attr_value true"]

    def parser(self, subparser: "ArgumentParser") -> None:
        attribute_group = super().subcommand_parser(subparser)
        attribute_group.add_argument("--attr-key", dest="key", help="Attribute key")
        attribute_group.add_argument("--attr-value", dest="value", help="Attribute value")

    def list(self):
        return list_account_attributes(self.args, self.logger)

    def add(self):
        return add_account_attribute(self.args, self.logger)

    def remove(self):
        return delete_account_attribute(self.args, self.logger)


class AccountBan(CLIClientBase):
    PARSER_NAME = "ban"

    def parser(self, subparser: "ArgumentParser") -> None:
        super().subcommand_parser(subparser)

    def module_help(self) -> str:
        return "Ban or un-ban a user."

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} set account ban --account-name jdoe # Ban jdoe",
            f"$ {self.COMMAND_NAME} unset account ban --account-name jdoe # Remove the ban on jdoe"
        ]

    def set(self):
        return ban_account(self.args, self.logger)

    def unset(self):
        return unban_account(self.args, self.logger)


class AccountIdentities(CLIClientBase):
    PARSER_NAME = "identities"

    def module_help(self) -> str:
        return "View or modify an identity access to an account."

    def usage_example(self) -> list[str]:
        add_cmd = f"$ {self.COMMAND_NAME} add account identities --account-name jdoe --email jdoe@email.com --auth-type GSS --identity 'jdoe@email.com'"
        list_cmd = f"$ {self.COMMAND_NAME} list account identities --account-name jdoe"
        return [add_cmd, list_cmd]

    def parser(self, subparser: "ArgumentParser") -> None:
        identities_group = super().subcommand_parser(subparser)

        identities_group.add_argument("--auth-type", dest="auth_type", help="'Authentication type", choices=["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"])
        identities_group.add_argument("--password", dest="password", help="[Optional] Password for the identity if `userpass` is used as the auth method")
        identities_group.add_argument("--identity", dest="identity", help="Identity")  # TODO Good description of identities

    def add(self):
        return identity_add(self.args, self.logger)

    def remove(self):
        return identity_delete(self.args, self.logger)

    def list(self):
        if self.args.account is None:
            raise ValueError
        return list_identities(self.args, self.logger)


class AccountLimits(CLIClientBase):
    PARSER_NAME = "limits"

    def module_help(self) -> str:
        return "View or modify limits for rse, by specific account."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add account limits --account-name jdoe --rse DESY-ZN_DATADISK --bytes 1.00TB"]

    def parser(self, subparser: "ArgumentParser") -> None:
        limits_group = super().subcommand_parser(subparser)

        limits_group.add_argument("--rse", dest="rse", help="RSE boolean expression")
        limits_group.add_argument("--bytes", dest="bytes", help='Value can be specified in bytes ("10000"), with a storage unit ("10GB"), or "infinity"')
        limits_group.add_argument("--locality", dest="locality", choices=["local", "global"], help="Global or local limit scope", default="local")
        limits_group.add_argument("--human", action='store_true', help="Return as human readable")

    def list(self):
        self.args.limit_account = self.args.account
        return list_account_limits(self.args, self.logger)

    def remove(self):
        return delete_limits(self.args, self.logger)

    def add(self):
        return set_limits(self.args, self.logger)
