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
from argparse import SUPPRESS
from typing import TYPE_CHECKING, Optional

from rucio.client.commands.bin_legacy.rucio import list_account_usage
from rucio.client.commands.bin_legacy.rucio_admin import (
    add_account,
    add_account_attribute,
    ban_account,
    delete_account,
    delete_account_attribute,
    delete_limits,
    get_limits,
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
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace
    from logging import Logger

    from rucio.client.client import Client
    from rucio.client.commands.utils import OperationDict


class Account(CommandBase):
    def __init__(self, client: Optional["Client"], args: Optional["Namespace"], logger: Optional["Logger"]) -> None:
        super().__init__(client, args, logger)

    def module_help(self) -> str:
        return "Methods to add or change accounts for users, groups, and services. Used to assign privileges."

    def usage_example(self) -> list[str]:
        return [
            "$ rucio account  # List all accounts on the instance" "$ rucio account add --account user_jdoe --type USER  # Create a new user account",
            "$ rucio account set --account user_jdoe --key email --value jdoe@cern.ch  # Update jdoe's email",
            "$ rucio account usage --account root  # Show all the usage history for the account root",
        ]

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--type", dest="account_type", default="USER", help="Account Type", choices={"USER", "GROUP", "SERVICE"})
        parser.add_argument("-a", "--account", dest="account", help="Account name")
        parser.add_argument("--id", dest="identity", action="store", help="Identity (e.g. DN)")
        parser.add_argument("--filters", dest="filters", action="store", help="Filter arguments in form `key=value,another_key=next_value`")

    def add_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--type", dest="accounttype", default="USER", help="Account Type (USER, GROUP, SERVICE)")
        parser.add_argument("-a", "--account", dest="account", help="Account name")
        parser.add_argument("--email", dest="accountemail", help="Add an email address associated with the account")

    def info_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--type", dest="accounttype", default="USER", help="Account Type (USER, GROUP, SERVICE)")
        parser.add_argument("-a", "--account", dest="account", help="Account name")

    def set_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", help="Account name", required=True)
        parser.add_argument("--key", help="Account parameter", required=True)
        parser.add_argument("--value", help="Account parameter value", required=True)

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", dest="acnt", action="store", help="Account name")

    def usage_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", dest="usage_account", help="Account name.")
        parser.add_argument("-r", "--rse", help="Show usage for only for this RSE.")
        parser.add_argument("--human", default=True, help=SUPPRESS)

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "List accounts.", "namespace": self.list_namespace},
            "add": {"call": self.add, "docs": "Add a new account.", "namespace": self.add_namespace},
            "info": {"call": self.info, "docs": "Get all stats on an account, including status, account type, and dates of creation and updates.", "namespace": self.info_namespace},
            "remove": {"call": self.remove, "docs": "Delete an account.", "namespace": self.remove_namespace},
            "usage": {"call": self.usage, "docs": "See historical usage for an account", "namespace": self.usage_namespace},
            "set": {"call": self.set_, "docs": "Change the basic account settings.", "namespace": self.set_namespace},
        }

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {"ban": Ban, "attribute": Attribute, "limit": Limit, "identity": Identity}

    def default_operation(self):
        return self.list_

    def list_(self):
        list_accounts(self.args, self.client, self.logger)

    def add(self):
        add_account(self.args, self.client, self.logger)

    def remove(self):
        delete_account(self.args, self.client, self.logger)

    def info(self):
        info_account(self.args, self.client, self.logger)

    def usage(self):
        list_account_usage(self.args, self.client, self.logger)

    def set_(self):
        update_account(self.args, self.client, self.logger)


class Ban(Account):
    def __init__(self, client: Optional["Client"], args: Optional["Namespace"], logger: Optional["Logger"]) -> None:
        super().__init__(client, args, logger)

    def ban_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--account", help="Account to ban or un-ban")

    def module_help(self) -> str:
        return "Disable an account. In case of accidental ban, use `$ rucio account ban remove`"

    def usage_example(self) -> list[str]:
        return [
            "$ rucio account ban add --account jdoe  # Ban jdoe",
            "$ rucio account ban remove --account jdoe  # Un-Ban jdoe",
        ]

    def default_operation(self):
        return self.add

    def _operations(self) -> dict[str, "OperationDict"]:
        return {"add": {"call": self.add, "docs": "Ban an account", "namespace": self.ban_namespace}, "remove": {"call": self.remove, "docs": "Un-ban an account", "namespace": self.ban_namespace}}

    def add(self):
        ban_account(self.args, self.client, self.logger)

    def remove(self):
        unban_account(self.args, self.client, self.logger)


class Attribute(Account):
    def __init__(self, client: Optional["Client"], args: Optional["Namespace"], logger: Optional["Logger"]) -> None:
        super().__init__(client, args, logger)

    def module_help(self) -> str:
        return "Add additional key/value pairs associated with an account for organizational purposes."

    def default_operation(self):
        raise NotImplementedError

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def namespace(self, subparser):
        subparser.add_argument("-a", "--account", help="Account name")
        subparser.add_argument("--key", dest="key", action="store", help="Attribute key")
        subparser.add_argument("--value", dest="value", action="store", help="Attribute value")

    def usage_example(self) -> list[str]:
        return ["$ rucio account attribute list --account jdoe  # Show all attributes for jdoe", "$ rucio -v account attribute add --account jdoe --key test_key --value true  # Set test_key = true for jdoe"]

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "List all account attributes."},
            "add": {"call": self.add, "docs": "Add a new attribute to an account or update an existing one."},
            "remove": {"call": self.remove, "docs": "Remove an existing account attribute."},
        }

    def list_(self):
        list_account_attributes(self.args, self.client, self.logger)

    def add(self):
        add_account_attribute(self.args, self.client, self.logger)

    def remove(self):
        delete_account_attribute(self.args, self.client, self.logger)


class Limit(Account):
    def __init__(self, client: Optional["Client"], args: Optional["Namespace"], logger: Optional["Logger"]) -> None:
        super().__init__(client, args, logger)

    def module_help(self) -> str:
        return "Manage storage limits for an account at a given RSE."

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", dest="account", help="Account name", required=True)
        parser.add_argument("-r", "--rse", action="store", help="RSE expression")
        parser.add_argument("--bytes", action="store", help='Value can be specified in bytes ("10000"), with a storage unit ("10GB"), or "infinity"')
        parser.add_argument("--locality", nargs="?", default="local", choices=["local", "global"], help="Global or local limit scope.")
        parser.add_argument("--human", default=True, help=SUPPRESS)

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show limits for an account at a given RSE.", "namespace": self.namespace},
            "add": {"call": self.add, "docs": "Add or update limits for an account.", "namespace": self.namespace},
            "remove": {"call": self.remove, "docs": "Remove all limits for given account/rse/locality.", "namespace": self.namespace},
        }

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def usage_example(self) -> list[str]:
        return super().usage_example()

    def default_operation(self):
        raise NotImplementedError

    def list_(self):
        get_limits(self.args, self.client, self.logger)

    def add(self):
        set_limits(self.args, self.client, self.logger)

    def remove(self):
        delete_limits(self.args, self.client, self.logger)


class Identity(Account):
    def __init__(self, client: Optional["Client"], args: Optional["Namespace"], logger: Optional["Logger"]) -> None:
        super().__init__(client, args, logger)

    def module_help(self) -> str:
        return "Manage identities (DNs) on an account."

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--account", dest="account", action="store", help="Account name", required=True)
        parser.add_argument("--type", dest="authtype", action="store", choices=["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"], help="Authentication type.")
        parser.add_argument("--id", dest="identity", action="store", help="Identity as a DNs, provide in quotes.")
        parser.add_argument("--email", dest="email", action="store", help="Email address associated with the identity")
        parser.add_argument("--password", dest="password", action="store", help="Password if authtype is USERPASS")
        parser.add_argument("--human", default=True, help=SUPPRESS)

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show existing DNs for an account.", "namespace": self.namespace},
            "add": {"call": self.add, "docs": "Grant identity access to an account.  Format IDs as 'KEY1=Value One,KEY2=Value Two' if DNs.", "namespace": self.namespace},
            "remove": {"call": self.remove, "docs": "Revoke identity access for an account.", "namespace": self.namespace},
        }

    def usage_example(self) -> list[str]:
        return [
            "$ rucio account identity list --account jdoe  # List all auth identities for jdoe",
            "$ rucio account identity add --account jdoe --type GSS --email jdoe@cern.ch --id jdoe@fnal.ch  # Add a new GSS auth",
            "$ rucio account identity add --account jdoe --type X509 --id 'CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch' --email jdoe@cern.ch  # Add a new X509 auth. Note the DN in quotes.",
        ]

    def default_operation(self):
        raise NotImplementedError

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def list_(self):
        list_identities(self.args, self.client, self.logger)

    def add(self):
        identity_add(self.args, self.client, self.logger)

    def remove(self):
        identity_delete(self.args, self.client, self.logger)
