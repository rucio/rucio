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

from rucio.client.rcom.base_command import CLIClientBase
from rucio.common.utils import get_bytes_value_from_string, sizefmt

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Account(CLIClientBase):
    PARSER_NAME = "account"
    SUBCOMMAND_NAMES = ["attribute", "limits", "ban", "identities"]

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)

        parser.add_argument("--account-name", dest=f"{self.PARSER_NAME}_name", help="Account name", default=None)

        # Each command arguments
        parser.add_argument("--type", dest=f"{self.PARSER_NAME}_type", choices=[None, "USER", "GROUP", "SERVICE"], help="Account Type", default="USER")
        parser.add_argument("--id", dest=f"{self.PARSER_NAME}_id", help="Identity (e.g. DN)", default=None)
        parser.add_argument("--filters", dest=f"{self.PARSER_NAME}_filters", help="Filter arguments in form `key=value,another_key=next_value`")
        parser.add_argument("--email", dest=f"{self.PARSER_NAME}_email", help="Email address associated with the account")
        parser.add_argument("--account-key", dest=f"{self.PARSER_NAME}_key", help="Key to Update")
        parser.add_argument("--account-value", dest=f"{self.PARSER_NAME}_value", help="Value to put in key")

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
        list_cmd = f"$ {self.COMMAND_NAME} list account --type USER # Show all existing user accounts"
        set_cmd = f"$ {self.COMMAND_NAME} set account --account-name jdoe --key email --value jdoe@email.com # Update jdoe's email"
        remove_cmd = f"$ {self.COMMAND_NAME} remove account --account-name jdoe --type USER # Remove jdoe"
        return [add_cmd, list_cmd, set_cmd, remove_cmd]

    def set(self) -> None:
        self.client.update_account(account=self.args.account_name, key=self.args.account_key, value=self.args.account_value)
        self.logger.info(f"Updated account {self.args.account_name}: {self.args.account_key} = {self.args.account_value}")

    def remove(self) -> None:
        self.client.delete_account(account=self.args.account_name)
        self.logger.info(f"Deleted account {self.args.account_name}")

    def add(self) -> None:
        self.client.add_account(account=self.args.account_name, type_=self.args.account_type, email=self.args.account_email)
        self.logger.info(f"Created account {self.args.account_name} with type {self.args.account_type}")

    def list(self) -> list[dict[str, str]]:
        applied_filters = {}
        if self.args.account_filters is not None:
            for key, value in [(_.split("=")[0], _.split("=")[1]) for _ in self.args.account_filters.split(",")]:
                applied_filters[key] = value
        accounts = self.client.list_accounts(identity=self.args.account_id, account_type=self.args.account_type, filters=self.args.account_filters)
        accounts = [account for account in accounts]
        return accounts


class AccountAttribute(CLIClientBase):
    PARSER_NAME = "attribute"

    def module_help(self) -> str:
        return "Modify the attributes of a specific account."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add account attribute --account-name jdoe --attr_key admin --attr_value true"]

    def parser(self, subparser: "ArgumentParser") -> None:
        attribute_group = super().subcommand_parser(subparser)
        attribute_group.add_argument("--attr-key", dest=f"{self.PARSER_NAME}_key", help="Attribute key")
        attribute_group.add_argument("--attr-value", dest=f"{self.PARSER_NAME}_value", help="Attribute value")

    def list(self) -> list[dict[str, str]]:
        account = self.args.account_name or self.client.account
        attributes = next(self.client.list_account_attributes(account))
        table = []
        for attr in attributes:
            table.append(attr)
        return table

    def add(self) -> None:
        self.client.add_account_attribute(account=self.args.account_name, key=self.args.attribute_key, value=self.args.attribute_value)
        self.logger.info(f"Updated account {self.args.account_name}: {self.args.attribute_key} = {self.args.attribute_value}")

    def remove(self) -> None:
        self.client.delete_account_attribute(
            account=self.args.account_name,
            key=self.args.attribute_key,
        )
        self.logger.info(f"Removed attribute {self.args.attribute_key} from account {self.args.account_name}")


class AccountBan(CLIClientBase):
    PARSER_NAME = "ban"

    def parser(self, subparser: "ArgumentParser") -> None:
        super().subcommand_parser(subparser)

    def module_help(self) -> str:
        return "Ban or un-ban a user."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} set account ban --account-name jdoe # Ban jdoe", f"$ {self.COMMAND_NAME} unset account ban --account-name jdoe # Remove the ban on jdoe"]

    def set(self) -> None:
        if self.args.account_name is None:
            self.logger.error("Supply an account to ban with --account-name")

        self.client.update_account(account=self.args.account_name, key="status", value="SUSPENDED")
        self.logger.info(f"Banned account {self.args.account_name}")

    def unset(self) -> None:
        self.client.update_account(account=self.args.account_name, key="status", value="ACTIVE")
        self.logger.info(f"Un-Banned account {self.args.account_name}")


class AccountIdentities(CLIClientBase):
    PARSER_NAME = "identities"

    def module_help(self) -> str:
        return "View or modify an identity access to an account."

    def usage_example(self) -> list[str]:
        add_cmd = f"$ {self.COMMAND_NAME} add account identities --account-name jdoe --email jdoe@email.com --auth-type GSS --identity 'jdoe@email.com'"
        list_cmd = f"$ {self.COMMAND_NAME} list account identities --account-namejdoe"
        return [add_cmd, list_cmd]

    def parser(self, subparser: "ArgumentParser") -> None:
        identities_group = super().subcommand_parser(subparser)

        # TODO Add account email back into help menu here
        # Right now it conflicts with the
        # attribute_group.add_argument("--email", dest=f"{self.PARSER_NAME}_email", action="store", help="Attribute key")

        identities_group.add_argument("--auth-type", dest=f"{self.PARSER_NAME}_auth_type", help="'Authentication type", choices=["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"])
        identities_group.add_argument("--password", dest=f"{self.PARSER_NAME}_password", help="[Optional] Password for the identity if `userpass` is used as the auth method")
        identities_group.add_argument("--identity", dest=f"{self.PARSER_NAME}_identity", help="Identity")  # TODO Good description of identities

    def add(self) -> None:
        if self.args.account_email is None:
            self.logger.error("Error: --email argument can't be an empty string. Failed to grant an identity access to an account")

        if self.args.identities_auth_type == "USERPASS" and not self.args.identities_password:
            self.logger.error("--password argument is required when using `USERPASS` for auth")

        self.client.add_identity(account=self.args.account_name, identity=self.args.identities_identity, authtype=self.args.identities_auth_type, email=self.args.account_email, password=self.args.identities_password)
        self.logger.info(f"Added identity {self.args.identities_identity} to {self.args.account_name}")

    def remove(self) -> None:
        self.client.del_identity(account=self.args.account_name, identity=self.args.identities_identity, authtype=self.args.identities_auth_type)
        self.logger.info(f"Removed identity {self.args.identities_identity} from {self.args.account_name}")

    def list(self) -> list[dict[str, str]]:
        identities = [i for i in self.client.list_identities(account=self.args.account_name)]
        return identities


class AccountLimits(CLIClientBase):
    PARSER_NAME = "limits"

    def module_help(self) -> str:
        return "View or modify limits for rse, by specific account."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add account limits --account-namejdoe --rse DESY-ZN_DATADISK --bytes 1.00TB"]

    def parser(self, subparser: "ArgumentParser") -> None:
        limits_group = super().subcommand_parser(subparser)

        limits_group.add_argument("--rse", dest=f"{self.PARSER_NAME}_rse", help="RSE boolean expression")
        limits_group.add_argument("--bytes", dest=f"{self.PARSER_NAME}_bytes", help='Value can be specified in bytes ("10000"), with a storage unit ("10GB"), or "infinity"')
        limits_group.add_argument("--locality", dest=f"{self.PARSER_NAME}_locality", choices=["local", "global"], help="Global or local limit scope", default="local")

    def list(self) -> list[dict[str, str]]:
        locality = self.args.limits_locality.lower()
        limits = self.client.get_account_limits(account=self.args.account_name, rse_expression=self.args.limits_rse, locality=locality)
        return [{"rse": rse, "bytes": limit} for rse, limit in limits.items()]

    def remove(self) -> None:
        locality = self.args.limits_locality.lower()
        self.client.delete_account_limit(account=self.args.account_name, rse=self.args.limits_rse, locality=locality)
        self.logger.info(f"Deleted account limit for account {self.args.account_name} and RSE {self.args.limits_rse}")

    def add(self) -> None:
        locality = self.args.limits_locality.lower()
        byte_limit = None
        limit_input = self.args.limits_bytes.lower()

        if limit_input == "inf" or limit_input == "infinity":
            byte_limit = -1
        else:
            byte_limit = get_bytes_value_from_string(limit_input)
            if not byte_limit:
                try:
                    byte_limit = int(limit_input)
                except ValueError:
                    self.logger.error(
                        "The limit could not be set. Either you misspelled infinity or your input could not be converted to integer or you used a wrong pattern. Please use a format like 10GB with B,KB,MB,GB,TB,PB as units (not case sensitive)"
                    )

        self.client.set_account_limit(account=self.args.account_name, rse=self.args.limits_rse, bytes_=byte_limit, locality=locality)
        self.logger.info(f"Set account limit for account {self.args.account_name} on RSE {self.args.limits_rse}: {sizefmt(byte_limit, True)}")
