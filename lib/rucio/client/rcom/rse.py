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
import json
from typing import TYPE_CHECKING, Any, Optional, Union

from rucio.client.rcom.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class RSE(CLIClientBase):
    SUBCOMMAND_NAMES = ["attribute", "protocol", "distance", "limit", "qos-policy", "usage"]

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]"):
        parser = super().parser(subparser)
        parser.add_argument("--rse-expression")
        parser.add_argument("--rse")
        parser.add_argument("--info", action="store_true", help="View extended information about the RSE")
        parser.add_argument("--key", help="Key")
        parser.add_argument("--value")
        parser.add_argument("--deterministic", action="store_true")

        # Add the subcommands
        parser.add_argument("subcommand", nargs="?", choices=self.SUBCOMMAND_NAMES, default=None)
        RSEAttribute(client=None, args=None, logger=None).parser(parser)  # type: ignore
        RSEProtocol(client=None, args=None, logger=None).parser(parser)  # type: ignore
        RSEDistance(client=None, args=None, logger=None).parser(parser)  # type: ignore
        RSELimit(client=None, args=None, logger=None).parser(parser)  # type: ignore
        RSEQOSPolicy(client=None, args=None, logger=None).parser(parser)  # type: ignore
        RSEUsage(client=None, args=None, logger=None).parser(parser)  # type: ignore

    def module_help(self) -> str:
        return f"Add, remove or view Rucio Storage Elements \n Subcommands: {self.SUBCOMMAND_NAMES}"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} list rse --rse RSE-1 # View all the RSE's that match the rse expression RSE-1",
            f"$ {self.COMMAND_NAME} list rse --rse RSE-ID_12345 --info # View extended information about a specific RSE",
            f"$ {self.COMMAND_NAME} add rse --rse RSE_1D_56789 # Add a new RSE ",
            f"$ {self.COMMAND_NAME} remove rse --rse RSE_ID_12345 # Remove the other RSE",
        ]

    def list(self) -> Union[dict[str, Any], list[dict[str, Any]]]:
        if self.args.rse is not None:
            expression = self.args.rse
        else:
            expression = self.args.rse_expression

        if not self.args.info:
            return [rse for rse in self.client.list_rses(rse_expression=expression)]
        else:
            rse_info = [i for i in self.client.get_rse(rse=expression)]
            attributes = [i for i in self.client.list_rse_attributes(rse=expression)]
            usage = [i for i in self.client.get_rse_usage(rse=expression)]
            rse_limits = [i for i in self.client.get_rse_limits(expression)]

        total_info = []
        for index, rse in enumerate(rse_info):
            rse_dict = {"rse": rse}
            try:
                rse_dict |= attributes[index]
            except (IndexError, ValueError):
                pass  # Can just be the rse name if there are no attributes
            try:
                rse_dict |= usage[index]
            except IndexError:
                pass
            try:
                rse_dict |= rse_limits[index]
            except IndexError:
                pass

            total_info.append(rse_dict)
        return total_info

    def add(self) -> None:
        self.client.add_rse(self.args.rse, deterministic=self.args.deterministic)
        self.logger.info(f'Added new {"non-" if not self.args.deterministic else ""}deterministic RSE: {self.args.rse}')

    def remove(self) -> None:
        self.client.delete_rse(self.args.rse)
        self.logger.info("Successfully removed RSE")

    def set(self) -> None:
        if self.args.value in ["true", "True", "TRUE", "1"]:
            value = True
        elif self.args.value in ["false", "False", "FALSE", "0"]:
            value = False
        else:
            value = self.args.value

        params = {self.args.key: value}
        self.client.update_rse(self.args.rse, parameters=params)
        self.logger.info(f"Updated RSE {self.args.rse} settings {self.args.key} to {value}")


class RSEAttribute(CLIClientBase):
    PARSER_NAME = "attribute"

    def parser(self, subparser: "ArgumentParser"):
        self.subcommand_parser(subparser)

    def module_help(self) -> str:
        return "Change the attributes of an RSE."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add rse attribute --rse RSE-1 --key key --value value # Add a new attribute to the RSE", f"$ {self.COMMAND_NAME} remove rse attribute --rse RSE-1 --key key # Remove that attribute"]

    def remove(self) -> None:
        self.client.delete_rse_attribute(rse=self.args.rse, key=self.args.key)
        self.logger.info(f"Removed RSE attribute {self.args.rse}:{self.args.key}")

    def add(self) -> None:
        self.client.add_rse_attribute(rse=self.args.rse, key=self.args.key, value=self.args.value)
        self.logger.info(f"Added RSE attribute for {self.args.rse}:{self.args.key}={self.args.value}")

    def list(self) -> dict[str, str]:
        return self.client.list_rse_attributes(rse=self.args.rse)


class RSEProtocol(CLIClientBase):
    PARSER_NAME = "protocol"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--host-name", help="Endpoint hostname")
        parser.add_argument("--scheme", choices=["srm", "gsiftp", "file"], help="Endpoint URL scheme")
        parser.add_argument("--port", help="URL Port", type=int)
        parser.add_argument("--implementation", default="rucio.rse.protocols.gfal.Default", help="Transfer protocol implementation to use")
        parser.add_argument(
            "--prefix",
            help="Endpoint URL path prefix",
        )
        parser.add_argument("--domain-json", help="JSON describing the WAN / LAN setup", type=str)
        parser.add_argument("--extended-attr-json", help="JSON describing any extended attributes")
        parser.add_argument("--web-service-path", help="Web service URL (SRM-only)")
        parser.add_argument("--space-token", help="Space token name (SRM-only)")

    def module_help(self) -> str:
        return "Modify or view a protocol and its settings for an RSE."

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rse protocol --host-name jdoes.test.org --scheme gsiftp --prefix /atlasdatadisk/rucio/ --port 8443 --rse RSE-T5 # Add a new protocol",
            f"$ {self.COMMAND_NAME} add rse protocol --host-name jdoes.test.org --port 8443 --rse RSE-T5 # Remove protocols from port 8443",
            f"$ {self.COMMAND_NAME} list rse protocol --rse RSE-T5  # List all active protocols on the rse",
        ]

    def add(self) -> None:
        if self.args.scheme == "srm" and not self.args.web_service_path:
            raise ValueError("Error: space-token and web-service-path must be provided for SRM endpoints.")

        protocol = {"hostname": self.args.host_name, "scheme": self.args.scheme, "port": self.args.port, "impl": self.args.implementation, "prefix": self.args.prefix}
        if self.args.domain_json:
            protocol["domains"] = json.loads(self.args.domain_json)
            self.logger.debug(f"Using domain json: {self.args.domain_json}")

        extended_attributes = {}
        if self.args.extended_attr_json:
            extended_attributes = self.args.extended_attr_json

        if self.args.space_token:
            extended_attributes["space_token"] = self.args.space_token
        if self.args.web_service_path:
            extended_attributes["web_service_path"] = self.args.web_service_path
        if extended_attributes is not {}:
            protocol["extended_attributes"] = extended_attributes

        self.client.add_protocol(self.args.rse, protocol)

    def remove(self) -> None:
        kwargs = {}
        if self.args.port:
            kwargs["port"] = self.args.port
        if self.args.host_name:
            kwargs["hostname"] = self.args.host_name

        self.client.delete_protocols(self.args.rse, self.args.scheme, **kwargs)
        self.logger.info(f"Deleted {self.args.scheme} protocol for {self.args.rse}")

    def list(self) -> list[dict[str, str]]:
        return [i for i in self.client.get_protocols(rse=self.args.rse)]


class RSEDistance(CLIClientBase):
    PARSER_NAME = "distance"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--destination", help="Destination RSE name")
        parser.add_argument("--distance", help="Distance between RSE and destination")

    def module_help(self) -> str:
        return "View or modify the distance information between a pair of RSEs."

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rse distance --rse RSE-T0 --destination RSE-T3 --distance 4 # Add a new distance between RSE-T0 and RSE-T3 ",
            f"$ {self.COMMAND_NAME} list rse distance --rse RSE-T0 --destination RSE-T3 # View the distance between",
            f"$ {self.COMMAND_NAME} set rse distance --rse RSE-T0 --destination RSE-T3 --distance 1 # Update an existing distance ",
        ]

    def list(self) -> Optional[dict[str, str]]:
        distance_info = self.client.get_distance(self.args.rse, self.args.destination)
        if distance_info:
            return {"source": self.args.rse, "destination": self.args.destination, "distance": distance_info[0]["distance"]}
        else:
            self.logger.warning(f"No distance set from {self.args.rse} to {self.args.destination}")

    def add(self) -> None:
        if self.args.distance is None:
            raise ValueError("Distance a required argument to add distances")
        self.client.add_distance(self.args.rse, self.args.destination, {"distance": self.args.distance})
        self.logger.info(f"Distance from {self.args.rse} to {self.args.destination} is set to {self.args.distance}")

    def remove(self) -> None:
        self.client.delete_distance(self.args.rse, self.args.destination)
        self.logger.info(f"Deleted distance information from {self.args.rse} to {self.args.destination}.")

    def set(self) -> None:
        if self.args.distance is None:
            raise ValueError("Distance a required argument to update distances")
        self.client.update_distance(self.args.rse, self.args.destination, parameters={"distance": self.args.distance})
        self.logger.info(f"Distance from {self.args.rse} to {self.args.destination} is set to {self.args.distance}")


class RSELimit(CLIClientBase):
    PARSER_NAME = "limit"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--name", help="Parameter to limit")
        parser.add_argument("--limit", help="Limit value", type=int)

    def module_help(self) -> str:
        return "Modify an RSE Limit"

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add rse limit --rse RSE-T4 --name XRD1 MinFreeSpace  --limit 10000", f"$ {self.COMMAND_NAME} remove rse limit --rse RSE-T4 --name XRD1 MinFreeSpace "]

    def add(self) -> None:
        self.client.set_rse_limits(self.args.rse, self.args.name, self.args.limit)
        if self.client.set_rse_limits(self.args.rse, self.args.name, self.args.limit):
            self.logger.info(f"Set RSE limit successfully for {self.args.rse}, {self.args.name} = {self.args.limit})")
        else:
            raise RuntimeError(f"Failed to set RSE limit for {self.args.rse}")

    def remove(self) -> None:
        names = self.client.get_rse_limits(self.args.rse).keys()
        if self.args.name not in names:
            raise ValueError(f"Limit {self.args.name} not defined in RSE {self.args.rse}")
        else:
            if self.client.delete_rse_limits(self.args.rse, self.args.name):
                self.logger.info(f"Deleted RSE limit {self.args.name} successfully for {self.args.rse}")
            else:
                raise RuntimeError(f"Failed to remove RSE limit {self.args.name} for {self.args.rse}")


class RSEQOSPolicy(CLIClientBase):
    PARSER_NAME = "qos-policy"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--qos_policy", help="QoS Policy")

    def module_help(self) -> str:
        return "View or modify QoS policies of an RSE."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add rse qos-policy --rse RSE-T0 --qos_policy SLOW_BUT_CHEAP", f"$ {self.COMMAND_NAME} remove rse qos-policy --rse RSE-T0 --qos_policy SLOW_BUT_CHEAP"]

    def add(self) -> None:
        self.client.add_qos_policy(self.args.rse, self.args.qos_policy)
        self.logger.info("Added QoS policy to RSE {self.args.rse}: {self.args.qos_policy}")

    def remove(self) -> None:
        self.client.delete_qos_policy(self.args.rse, self.args.qos_policy)
        self.logger.info(f"Deleted QoS policy from RSE {self.args.rse}: {self.args.qos_policy}")

    def list(self) -> list[dict[str, str]]:
        return [i for i in self.client.list_qos_policies(self.args.rse)]


class RSEUsage(CLIClientBase):
    PARSER_NAME = "usage"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--show-accounts", action="store_true", help="List accounts usages of RSE")

    def module_help(self) -> str:
        return "Show the total/free/used space for a given RSE. This values can differ for different RSE source."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} --format json list rse usage --rse RSE-T1"]

    def list(self) -> list[dict[str, Any]]:
        if self.args.rse is not None:
            expression = self.args.rse
        else:
            expression = self.args.rse_expression

        all_usages = self.client.get_rse_usage(rse=expression, filters={"per_account": self.args.show_accounts})
        select_usages = [u for u in all_usages if u["source"] not in ("srm", "gsiftp", "webdav")]  # Ignore the utilities

        usage_results = []

        for usage in select_usages:
            if self.args.show_accounts:
                # Make a new entry for each account
                for account_stats in usage["account_usages"]:
                    if account_stats == {}:
                        account_stats = {"used": 0, "percent": 0, "account": "Not Used"}
                    account_usage = {**usage, **account_stats}  # Combine the dictionaries

                    del account_usage["account_usage"]  # Remove the list of usages
                    usage_results.append(account_usage)

            else:
                usage_results.append(usage)

        return usage_results
