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
from typing import TYPE_CHECKING

from rucio.client.bin.rucio import list_rse_usage, list_rses
from rucio.client.bin.rucio_admin import (
    add_distance_rses,
    add_protocol_rse,
    add_qos_policy,
    add_rse,
    del_protocol_rse,
    delete_attribute_rse,
    delete_distance_rses,
    delete_limit_rse,
    delete_qos_policy,
    disable_rse,
    get_attribute_rse,
    get_distance_rses,
    info_rse,
    list_qos_policies,
    set_attribute_rse,
    set_limit_rse,
    update_distance_rses,
    update_rse,
)
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class RSE(CLIClientBase):
    SUBCOMMAND_NAMES = ["attribute", "protocol", "distance", "limit", "qos-policy", "usage"]

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]"):
        parser = super().parser(subparser)
        parser.add_argument("--rse")
        parser.add_argument("--key", help="Key")
        parser.add_argument("--value")
        parser.add_argument("--non-deterministic", action="store_true")

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

    def list(self):
        self.args.rses = self.args.rse
        return {
            None: list_rses,
            "info": info_rse
        }[self.args.view](self.args, self.logger)

    def add(self):
        return add_rse(self.args, self.logger)

    def remove(self):
        return disable_rse(self.args, self.logger)

    def set(self):
        self.args.param = self.args.key

        return update_rse(self.args, self.logger)


class RSEAttribute(CLIClientBase):
    PARSER_NAME = "attribute"

    def parser(self, subparser: "ArgumentParser"):
        self.subcommand_parser(subparser)

    def module_help(self) -> str:
        return "Change the attributes of an RSE."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add rse attribute --rse RSE-1 --key key --value value # Add a new attribute to the RSE", f"$ {self.COMMAND_NAME} remove rse attribute --rse RSE-1 --key key # Remove that attribute"]

    def remove(self) -> None:
        delete_attribute_rse(self.args, self.logger)

    def add(self) -> None:
        set_attribute_rse(self.args, self.logger)

    def list(self) -> None:
        get_attribute_rse(self.args, self.logger)


class RSEProtocol(CLIClientBase):
    PARSER_NAME = "protocol"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--host-name", dest='hostname', help="Endpoint hostname")
        parser.add_argument("--scheme", choices=["srm", "gsiftp", "file"], help="Endpoint URL scheme")
        parser.add_argument("--port", help="URL Port", type=int)
        parser.add_argument("--impl", default="rucio.rse.protocols.gfal.Default", help="Transfer protocol implementation to use")
        parser.add_argument(
            "--prefix",
            help="Endpoint URL path prefix",
        )
        parser.add_argument("--domain-json", help="JSON describing the WAN / LAN setup", type=str)
        parser.add_argument("--extended-attr-json", dest='ext_attr_json', help="JSON describing any extended attributes")
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

    def add(self):
        self.args.domain_json = json.loads(self.args.domain_json)
        return add_protocol_rse(self.args, self.logger)

    def remove(self):
        return del_protocol_rse(self.args, self.logger)


class RSEDistance(CLIClientBase):
    PARSER_NAME = "distance"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--destination", help="Destination RSE name")
        parser.add_argument("--distance", help="Distance between RSE and destination", type=int)

    def module_help(self) -> str:
        return "View or modify the distance information between a pair of RSEs."

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rse distance --rse RSE-T0 --destination RSE-T3 --distance 4 # Add a new distance between RSE-T0 and RSE-T3 ",
            f"$ {self.COMMAND_NAME} list rse distance --rse RSE-T0 --destination RSE-T3 # View the distance between",
            f"$ {self.COMMAND_NAME} set rse distance --rse RSE-T0 --destination RSE-T3 --distance 1 # Update an existing distance ",
        ]

    def add(self):
        self.args.source = self.args.rse
        return add_distance_rses(self.args, self.logger)

    def remove(self) -> None:
        self.args.source = self.args.rse
        delete_distance_rses(self.args, self.logger)

    def set(self) -> None:
        self.args.source = self.args.rse
        update_distance_rses(self.args, self.logger)

    def list(self) -> None:
        self.args.source = self.args.rse
        get_distance_rses(self.args, self.logger)


class RSELimit(CLIClientBase):
    PARSER_NAME = "limit"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--name", help="Parameter to limit")
        parser.add_argument("--limit", dest='value', help="Limit value", type=int)

    def module_help(self) -> str:
        return "Modify an RSE Limit"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rse limit --rse RSE-T4 --name XRD1 MinFreeSpace  --limit 10000",
            f"$ {self.COMMAND_NAME} remove rse limit --rse RSE-T4 --name XRD1 MinFreeSpace "
        ]

    def add(self):
        return set_limit_rse(self.args, self.logger)

    def remove(self):
        return delete_limit_rse(self.args, self.logger)


class RSEQOSPolicy(CLIClientBase):
    PARSER_NAME = "qos-policy"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--qos-policy", help="QoS Policy")

    def module_help(self) -> str:
        return "View or modify QoS policies of an RSE."

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rse qos-policy --rse RSE-T0 --qos_policy SLOW_BUT_CHEAP",
            f"$ {self.COMMAND_NAME} remove rse qos-policy --rse RSE-T0 --qos_policy SLOW_BUT_CHEAP"
        ]

    def add(self):
        return add_qos_policy(self.args, self.logger)

    def remove(self):
        return delete_qos_policy(self.args, self.logger)

    def list(self):
        return list_qos_policies(self.args, self.logger)


class RSEUsage(CLIClientBase):
    PARSER_NAME = "usage"

    def parser(self, subparser: "ArgumentParser"):
        parser = self.subcommand_parser(subparser)
        parser.add_argument("--show-accounts", action="store_true", help="List accounts usages of RSE")
        parser.add_argument("--human", action="store_true", default=True, help="Human readable output")

    def module_help(self) -> str:
        return "Show the total/free/used space for a given RSE. This values can differ for different RSE source."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} list rse usage --rse RSE-T1"]

    def list(self) -> None:
        list_rse_usage(self.args, self.logger)
