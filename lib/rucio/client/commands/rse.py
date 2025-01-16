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

from rucio.client.commands.bin_legacy.rucio import list_rses
from rucio.client.commands.bin_legacy.rucio_admin import (
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
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class RSE(CommandBase):
    def module_help(self) -> str:
        return "Manage Rucio Storage Elements - the sites where Rucio can place and access data."

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show all RSEs", "namespace": self.list_namespace},
            "show": {"call": self.show, "docs": "Show history of RSE usage (in terms of bytes and files)", "namespace": self.namespace},
            "remove": {"call": self.remove, "docs": "Disable an RSE", "namespace": self.namespace},
            "add": {"call": self.add, "docs": "Create a new RSE", "namespace": self.namespace},
            "update": {"call": self.update, "docs": "Update an existing RSE", "namespace": self.namespace},
        }

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {"attribute": Attribute, "distance": Distance, "protocol": Protocol, "limit": Limit, "qos": QOS}

    def usage_example(self) -> list[str]:
        return [
            "$ rucio rse list # Show all current RSEs, can also access with",
            "$ rucio rse list --rses 'deterministic=True'  # Show all RSEs that match the RSE Expression 'deterministic=True'",
            "$ rucio rse remove --rse RemoveThisRSE  # Disable an RSE by name",
            "$ rucio rse add --rse CreateANewRSE  # add a new RSE named CreateANewRSE",
            "$ rucio rse update --rse rse123456 --setting deterministic --value False  # Make an RSE Non-Deterministic",
            "$ rucio rse show --rse rse123456  # See all the settings for rse123456"
        ]

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rse", "--rse-name", help="RSE name", required=True)
        parser.add_argument("--non-deterministic", action="store_true", help="Create RSE in non-deterministic mode")

        parser.add_argument(
            "--setting",
            dest="param",
            help="RSE setting",
            choices={"deterministic", "rse_type", "staging_area", "volatile", "qos_class", "availability_delete", "availability_read", "availability_write", "city", "country_name", "latitude", "longitude", "region_code", "time_zone"},
        )
        parser.add_argument("--value", dest="value", help='Value for the new setting configuration. Use "", None or null to wipe the value')

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rses", "--rse-exp", dest="rses", help="RSE name or expression")
        parser.add_argument("--csv", action='store_true', help="Output list of RSEs as a csv")

    def show_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rse", "--rse-name", help="RSE name", required=True)
        parser.add_argument("--csv", action='store_true', help="Output list of RSE property key and values as a csv")

    def list_(self):
        list_rses(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        add_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def update(self):
        update_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def show(self):
        info_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        disable_rse(self.args, self.client, self.logger, self.console, self.spinner)


class Attribute(RSE):
    def module_help(self) -> str:
        return "Manage RSE Attributes as key/value pairs. \nCAUTION: the existing attributes can be overwritten"

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show existing attributes for an RSE"},
            "add": {"call": self.add, "docs": "Update an RSE's setting. Will overwrite existing settings"},
            "remove": {"call": self.remove, "docs": "Wipe an RSE's setting"}
        }

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rse", "--rse-name", help="RSE name", required=True)
        parser.add_argument("--key", help="Attribute key")
        parser.add_argument("--value", help="Attribute value")

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def usage_example(self) -> list[str]:
        return [
            "$ rucio rse attribute list --rse ThisRSE  # Show all the attributes for a given RSE",
            "$ rucio rse attribute list --rse ThisRSE --key name  # Show all the attribute 'name' for a given RSE",
            "$ rucio rse attribute add --rse ThisRSE --key given-attribute --value updated  # Set the attribute 'given-attribute' to 'updated' for an RSE",
        ]

    def add(self):
        set_attribute_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_attribute_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def list_(self):
        get_attribute_rse(self.args, self.client, self.logger, self.console, self.spinner)


class Distance(RSE):
    def module_help(self) -> str:
        return "Manage distances between RSEs. Used for determining efficiency of transfers from RSE to RSE via multihop operations"

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show distances between RSEs",
                     "namespace": self.list_namespace},
            "add": {"call": self.add, "docs": "Add a distance between RSEs", "namespace": self.add_namespace},
            "remove": {"call": self.remove,
                       "docs": "Delete the distance between a pair of RSEs",
                       "namespace": self.remove_namespace},
            "set": {"call": self.set_,
                    "docs": "Update the distance between a pair of RSE that already have a distance between them",
                    "namespace": self.set_namespace},
        }

    def usage_example(self) -> list[str]:
        return [
            "$ rucio rse distance list --source rse1 --destination rse2  # View the existing distance between rse1 and rse2",
            "$ rucio rse distance remove --source rse1 --destination rse2  # Remove an existing distance",
            "$ rucio rse distance add --source rse1 --destination rse2 --distance 10  # Add the distance between two rses that do not already have a distance",
            "$ rucio rse distance set --source rse1 --destination rse2 --distance 20  # Update an existing distance",
        ]

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--source", dest="source", help="Source RSE name")
        parser.add_argument("--destination", dest="destination", help="Destination RSE name")

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        self.list_namespace(parser)

    def add_namespace(self, parser: "ArgumentParser") -> None:
        self.list_namespace(parser)
        parser.add_argument("--distance", dest="distance", type=int, help="Distance between RSEs")

    def set_namespace(self, parser: "ArgumentParser") -> None:
        self.add_namespace(parser)

    def list_(self):
        get_distance_rses(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        add_distance_rses(self.args, self.client, self.logger, self.console, self.spinner)

    def set_(self):
        update_distance_rses(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_distance_rses(self.args, self.client, self.logger, self.console, self.spinner)


class Protocol(RSE):
    def module_help(self) -> str:
        return "Manage RSE transfer and storage protocols. Use `$ rucio rse show` to view an RSE's existing protocols"

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def _operations(self) -> dict[str, "OperationDict"]:
        return {"add": {"call": self.add, "docs": "Create a new RSE transfer protocol"}, "remove": {"call": self.remove, "docs": "Remove an existing RSE protocol"}}

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rse", "--rse-name", dest='rse', help="RSE name")
        parser.add_argument("--host", dest="hostname", help="Endpoint hostname")
        parser.add_argument("--scheme", help="Endpoint URL scheme")
        parser.add_argument("--prefix", help="Endpoint URL path prefix")
        parser.add_argument("--space-token", help="Space token name (SRM-only)")
        parser.add_argument("--web-service-path", help="Web service URL (SRM-only)")
        parser.add_argument("--port", type=int, help="URL port")
        parser.add_argument("--impl", default="rucio.rse.protocols.gfal.Default", help="Transfer protocol implementation to use")
        parser.add_argument("--domain-json", type=json.loads, help="JSON describing the WAN / LAN setup")
        parser.add_argument("--extended-attributes-json", dest="ext_attr_json", type=json.loads, help="JSON describing any extended attributes")

    def usage_example(self) -> list[str]:
        return [
            "$ rucio rse protocol --host jdoes.test.org --scheme gsiftp --prefix '/atlasdatadisk/rucio/' --port 8443 --rse JDOE_DATADISK  # Add a new protocol on jdoe.test.org that uses gsiftp",
            "$ rucio rse protocol remove --scheme gsiftp --rse JDOE_DATADISK # Remove the existing gsiftp protocol",
        ]

    def add(self):
        add_protocol_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        del_protocol_rse(self.args, self.client, self.logger, self.console, self.spinner)


class Limit(RSE):
    def module_help(self) -> str:
        return "Manage storage size limits. Existing limits can be found with `$ rucio rse info`"

    def _operations(self) -> dict[str, "OperationDict"]:
        return {"add": {"call": self.add, "docs": "Add a storage limit"}, "remove": {"call": self.remove, "docs": "Remove an existing storage limit"}}

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rse", "--rse-name", dest='rse', help="RSE name")
        parser.add_argument("--name", help="Name of the limit")
        parser.add_argument("--limit", dest="value", help="Value of the limit in bytes")

    def usage_example(self) -> list[str]:
        return ["$ rucio rse limit add --rse XRD1 --name MinFreeSpace --value 10000", "$ rucio rse limit --rse XRD3 --name MinFreeSpace"]

    def add(self):
        set_limit_rse(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_limit_rse(self.args, self.client, self.logger, self.console, self.spinner)


class QOS(RSE):
    def module_help(self) -> str:
        return "Interact with an RSE's QoS policy."

    def _operations(self) -> dict[str, "OperationDict"]:
        return {"list": {"call": self.list_, "docs": "Show existing QoS Policies"}, "add": {"call": self.add, "docs": "Add a new policy"}, "remove": {"call": self.remove, "docs": "Remove Policy"}}

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--rse", "--rse-name", dest="rse", help="RSE name")
        parser.add_argument("--policy", dest="qos_policy", help="QoS policy")

    def usage_example(self) -> list[str]:
        return [
            "$ rucio rse qospolicy list --rse JDOE_DATADISK  # List QoS Policy for a given RSE",
            "$ rucio rse qospolicy add --rse JDOE_DATADISK --policy SLOW_BUT_CHEAP  # Add a SLOW_BUT_CHEAP policy to the JDOE_DATADISK RSE",
            "$ rucio rse qospolicy remove --rse JDOE_DATADISK --policy SLOW_BUT_CHEAP  # Remove the same policy",
        ]

    def add(self):
        add_qos_policy(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_qos_policy(self.args, self.client, self.logger, self.console, self.spinner)

    def list_(self):
        list_qos_policies(self.args, self.client, self.logger, self.console, self.spinner)
