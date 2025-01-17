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

import click

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
from rucio.client.commands.utils import Arguments, click_decorator


@click.group()
@click.help_option("-h", "--help")
def rse():
    """Manage Rucio Storage Elements (RSEs)"""


@rse.command("list")
@click.option("--rses", "--rse-exp", help="RSE Expression to use as a filter", required=False)
@click.add_option("--csv", is_flag=True, default=False, help="Output list of RSEs as a csv")
@click_decorator
def list_(ctx, rses, csv):
    """List all registered Rucio Storage Elements (RSEs)"""
    list_rses(Arguments({"rses": rses, "csv": csv}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("show")
@click.argument("rse-name")
@click.add_option("--csv", is_flag=True, default=False, help="Output list of RSE property key and values as a csv")
@click_decorator
def show(ctx, rse_name, csv):
    """Usage, protocols, settings, and attributes for a given RSE"""
    info_rse(Arguments({"rse": rse_name, "csv": csv}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("add")
@click.argument("rse-name")
@click.option("--non-deterministic/--deterministic", default=False, help="Create RSE in non-deterministic mode")
@click_decorator
def add_(ctx, rse_name, non_deterministic):
    """Add a new RSE"""
    args = Arguments({"rse": rse_name, "non_deterministic": non_deterministic})
    add_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("remove")
@click.argument("rse-name")
@click.confirmation_option(prompt="Are you sure you want to delete this RSE?")
@click_decorator
def remove(ctx, rse_name):
    """Permanently disable an RSE. WARNING: You may not be able to recover this RSE!"""
    disable_rse(Arguments({"rse": rse_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("update")
@click.argument("rse-name")
@click.option("-o", "--option", type=(str, str))
@click_decorator
def update(ctx, rse_name, option):
    """
    Update an RSE's setting.

    \b
    Example:
        $ rucio rse update my-rse --option availability_write True
    """
    args = Arguments({"rse": rse_name, "param": option[0], "value": option[1]})
    update_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def distance():
    """Manage the relative distance between RSEs for transfer prioritization calculations"""


@distance.command("show")
@click.argument("source-rse")
@click.argument("destination-rse")
@click_decorator
def distance_show(ctx, source_rse, destination_rse):
    """Display distance information from SOURCE-RSE to DESTINATION-RSE"""
    get_distance_rses(Arguments({"source": source_rse, "destination": destination_rse}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@distance.command("add")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.option("--distance", default=1, type=int, help="Relative distance between RSEs")
@click.option("--ranking", default=1, type=int, help="Ranking of link to prioritize transfers")
@click_decorator
def distance_add(ctx, source_rse, destination_rse, distance, ranking):
    """Create a new link from SOURCE-RSE to DESTINATION-RSE with a distance and ranking"""
    args = Arguments({"source": source_rse, "destination": destination_rse, "distance": distance, "ranking": ranking})
    add_distance_rses(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@distance.command("remove")
@click.argument("source-rse")
@click.argument("destination-rse")
@click_decorator
def distance_remove(ctx, source_rse, destination_rse):
    """Un-link SOURCE-RSE from DESTINATION-RSE by removing the distance between them"""
    args = Arguments({"source": source_rse, "destination": destination_rse})
    delete_distance_rses(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@distance.command("update")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.option("--distance", default=1, type=int, help="Relative distance between RSEs")
@click.option("--ranking", default=1, type=int, help="Ranking of link to prioritize transfers")
@click_decorator
def distance_update(ctx, source_rse, destination_rse, distance, ranking):
    """Update the existing distance or ranking from SOURCE-RSE to DESTINATION-RSE"""
    if (distance is None) and (ranking is None):
        raise ValueError("Either [distance] or [ranking] must be specified")
    args = Arguments({"source": source_rse, "destination": destination_rse, "distance": distance, "ranking": ranking})
    update_distance_rses(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def attribute():
    """Interact with RSE Attributes"""


@attribute.command("list")
@click.argument("rse-name")
@click_decorator
def attr_list_(ctx, rse_name):
    """List all attributes of a given RSE"""
    get_attribute_rse(Arguments({"rse": rse_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@attribute.command("add")
@click.argument("rse-name")
@click.option("-o", "--option", type=(str, str), required=True)
@click_decorator
def attr_add_(ctx, rse_name, option):
    """Add a new attribute for an RSE

    \b
    Example:
        $ rucio rse attribute add my-rse --option My-Attribute True
    """
    args = Arguments({"rse": rse_name, "key": option[0], "value": option[1]})
    set_attribute_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# TODO Update attribute - only overwrites existing attributes
# @attribute.command("update")
# @click.argument("rse-name")
# @click.option("-o", "--option", type=(str, str))
# @click_decorator
# @click.confirmation_option(prompt="Are you sure you want to delete this value?")
# def attr_update(ctx):
# Only update existing attributes


@attribute.command("remove")
@click.argument("rse-name")
@click.option("-attr", "--attribute", help="Attribute to remove", required=True)
@click_decorator
def attr_remove(ctx, rse_name, attribute):
    """Remove an existing attribute from an RSE"""
    args = Arguments({"rse": rse_name, "key": attribute, "value": None})
    delete_attribute_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def limit():
    """Manage storage size limits"""


@limit.command("add")
@click.argument("rse-name")
@click.option("--limit", type=(str, int), required=True, help="Name of limit and value in bytes")
@click_decorator
def limit_add(ctx, rse_name, limit):
    """Add a usage limit to an RSE

    \b
    Example, add a limit of 1KB to XRD1 named "MinFreeSpace":
        $ rucio rse limit add XRD1 --limit MinFreeSpace 10000
    """
    args = Arguments({"rse": rse_name, "name": limit[0], "value": limit[1]})
    set_limit_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@limit.command("remove")
@click.argument("rse-name")
@click.option("--limit", required=True, help="Name of limit to remove")
@click_decorator
def limit_remove(ctx, rse_name, limit):
    """Remove an existing RSE limit"""
    args = Arguments({"rse": rse_name, "name": limit})
    delete_limit_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def protocol():
    """Manage RSE transfer protocols"""


# TODO Better loader for json types
@protocol.command("add")
@click.argument("rse-name")
@click.option("--host", "--host-name", help="Endpoint hostname", required=True)
@click.option("--scheme", help="Endpoint URL scheme", required=True)
@click.option("--prefix", help="Endpoint URL path prefix", required=True)
@click.option("--space-token", help="Space token name (SRM-only)")
@click.option("--web-service-path", help="Web service URL (SRM-only)")
@click.option("--port", type=int, help="URL port")
@click.option("--impl", default="rucio.rse.protocols.gfal.Default", help="Transfer protocol implementation to use")
@click.option("--domain-json", type=json.loads, help="JSON describing the WAN / LAN setup")
@click.option("--extended-attributes-json", type=json.loads, help="JSON describing any extended attributes")
@click_decorator
def protocol_add(ctx, rse_name, host, scheme, prefix, space_token, web_service_path, port, impl, domain_json, extended_attributes_json):
    """
    Add a new protocol for an RSE used for transferring files

    \b
    Example, adding a default protocol hosted at jdoes.test.org to the RSE JDOE_DATADISK
        $ rucio rse protocol add JDOE_DATADISK --host-name jdoes.test.org --scheme gsiftp --prefix '/atlasdatadisk/rucio/' --port 8443'

    """
    args = Arguments(
        {"rse": rse_name, "hostname": host, "ext_attr_json": extended_attributes_json, "scheme": scheme, "prefix": prefix, "space_token": space_token, "web_service_path": web_service_path, "port": port, "impl": impl, "domain_json": domain_json}
    )
    add_protocol_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@protocol.command("remove")
@click.argument("rse-name")
@click.option("--scheme", help="Endpoint URL scheme", required=True)
@click.option("--host-name", help="Endpoint hostname")
@click.option("--port", type=int, help="URL port")
@click_decorator
def protocol_remove(ctx, rse_name, host_name, scheme, port):
    """Remove an existing protocol from an RSE"""
    args = Arguments({"rse": rse_name, "scheme": scheme, "hostname": host_name, "port": port})
    del_protocol_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def qos():
    """Interact with the QoS model"""


@qos.command("add")
@click.argument("rse-name", nargs=1)
@click.option("--policy", required=True)
@click_decorator
def qos_add(ctx, rse_name, policy):
    "Add a new QoS policy"
    add_qos_policy(Arguments({"rse": rse_name, "qos_policy": policy}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@qos.command("remove")
@click.argument("rse-name", nargs=1)
@click.option("--policy", required=True)
@click_decorator
def qos_remove(ctx, rse_name, policy):
    "Remove an existing QoS policy"
    delete_qos_policy(Arguments({"rse": rse_name, "qos_policy": policy}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@qos.command("list")
@click.argument("rse-name", nargs=1)
@click_decorator
def qos_list(ctx, rse_name):
    "List the RSE's QoS policies"
    list_qos_policies(Arguments({"rse": rse_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
