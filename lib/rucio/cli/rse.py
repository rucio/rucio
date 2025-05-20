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

from rucio.cli.bin_legacy.rucio import list_rses
from rucio.cli.bin_legacy.rucio_admin import (
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
from rucio.cli.utils import Arguments


@click.group()
def rse():
    """Manage Rucio Storage Elements (RSEs)"""


@rse.command("list")
@click.option("--rses", "--rse-exp", help="RSE Expression to use as a filter", required=False)
@click.option("--csv", is_flag=True, default=False, help="Output list of RSEs as a csv")
@click.pass_context
def list_(ctx, rses, csv):
    """List all registered Rucio Storage Elements (RSEs)"""
    list_rses(Arguments({"no_pager": ctx.obj.no_pager, "rses": rses, "csv": csv}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("show")
@click.argument("rse-name")
@click.option("--csv", is_flag=True, default=False, help="Output list of RSE property key and values as a csv")
@click.pass_context
def show(ctx, rse_name, csv):
    """Usage, protocols, settings, and attributes for a given RSE"""
    info_rse(Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "csv": csv}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("add")
@click.argument("rse-name")
@click.option("--non-deterministic", is_flag=True, default=False, help="Create RSE in non-deterministic mode")
@click.pass_context
def add_(ctx, rse_name, non_deterministic):
    """Add a new RSE"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "non_deterministic": non_deterministic})
    add_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("remove")
@click.argument("rse-name")
@click.pass_context
def remove(ctx, rse_name):
    """Permanently disable an RSE. CAUTION: all information about the RSE might be lost!"""
    disable_rse(Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.command("update")
@click.argument("rse-name")
@click.option('--key', help='Setting key', required=True)
@click.option('--value', help='Setting value', required=True)
@click.pass_context
def update(ctx, rse_name, key, value):
    """
    Update an RSE's setting.

    \b
    Example:
        $ rucio rse update my-rse --option availability_write True
    """
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "param": key, "value": value})
    update_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def distance():
    """Manage the relative distance between RSEs for transfer prioritization calculations"""


@distance.command("show")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.pass_context
def distance_show(ctx, source_rse, destination_rse):
    """Display distance information from SOURCE-RSE to DESTINATION-RSE"""
    get_distance_rses(Arguments({"no_pager": ctx.obj.no_pager, "source": source_rse, "destination": destination_rse}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@distance.command("add")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.option("--distance", default=1, type=int, help="Relative distance between RSEs")
@click.option('--bidirectional', '--bidi', is_flag=True, help='Add distances in both directions')
@click.pass_context
def distance_add(ctx, source_rse, destination_rse, distance, bidirectional):
    """Create a new link from SOURCE-RSE to DESTINATION-RSE with a distance"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "source": source_rse, "destination": destination_rse, "distance": distance, "bidirectional": bidirectional})
    add_distance_rses(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@distance.command("remove")
@click.argument("source", required=False)
@click.argument("destination", required=False)
@click.option('-y', '--yes', is_flag=True, help='Automatically confirm deletion')
@click.option('--bidirectional', '--bidi', is_flag=True, help='Delete distances in both directions')
@click.pass_context
def distance_remove(ctx: click.Context, source: str, destination: str, yes: bool, bidirectional: bool) -> None:
    """
    Un-link RSEs by removing the distance between them.
    
    This command supports multiple modes:
    - Delete distance from one RSE to another
    - Delete distances between RSEs matching SOURCE expression to RSEs matching DESTINATION
    - Delete all outgoing distances from RSEs matching SOURCE to all RSEs
    - Delete all incoming distances to RSEs matching DESTINATION from all RSEs
    - Delete distances in both directions (using --bidirectional)
    
    Arguments accept RSE expressions (e.g., "site=SITE_NAME" or "*").
    An RSE name is itself a valid RSE expression.
    
    Examples:
    
    # Delete distance between two specific RSEs
    rucio rse distance remove JDOE_DATADISK JDOE_SCRATCHDISK
    
    # Delete distance between all RSEs at two sites
    rucio rse distance remove "site=JDOE_SITE_A" "site=JDOE_SITE_B"
    
    # Delete distance bidirectionally between two RSE expressions
    rucio rse distance remove --bidirectional "site=JDOE_SITE_A" "site=JDOE_SITE_B"
    
    # Delete all outgoing links from RSEs matching an expression
    rucio rse distance remove "site=JDOE_SITE_A" "*"
    
    # Delete all incoming links to RSEs matching an expression
    rucio rse distance remove "*" "site=JDOE_SITE_B"
    """
    if not (source or destination):
        ctx.fail("Either source, destination, or both must be specified")
    
    args = Arguments({"no_pager": ctx.obj.no_pager, "source": source, "destination": destination, "yes": yes, "bidirectional": bidirectional})
    delete_distance_rses(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@distance.command("update")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.option("--distance", type=int, help="Relative distance between RSEs", required=True)
@click.pass_context
def distance_update(ctx, source_rse, destination_rse, distance):
    """Update the existing distance or ranking from SOURCE-RSE to DESTINATION-RSE"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "source": source_rse, "destination": destination_rse, "distance": distance})
    update_distance_rses(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
def attribute():
    """Interact with RSE Attributes"""


@attribute.command("list")
@click.argument("rse-name")
@click.pass_context
def attr_list_(ctx, rse_name):
    """List all attributes of a given RSE"""
    get_attribute_rse(Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@attribute.command("add")
@click.argument("rse-name")
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def attribute_add_(ctx, rse_name, key, value):
    """Add a new attribute for an RSE

    \b
    Example:
        $ rucio rse attribute add my-rse --key My-Attribute  --value True
    """
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "key": key, "value": value})
    set_attribute_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# TODO Update attribute - only overwrites existing attributes

@attribute.command("remove")
@click.argument("rse-name")
@click.option("--attribute", help="Attribute to remove", required=True)
@click.pass_context
def attribute_remove(ctx, rse_name, attribute):
    """Remove an existing attribute from an RSE"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "key": attribute, "value": None})
    delete_attribute_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
def limit():
    """Manage storage size limits"""


@limit.command("add")
@click.argument("rse-name")
@click.option("--limit", type=(str, int), required=True, help="Name of limit and value in bytes")
@click.pass_context
def limit_add(ctx, rse_name, limit):
    """Add a usage limit to an RSE

    \b
    Example, add a limit of 1KB to XRD1 named "MinFreeSpace":
        $ rucio rse limit add XRD1 --limit MinFreeSpace 10000
    """
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "name": limit[0], "value": limit[1]})
    set_limit_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@limit.command("remove")
@click.argument("rse-name")
@click.option("--limit", required=True, help="Name of limit to remove")
@click.pass_context
def limit_remove(ctx, rse_name, limit):
    """Remove an existing RSE limit"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "name": limit})
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
@click.pass_context
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
@click.pass_context
def protocol_remove(ctx, rse_name, host_name, scheme, port):
    """Remove an existing protocol from an RSE"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "scheme": scheme, "hostname": host_name, "port": port})
    del_protocol_rse(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rse.group()
@click.help_option("-h", "--help")
def qos():
    """Interact with the QoS model"""


@qos.command("add")
@click.argument("rse-name", nargs=1)
@click.option("--policy", required=True)
@click.pass_context
def qos_add(ctx, rse_name, policy):
    "Add a new QoS policy"
    add_qos_policy(Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "qos_policy": policy}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@qos.command("remove")
@click.argument("rse-name", nargs=1)
@click.option("--policy", required=True)
@click.pass_context
def qos_remove(ctx, rse_name, policy):
    "Remove an existing QoS policy"
    delete_qos_policy(Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name, "qos_policy": policy}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@qos.command("list")
@click.argument("rse-name", nargs=1)
@click.pass_context
def qos_list(ctx, rse_name):
    "List the RSE's QoS policies"
    list_qos_policies(Arguments({"no_pager": ctx.obj.no_pager, "rse": rse_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
