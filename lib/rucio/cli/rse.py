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
from rich.padding import Padding
from rich.text import Text
from rich.tree import Tree

from rucio.client.richclient import CLITheme, generate_table, print_output
from rucio.common.exception import InputValidationError
from rucio.common.utils import sizefmt


@click.group()
def rse():
    """Manage Rucio Storage Elements (RSEs)"""


@rse.command("list")
@click.option("--rses", "--rse-exp", help="RSE Expression to use as a filter", required=False)
@click.option("--csv", is_flag=True, default=False, help="Output list of RSEs as a csv")
@click.pass_context
def list_(ctx, rses, csv):
    """List all registered Rucio Storage Elements (RSEs)"""
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching RSEs')
        ctx.obj.spinner.start()

    rse_list = ctx.obj.client.list_rses(rses)
    if csv:
        print(*(rse['rse'] for rse in rses), sep='\n')
    if ctx.obj.use_rich:
        table = generate_table([[rse['rse']] for rse in sorted(rses, key=lambda elem: elem['rse'])], headers=['RSE'], col_alignments=['left'])
        ctx.obj.spinner.stop()
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        for rse in rse_list:
            print('%(rse)s' % rse)  # TODO replace with f-string


@rse.command("show")
@click.argument("rse-name")
@click.pass_context
def show(ctx, rse_name):
    """Usage, protocols, settings, and attributes for a given RSE"""
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching RSE info')
        ctx.obj.spinner.start()

    rseinfo = ctx.obj.client.get_rse(rse=rse_name)
    attributes = ctx.obj.client.list_rse_attributes(rse=rse_name)
    usage = ctx.obj.client.get_rse_usage(rse=rse_name)
    rse_limits = ctx.obj.client.get_rse_limits(rse_name)

    if ctx.obj.use_rich:
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.RSE_TYPE}
        output = []
        table_data = []
    else:
        print('Settings:')
        print('=========')
    for i, key in enumerate(sorted(rseinfo)):
        if ctx.obj.use_rich:
            if i == 0:
                output.append('[b]Settings:[/]')
            if key != 'protocols':
                table_data.append([key, Text(str(rseinfo[key]), style=keyword_styles.get(str(rseinfo[key]), 'default'))])
        else:
            if key != 'protocols':
                print('  ' + key + ': ' + str(rseinfo[key]))  # TODO f-strings

    if ctx.obj.use_rich:
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        output.append(table)
        table_data = []
    else:
        print('Attributes:')
        print('===========')
    for i, attribute in enumerate(sorted(attributes)):
        if ctx.obj.use_rich:
            if i == 0:
                output.append('\n[b]Attributes:[/]')
            table_data.append([attribute, Text(str(attributes[attribute]), style=keyword_styles.get(str(attributes[attribute]), 'default'))])
        else:
            print('  ' + attribute + ': ' + str(attributes[attribute]))  # TODO f-strings

    if ctx.obj.use_rich:
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        output.append(table)
    else:
        print('Protocols:')
        print('==========')
    for i, protocol in enumerate(sorted(rseinfo['protocols'], key=lambda x: x['scheme'])):
        if ctx.obj.use_rich:
            if i == 0:
                output.append('\n[b]Protocols:[/]')
            output.append(Padding.indent(Text(protocol['scheme'], style=CLITheme.SUBHEADER_HIGHLIGHT), 2))
        else:
            print('  ' + protocol['scheme'])  # TODO f-string

        table_data = []
        for item in sorted(protocol):
            if ctx.obj.use_rich:
                if item == 'domains':
                    tree = Tree('')
                    for domain, values in protocol[item].items():
                        branch = tree.add(f'[{CLITheme.JSON_STR}]{domain}')
                        for k, v in values.items():
                            branch.add(f'[{CLITheme.JSON_STR}]{k}[/]: [{CLITheme.JSON_NUM}]{v}[/]')
                    table_data.append([item, tree])
                else:
                    table_data.append([item, Text(str(protocol[item]), style=keyword_styles.get(protocol[item], 'default'))])
            else:
                if item == 'domains':
                    print('    ' + item + ': \'' + json.dumps(protocol[item]) + '\'')
                else:
                    print('    ' + item + ': ' + str(protocol[item]))

        if ctx.obj.use_rich:
            table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
            output.append(Padding.indent(table, 2))

    if ctx.obj.use_rich:
        header = ['SOURCE', 'USED', 'FILES', 'FREE', 'TOTAL', 'UPDATED AT']
        key2id = {header[i].lower().replace(' ', '_'): i for i in range(len(header))}
        table_data = []
    else:
        print('Usage:')
        print('======')
    for i, elem in enumerate(sorted(usage, key=lambda x: x['source'])):
        if ctx.obj.use_rich:
            if i == 0:
                output.append('\n[b]Usage:[/]')

            row = [''] * len(header)
            row[0] = elem['source']
            for item in sorted(elem):
                if item in ['used', 'free', 'total']:
                    row[key2id[item]] = sizefmt(elem[item], True)
                elif item != 'source' and item in key2id:
                    row[key2id[item]] = str(elem[item])
            table_data.append(row)
        else:
            print('  ' + elem['source'])
            for item in sorted(elem):
                print('    ' + item + ': ' + str(elem[item]))

    if ctx.obj.use_rich:
        if len(table_data) > 0:
            usage_table = generate_table(table_data, headers=header, col_alignments=['left', 'right', 'right', 'right', 'right', 'left'])
            output.append(usage_table)
        table_data = []
    else:
        print('RSE limits:')
        print('===========')
    for i, limit in enumerate(rse_limits):
        if ctx.obj.use_rich:
            if i == 0:
                output.append('\n[b]RSE limits:[/]')  # TODO f-strings
            table_data.append([limit, str(rse_limits[limit]) + ' B'])
        else:
            print('  ' + limit + ': ' + str(rse_limits[limit]) + ' B')

    if ctx.obj.use_rich:
        if len(table_data) > 0:
            table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'right'])
            output.append(table)
        ctx.obj.spinner.stop()
        print_output(*output, console=ctx.obj.console, no_pager=ctx.obj.no_pager)


@rse.command("add")
@click.argument("rse-name")
@click.option("--non-deterministic", is_flag=True, default=False, help="Create RSE in non-deterministic mode")
@click.pass_context
def add_(ctx, rse_name, non_deterministic):
    """Add a new RSE"""
    ctx.obj.client.add_rse(rse_name, deterministic=not non_deterministic)
    print('Added new %sdeterministic RSE: %s' % ('non-' if non_deterministic else '', rse))  # TODO f-string


@rse.command("remove")
@click.argument("rse-name")
@click.pass_context
def remove(ctx, rse_name):
    """Permanently disable an RSE. CAUTION: all information about the RSE might be lost!"""
    ctx.obj.client.delete_rse(rse_name)


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
    if value in ['true', 'True', 'TRUE', '1']:
        value = True
    if value in ['false', 'False', 'FALSE', '0']:
        value = False
    params = {key: value}
    ctx.obj.client.update_rse(rse_name, parameters=params)

    if isinstance(value, bool):
        value = str(value)
    # TODO f-string
    print('Updated RSE %s settings %s to %s' % (rse_name, key, value if value.lower() not in ['', 'none', 'null'] else '[WIPED]'))


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
    distance_info = ctx.obj.client.get_distance(source_rse, destination_rse)
    if ctx.obj.use_rse:
        if distance_info:
            table = generate_table(
                [[source_rse, destination_rse, str(distance_info[0]['distance'])]],
                headers=['SOURCE', 'DESTINATION', 'DISTANCE'],
                col_alignments=['left', 'left', 'right']
            )
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            # TODO f-string
            print(f"No distance set from {source_rse} to {destination_rse}")
    else:
        if distance_info:
            # TODO f-strings
            print('Distance information from %s to %s: distance=%d' % (source_rse, destination_rse, distance_info[0]['distance']))
        else:
            print("No distance set from %s to %s" % (source_rse, destination_rse))


@distance.command("add")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.option("--distance", default=1, type=int, help="Relative distance between RSEs")
@click.pass_context
def distance_add(ctx, source_rse, destination_rse, distance):
    """Create a new link from SOURCE-RSE to DESTINATION-RSE with a distance"""
    params = {'distance': distance}
    ctx.obj.client.add_distance(source_rse, destination_rse, params)
    # TODO f-strings
    print('Set distance from %s to %s to %d' % (source_rse, destination_rse, distance))


@distance.command("remove")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.pass_context
def distance_remove(ctx, source_rse, destination_rse):
    """Un-link SOURCE-RSE from DESTINATION-RSE by removing the distance between them"""
    ctx.obj.client.delete_distance(source_rse, destination_rse)
    # TODO f-strings
    print('Deleted distance information from %s to %s.' % (source_rse, destination_rse))


@distance.command("update")
@click.argument("source-rse")
@click.argument("destination-rse")
@click.option("--distance", type=int, help="Relative distance between RSEs", required=True)
@click.pass_context
def distance_update(ctx, source_rse, destination_rse, distance):
    """Update the existing distance or ranking from SOURCE-RSE to DESTINATION-RSE"""
    params = {}
    if distance is not None:  # TODO tests to verify this is not required
        params['distance'] = distance
    ctx.obj.client.update_distance(source_rse, destination_rse, params)
    # TODO f-strings
    print('Update distance information from %s to %s:' % (source_rse, destination_rse))
    if params.get('distance') is not None:
        print("- Distance set to %d" % params['distance'])


@rse.group()
def attribute():
    """Interact with RSE Attributes"""


@attribute.command("list")
@click.argument("rse-name")
@click.pass_context
def attr_list_(ctx, rse_name):
    """List all attributes of a given RSE"""
    attributes = ctx.obj.client.list_rse_attributes(rse=rse_name)
    if ctx.obj.use_rich:
        table_data = [(k, Text(str(v), style=CLITheme.BOOLEAN.get(str(v), 'default'))) for k, v in sorted(attributes.items())]
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        for k in attributes:  # TODO f-string
            print(k + ': ' + str(attributes[k]))


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
    ctx.obj.client.add_rse_attribute(rse=rse_name, key=key, value=value)
    # TODO: f-string
    print('Added new RSE attribute for %s: %s-%s ' % (rse_name, key, value))

# TODO Update attribute - only overwrites existing attributes


@attribute.command("remove")
@click.argument("rse-name")
@click.option("--attribute", help="Attribute to remove", required=True)
@click.pass_context
def attribute_remove(ctx, rse_name, attribute):
    """Remove an existing attribute from an RSE"""
    ctx.obj.client.delete_rse_attribute(rse=rse_name, key=attribute)
    # TODO f-strings
    print('Deleted RSE attribute for %s: %s ' % (rse_name, attribute))


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
    name = limit[0]
    value = limit[1]
    try:  # TODO test to verify this logic is needed
        value = int(value)
        if ctx.obj.client.set_rse_limits(rse_name, name, value):
            # TODO change to print, f-string
            ctx.obj.logger.info('Set RSE limit successfully for %s: %s = %s' % (rse_name, name, value))
    except ValueError:
        # TODO raise exception
        ctx.obj.logger.error('The RSE limit value must be an integer')


@limit.command("remove")
@click.argument("rse-name")
@click.option("--limit", required=True, help="Name of limit to remove")
@click.pass_context
def limit_remove(ctx, rse_name, limit):
    """Remove an existing RSE limit"""
    limits = ctx.obj.client.get_rse_limits(rse_name)
    if limit not in limits.keys():
        # TODO Raise error
        # TODO f-strings
        ctx.obj.logger.error('Limit %s not defined in RSE %s' % (limit, rse_name))
    else:
        if ctx.obj.client.delete_rse_limits(rse_name, limit):
            # TODO f-strings
            ctx.obj.logger.info('Deleted RSE limit successfully for %s: %s' % (rse_name, limit))


@rse.group()
@click.help_option("-h", "--help")
def protocol():
    """Manage RSE transfer protocols"""


# TODO Better loader for json types
@protocol.command("add")
@click.argument("rse-name")
@click.option("--hostname", help="Endpoint hostname", required=True)
@click.option("--scheme", help="Endpoint URL scheme", required=True)
@click.option("--prefix", help="Endpoint URL path prefix", required=True)
@click.option("--space-token", help="Space token name (SRM-only)")
@click.option("--web-service-path", help="Web service URL (SRM-only)")
@click.option("--port", type=int, help="URL port")
@click.option("--impl", default="rucio.rse.protocols.gfal.Default", help="Transfer protocol implementation to use")
@click.option("--domain-json", type=json.loads, help="JSON describing the WAN / LAN setup")
@click.option("--extended-attributes-json", type=json.loads, help="JSON describing any extended attributes")
@click.pass_context
def protocol_add(ctx, rse_name, hostname, scheme, prefix, space_token, web_service_path, port, impl, domain_json, extended_attributes_json):
    """
    Add a new protocol for an RSE used for transferring files

    \b
    Example, adding a default protocol hosted at jdoes.test.org to the RSE JDOE_DATADISK
        $ rucio rse protocol add JDOE_DATADISK --hostname jdoes.test.org --scheme gsiftp --prefix '/atlasdatadisk/rucio/' --port 8443'

    """
    proto = {
        'hostname': hostname,
        'scheme': scheme,
        'port': port,
        'impl': impl,
        'prefix': prefix
    }
    if domain_json:
        proto['domains'] = domain_json
    proto.setdefault('extended_attributes', {})
    if extended_attributes_json:
        proto['extended_attributes'] = extended_attributes_json
    if proto['scheme'] == 'srm' and not web_service_path:
        raise InputValidationError('Error: space-token and web-service-path must be provided for SRM endpoints.')
    if space_token:
        proto['extended_attributes']['space_token'] = space_token
    if web_service_path:
        proto['extended_attributes']['web_service_path'] = web_service_path
    # Rucio >1.14.1 cannot have an empty extended attributes
    if not proto['extended_attributes']:
        del proto['extended_attributes']
    ctx.obj.client.add_protocol(rse_name, proto)


@protocol.command("remove")
@click.argument("rse-name")
@click.option("--scheme", help="Endpoint URL scheme", required=True)
@click.option("--hostname", help="Endpoint hostname")
@click.option("--port", type=int, help="URL port")
@click.pass_context
def protocol_remove(ctx, rse_name, hostname, scheme, port):
    """Remove an existing protocol from an RSE"""
    kwargs = {}
    if port:
        kwargs['port'] = port
    if hostname:
        kwargs['hostname'] = hostname
    ctx.obj.client.delete_protocols(rse_name, scheme, **kwargs)


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
    ctx.obj.client.add_qos_policy(rse_name, policy)
    # TODO f-strings
    print('Added QoS policy to RSE %s: %s' % (rse_name, policy))


@qos.command("remove")
@click.argument("rse-name", nargs=1)
@click.option("--policy", required=True)
@click.pass_context
def qos_remove(ctx, rse_name, policy):
    "Remove an existing QoS policy"
    ctx.obj.client.delete_qos_policy(rse_name, policy)
    # TODO f-string
    print('Deleted QoS policy from RSE %s: %s' % (rse_name, policy))


@qos.command("list")
@click.argument("rse-name", nargs=1)
@click.pass_context
def qos_list(ctx, rse_name):
    "List the RSE's QoS policies"
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching QoS policies')
        ctx.obj.spinner.start()

    qos_policies = ctx.obj.client.list_qos_policies(rse_name)
    if ctx.obj.use_rich:
        qos_policies = [[qos_policy] for qos_policy in sorted(qos_policies)]
        table = generate_table(qos_policies, headers=['QOS POLICY'], col_alignments=['left'])
        ctx.obj.spinner.stop()
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        for qos_policy in sorted(qos_policies):
            print(qos_policy)
