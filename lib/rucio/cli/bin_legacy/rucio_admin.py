#!/usr/bin/env python
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
import datetime
import json
import math
import os
import signal
import sys
import time
from textwrap import dedent

from rich.console import Console
from rich.padding import Padding
from rich.status import Status
from rich.text import Text
from rich.theme import Theme
from rich.traceback import install
from rich.tree import Tree
from tabulate import tabulate

from rucio import version
from rucio.cli.utils import exception_handler, get_client, setup_gfal2_logger, signal_handler
from rucio.client.richclient import MAX_TRACEBACK_WIDTH, MIN_CONSOLE_WIDTH, CLITheme, generate_table, get_cli_config, get_pager, print_output, setup_rich_logger
from rucio.common.constants import RseAttr
from rucio.common.exception import (
    InputValidationError,
    InvalidObject,
    ReplicaNotFound,
    RSEOperationNotSupported,
    RucioException,
)
from rucio.common.extra import import_extras
from rucio.common.utils import StoreAndDeprecateWarningAction, chunks, clean_pfns, construct_non_deterministic_pfn, extract_scope, get_bytes_value_from_string, parse_response, render_json, setup_logger, sizefmt
from rucio.rse import rsemanager as rsemgr

EXTRA_MODULES = import_extras(['argcomplete'])

if EXTRA_MODULES['argcomplete']:
    import argcomplete  # pylint: disable=E0401

possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                                os.pardir, os.pardir))
if os.path.exists(os.path.join(possible_topdir, 'lib/rucio', '__init__.py')):
    sys.path.insert(0, possible_topdir)

SUCCESS = 0
FAILURE = 1
DEFAULT_PORT = 443


tablefmt = 'psql'
cli_config = get_cli_config()


def get_scope(did, client):
    try:
        scope, name = extract_scope(did)
        return scope, name
    except TypeError:
        scopes = client.list_scopes()
        scope, name = extract_scope(did, scopes)
        return scope, name


@exception_handler
def add_account(args, client, logger, console, spinner):
    """
    %(prog)s add [options] <field1=value1 field2=value2 ...>

    Adds a new account. Specify metadata fields as arguments.

    """
    client.add_account(account=args.account, type_=args.account_type, email=args.email)
    print('Added new account: %s' % args.account)
    return SUCCESS


@exception_handler
def delete_account(args, client, logger, console, spinner):
    """
    %(prog)s disable [options] <field1=value1 field2=value2 ...>

    Delete account.

    """
    client.delete_account(args.account)
    print('Deleted account: %s' % args.account)
    return SUCCESS


@exception_handler
def update_account(args, client, logger, console, spinner):
    """
    %(prog)s update [options] <field1=value1 field2=value2 ...>

    Update an account.

    """
    client.update_account(account=args.account, key=args.key, value=args.value)
    print('%s of account %s changed to %s' % (args.key, args.account, args.value))
    return SUCCESS


@exception_handler
def ban_account(args, client, logger, console, spinner):
    """
    %(prog)s ban [options] <field1=value1 field2=value2 ...>

    Ban an account.

    """
    client.update_account(account=args.account, key='status', value='SUSPENDED')
    print('Account %s banned' % args.account)
    return SUCCESS


@exception_handler
def unban_account(args, client, logger, console, spinner):
    """
    %(prog)s unban [options] <field1=value1 field2=value2 ...>

    Unban a banned account.

    """
    client.update_account(account=args.account, key='status', value='ACTIVE')
    print('Account %s unbanned' % args.account)
    return SUCCESS


@exception_handler
def list_accounts(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List accounts.

    """
    filters = {}
    if args.filters:
        for key, value in [(_.split('=')[0], _.split('=')[1]) for _ in args.filters.split(',')]:
            filters[key] = value
    accounts = client.list_accounts(identity=args.identity, account_type=args.account_type, filters=filters)
    if args.csv:
        print(*(account['account'] for account in accounts), sep=',')
    elif cli_config == 'rich':
        table = generate_table([[account['account']] for account in accounts], headers=['ACCOUNT'], col_alignments=['left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for account in accounts:
            print(account['account'])
    return SUCCESS


@exception_handler
def info_account(args, client, logger, console, spinner):
    """
    %(prog)s show [options] <field1=value1 field2=value2 ...>

    Show extended information of a given account

    """
    info = client.get_account(account=args.account)
    if cli_config == 'rich':
        keyword_style = {**CLITheme.ACCOUNT_STATUS, **CLITheme.ACCOUNT_TYPE}
        table_data = [(k, Text(str(v), style=keyword_style.get(str(v), 'default'))) for k, v in sorted(info.items())]
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for k in info:
            print(k.ljust(10) + ' : ' + str(info[k]))
    return SUCCESS


@exception_handler
def list_identities(args, client, logger, console, spinner):
    """
    %(prog)s list-identities [options] <field1=value1 field2=value2 ...>

    List all identities on an account.
    """
    table_data = []
    identities = client.list_identities(account=args.account)
    for identity in identities:
        if cli_config == 'rich':
            table_data.append([identity['identity'], identity['type']])
        else:
            print('Identity: %(identity)s,\ttype: %(type)s' % identity)
    if cli_config == 'rich':
        table = generate_table(table_data, headers=['IDENTITY', 'TYPE'], col_alignments=['left', 'left'])
        print_output(table, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def set_limits(args, client, logger, console, spinner):
    """
    %(prog)s set [options] <field1=value1 field2=value2 ...>

    Set account limit for an account and rse.
    """
    locality = args.locality.lower()
    byte_limit = None
    limit_input = args.bytes.lower()

    if limit_input == 'inf' or limit_input == 'infinity':
        byte_limit = -1
    else:
        byte_limit = get_bytes_value_from_string(limit_input)
        if not byte_limit:
            try:
                byte_limit = int(limit_input)
            except ValueError:
                msg = f'\
                    The limit could not be set. Either you misspelled infinity or your input ({args.bytes}) could not be converted to integer or you used a wrong pattern. \
                    Please use a format like 10GB with B,KB,MB,GB,TB,PB as units (not case sensitive)'
                raise InputValidationError(msg)

    client.set_account_limit(account=args.account, rse=args.rse, bytes_=byte_limit, locality=locality)
    print('Set account limit for account %s on RSE %s: %s' % (args.account, args.rse, sizefmt(byte_limit, True)))
    return SUCCESS


@exception_handler
def get_limits(args, client, logger, console, spinner):
    """
    %(prog)s get-limits [options] <field1=value1 field2=value2 ...>

    Grant an identity access to an account.

    """
    locality = args.locality.lower()
    limits = client.get_account_limits(account=args.account, rse_expression=args.rse, locality=locality)
    for rse in limits:
        print('Quota on %s for %s : %s' % (rse, args.account, sizefmt(limits[rse], True)))
    return SUCCESS


@exception_handler
def delete_limits(args, client, logger, console, spinner):
    """
    %(prog)s delete [options] <field1=value1 field2=value2 ...>

    Delete account limit for an account and rse.
    """
    client.delete_account_limit(account=args.account, rse=args.rse, locality=args.locality)
    print('Deleted account limit for account %s and RSE %s' % (args.account, args.rse))
    return SUCCESS


@exception_handler
def identity_add(args, client, logger, console, spinner):
    """
    %(prog)s del [options] <field1=value1 field2=value2 ...>

    Grant an identity access to an account.

    """
    if args.email == "":
        raise InputValidationError('Error: --email argument can\'t be an empty string. Failed to grant an identity access to an account')

    if args.authtype == 'USERPASS' and not args.password:
        raise InputValidationError('Missing --password argument')

    client.add_identity(account=args.account, identity=args.identity, authtype=args.authtype, email=args.email, password=args.password)
    print('Added new identity to account: %s-%s' % (args.identity, args.account))
    return SUCCESS


@exception_handler
def identity_delete(args, client, logger, console, spinner):
    """
    %(prog)s delete [options] <field1=value1 field2=value2 ...>

    Revoke an identity's access to an account.

    """
    client.del_identity(args.account, args.identity, authtype=args.authtype)
    print('Deleted identity: %s' % args.identity)
    return SUCCESS


@exception_handler
def add_rse(args, client, logger, console, spinner):
    """
    %(prog)s add [options] <field1=value1 field2=value2 ...>

    Adds a new RSE. Specify metadata fields as arguments.

    """
    client.add_rse(args.rse, deterministic=not args.non_deterministic)
    print('Added new %sdeterministic RSE: %s' % ('non-' if args.non_deterministic else '', args.rse))
    return SUCCESS


@exception_handler
def disable_rse(args, client, logger, console, spinner):
    """
    %(prog)s del [options] <field1=value1 field2=value2 ...>

    Disable RSE.

    """
    client.delete_rse(args.rse)
    return SUCCESS


@exception_handler
def list_rses(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List RSEs.

    """
    if cli_config == 'rich':
        spinner.update(status='Fetching RSEs')
        spinner.start()

    rses = client.list_rses()
    if args.csv:
        print(*(rse['rse'] for rse in rses), sep='\n')
    elif cli_config == 'rich':
        table_data = [[rse['rse']] for rse in sorted(rses, key=lambda elem: elem['rse'])]
        table = generate_table(table_data, headers=['RSE'], col_alignments=['left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for rse in rses:
            print(rse['rse'])
    return SUCCESS


@exception_handler
def update_rse(args, client, logger, console, spinner):
    """
    %(prog)s update [options] <field1=value1 field2=value2 ...>

    Update the settings of the RSE:
      deterministic, rse_type, staging_are, volatile, qos_class,
      availability_delete, availability_read, availability_write,
      city, country_name, latitude, longitude, region_code, time_zone

    Use '', 'None' or 'null' to wipe the value of following RSE settings:
      qos_class
    """
    if args.value in ['true', 'True', 'TRUE', '1']:
        args.value = True
    if args.value in ['false', 'False', 'FALSE', '0']:
        args.value = False
    params = {args.param: args.value}
    client.update_rse(args.rse, parameters=params)

    if isinstance(args.value, bool):
        args.value = str(args.value)

    print('Updated RSE %s settings %s to %s' % (args.rse, args.param, args.value if args.value.lower() not in ['', 'none', 'null'] else '[WIPED]'))
    return SUCCESS


@exception_handler
def info_rse(args, client, logger, console, spinner):
    """
    %(prog)s info [options] <field1=value1 field2=value2 ...>

    Show extended information of a given RSE

    """
    if cli_config == 'rich':
        spinner.update(status='Fetching RSE info')
        spinner.start()

    rseinfo = client.get_rse(rse=args.rse)
    attributes = client.list_rse_attributes(rse=args.rse)
    usage = client.get_rse_usage(rse=args.rse)
    rse_limits = client.get_rse_limits(args.rse)

    if cli_config == 'rich':
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.RSE_TYPE}
        output = []
        table_data = []
    else:
        print('Settings:')
        print('=========')
    for i, key in enumerate(sorted(rseinfo)):
        if cli_config == 'rich':
            if i == 0:
                output.append('[b]Settings:[/]')
            if key != 'protocols':
                table_data.append([key, Text(str(rseinfo[key]), style=keyword_styles.get(str(rseinfo[key]), 'default'))])
        else:
            if key != 'protocols':
                print('  ' + key + ': ' + str(rseinfo[key]))

    if cli_config == 'rich':
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        output.append(table)
        table_data = []
    else:
        print('Attributes:')
        print('===========')
    for i, attribute in enumerate(sorted(attributes)):
        if cli_config == 'rich':
            if i == 0:
                output.append('\n[b]Attributes:[/]')
            table_data.append([attribute, Text(str(attributes[attribute]), style=keyword_styles.get(str(attributes[attribute]), 'default'))])
        else:
            print('  ' + attribute + ': ' + str(attributes[attribute]))

    if cli_config == 'rich':
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        output.append(table)
    else:
        print('Protocols:')
        print('==========')
    for i, protocol in enumerate(sorted(rseinfo['protocols'], key=lambda x: x['scheme'])):
        if cli_config == 'rich':
            if i == 0:
                output.append('\n[b]Protocols:[/]')
            output.append(Padding.indent(Text(protocol['scheme'], style=CLITheme.SUBHEADER_HIGHLIGHT), 2))
        else:
            print('  ' + protocol['scheme'])

        table_data = []
        for item in sorted(protocol):
            if cli_config == 'rich':
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

        if cli_config == 'rich':
            table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
            output.append(Padding.indent(table, 2))

    if cli_config == 'rich':
        header = ['SOURCE', 'USED', 'FILES', 'FREE', 'TOTAL', 'UPDATED AT']
        key2id = {header[i].lower().replace(' ', '_'): i for i in range(len(header))}
        table_data = []
    else:
        print('Usage:')
        print('======')
    for i, elem in enumerate(sorted(usage, key=lambda x: x['source'])):
        if cli_config == 'rich':
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

    if cli_config == 'rich':
        if len(table_data) > 0:
            usage_table = generate_table(table_data, headers=header, col_alignments=['left', 'right', 'right', 'right', 'right', 'left'])
            output.append(usage_table)
        table_data = []
    else:
        print('RSE limits:')
        print('===========')
    for i, limit in enumerate(rse_limits):
        if cli_config == 'rich':
            if i == 0:
                output.append('\n[b]RSE limits:[/]')
            table_data.append([limit, str(rse_limits[limit]) + ' B'])
        else:
            print('  ' + limit + ': ' + str(rse_limits[limit]) + ' B')

    if cli_config == 'rich':
        if len(table_data) > 0:
            table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'right'])
            output.append(table)
        spinner.stop()
        print_output(*output, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def set_attribute_rse(args, client, logger, console, spinner):
    """
    %(prog)s set-attribute [options] <field1=value1 field2=value2 ...>

    Set RSE attributes.

    """
    client.add_rse_attribute(rse=args.rse, key=args.key, value=args.value)
    print('Added new RSE attribute for %s: %s-%s ' % (args.rse, args.key, args.value))
    return SUCCESS


@exception_handler
def get_attribute_rse(args, client, logger, console, spinner):
    """
    %(prog)s get-attribute [options] <field1=value1 field2=value2 ...>

    Get RSE attributes.

    """
    attributes = client.list_rse_attributes(rse=args.rse)
    if cli_config == 'rich':
        table_data = [(k, Text(str(v), style=CLITheme.BOOLEAN.get(str(v), 'default'))) for k, v in sorted(attributes.items())]
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for k in attributes:
            print(k + ': ' + str(attributes[k]))
    return SUCCESS


@exception_handler
def delete_attribute_rse(args, client, logger, console, spinner):
    """
    %(prog)s delete-attribute [options] <field1=value1 field2=value2 ...>

    Delete RSE attributes.

    """
    client.delete_rse_attribute(rse=args.rse, key=args.key)
    print('Deleted RSE attribute for %s: %s-%s ' % (args.rse, args.key, args.value))
    return SUCCESS


@exception_handler
def add_distance_rses(args, client, logger, console, spinner):
    """
    %(prog)s add-distance [options] SOURCE_RSE DEST_RSE

    Set the distance between two RSEs.
    """
    params = {'distance': args.distance}
    client.add_distance(args.source, args.destination, params)
    print('Set distance from %s to %s to %d' % (args.source, args.destination, args.distance))
    return SUCCESS


@exception_handler
def get_distance_rses(args, client, logger, console, spinner):
    """
    %(prog)s get-distance SOURCE_RSE DEST_RSE

    Retrieve the existing distance information between two RSEs.
    """
    distance_info = client.get_distance(args.source, args.destination)
    if cli_config == 'rich':
        if distance_info:
            table = generate_table([[args.source, args.destination, str(distance_info[0]['distance'])]], headers=['SOURCE', 'DESTINATION', 'DISTANCE'],
                                   col_alignments=['left', 'left', 'right'])
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(f"No distance set from {args.source} to {args.destination}")
    else:
        if distance_info:
            print('Distance information from %s to %s: distance=%d' % (args.source, args.destination, distance_info[0]['distance']))
        else:
            print("No distance set from %s to %s" % (args.source, args.destination))
    return SUCCESS


@exception_handler
def update_distance_rses(args, client, logger, console, spinner):
    """
    %(prog)s update-distance [options] SOURCE_RSE DEST_RSE

    Update the existing distance entry between two RSEs.
    """
    params = {}
    if args.distance is not None:
        params['distance'] = args.distance
    elif args.ranking is not None:
        params['distance'] = args.ranking
    client.update_distance(args.source, args.destination, params)
    print('Update distance information from %s to %s:' % (args.source, args.destination))
    if params.get('distance') is not None:
        print("- Distance set to %d" % params['distance'])
    return SUCCESS


@exception_handler
def delete_distance_rses(args, client, logger, console, spinner):
    """
    %(prog)s delete-distance [options] SOURCE_RSE DEST_RSE

    Update the existing distance entry between two RSEs.
    """
    client.delete_distance(args.source, args.destination)
    print('Deleted distance information from %s to %s.' % (args.source, args.destination))
    return SUCCESS


@exception_handler
def add_protocol_rse(args, client, logger, console, spinner):
    """
    %(prog)s add-protocol-rse [options] <rse>

    Add a new protocol handler for an RSE
    """
    proto = {'hostname': args.hostname,
             'scheme': args.scheme,
             'port': args.port,
             'impl': args.impl,
             'prefix': args.prefix}
    if args.domain_json:
        proto['domains'] = args.domain_json
    proto.setdefault('extended_attributes', {})
    if args.ext_attr_json:
        proto['extended_attributes'] = args.ext_attr_json
    if proto['scheme'] == 'srm' and not args.web_service_path:
        raise InputValidationError('Error: space-token and web-service-path must be provided for SRM endpoints.')
    if args.space_token:
        proto['extended_attributes']['space_token'] = args.space_token
    if args.web_service_path:
        proto['extended_attributes']['web_service_path'] = args.web_service_path
    # Rucio 1.14.1 chokes on an empty extended_attributes key.
    if not proto['extended_attributes']:
        del proto['extended_attributes']
    client.add_protocol(args.rse, proto)
    return SUCCESS


@exception_handler
def del_protocol_rse(args, client, logger, console, spinner):
    """
    %(prog)s delete-protocol-rse [options] <rse>

    Remove a protocol handler for a RSE
    """
    kwargs = {}
    if args.port:
        kwargs['port'] = args.port
    if args.hostname:
        kwargs['hostname'] = args.hostname
    client.delete_protocols(args.rse, args.scheme, **kwargs)


@exception_handler
def add_qos_policy(args, client, logger, console, spinner):
    """
    %(prog)s add-qos-policy <rse> <qos_policy>

    Add a QoS policy to an RSE.
    """
    client.add_qos_policy(args.rse, args.qos_policy)
    print('Added QoS policy to RSE %s: %s' % (args.rse, args.qos_policy))
    return SUCCESS


@exception_handler
def delete_qos_policy(args, client, logger, console, spinner):
    """
    %(prog)s delete-qos-policy <rse> <qos_policy>

    Delete a QoS policy from an RSE.
    """
    client.delete_qos_policy(args.rse, args.qos_policy)
    print('Deleted QoS policy from RSE %s: %s' % (args.rse, args.qos_policy))
    return SUCCESS


@exception_handler
def list_qos_policies(args, client, logger, console, spinner):
    """
    %(prog)s list-qos-policies <rse>

    List all QoS policies of an RSE.
    """
    if cli_config == 'rich':
        spinner.update(status='Fetching QoS policies')
        spinner.start()

    qos_policies = client.list_qos_policies(args.rse)
    if cli_config == 'rich':
        qos_policies = [[qos_policy] for qos_policy in sorted(qos_policies)]
        table = generate_table(qos_policies, headers=['QOS POLICY'], col_alignments=['left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for qos_policy in sorted(qos_policies):
            print(qos_policy)
    return SUCCESS


@exception_handler
def set_limit_rse(args, client, logger, console, spinner):
    """
    %(prog)s set-limit <rse> <name> <value>

    Set the RSE limit given the rse name and the name and value of the limit
    """
    try:
        args.value = int(args.value)
        if client.set_rse_limits(args.rse, args.name, args.value):
            logger.info('Set RSE limit successfully for %s: %s = %s', args.rse, args.name, args.value)
    except ValueError:
        logger.error('The RSE limit value must be an integer')

    return SUCCESS


@exception_handler
def delete_limit_rse(args, client, logger, console, spinner):
    """
    %(prog)s delete-limit <rse> <name>

    Delete the RSE limit given the rse name and the name of the limit
    """
    limits = client.get_rse_limits(args.rse)
    if args.name not in limits.keys():
        logger.error('Limit %s not defined in RSE %s', args.name, args.rse)
    else:
        if client.delete_rse_limits(args.rse, args.name):
            logger.info('Deleted RSE limit successfully for %s: %s', args.rse, args.name)

    return SUCCESS


@exception_handler
def add_scope(args, client, logger, console, spinner):
    """
    %(prog)s add [options] <field1=value1 field2=value2 ...>

    Add scope.

    """
    client.add_scope(account=args.account, scope=args.scope)
    print(f'Added new scope to {args.account}: {args.scope}')
    return SUCCESS


@exception_handler
def list_scopes(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List scopes.

    """
    if (cli_config == 'rich') and (not args.csv):
        spinner.update(status='Fetching scopes')
        spinner.start()

    if args.account:
        scopes = client.list_scopes_for_account(args.account)
    else:
        scopes = client.list_scopes()
    if (cli_config == 'rich') and (not args.csv):
        scopes = [[scope] for scope in sorted(scopes)]
        table = generate_table(scopes, headers=['SCOPE'], col_alignments=['left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for scope in scopes:
            print(scope)
    return SUCCESS


@exception_handler
def get_config(args, client, logger, console, spinner):
    """
    %(prog)s get [options] <field1=value1 field2=value2 ...>

    Get the configuration. Either everything, or matching the given section/option.
    """
    res = client.get_config(section=args.section, option=args.option)
    if not isinstance(res, dict):
        print('[%s]\n%s=%s' % (args.section, args.option, str(res)))
    else:
        print_header = True
        for i in list(res.keys()):
            if print_header:
                if args.section is not None:
                    print('[%s]' % args.section)
                else:
                    print('[%s]' % i)
            if not isinstance(res[i], dict):
                print('%s=%s' % (i, str(res[i])))
                print_header = False
            else:
                for j in list(res[i].keys()):
                    print('%s=%s' % (j, str(res[i][j])))
    return SUCCESS


@exception_handler
def set_config_option(args, client, logger, console, spinner):
    """
    %(prog)s set [options] <field1=value1 field2=value2 ...>

    Set the configuration value for a matching section/option. Missing section/option will be created.
    """
    client.set_config_option(section=args.section, option=args.option, value=args.value)
    print('Set configuration: %s.%s=%s' % (args.section, args.option, args.value))
    return SUCCESS


@exception_handler
def delete_config_option(args, client, logger, console, spinner):
    """
    %(prog)s delete [options] <field1=value1 field2=value2 ...>

    Delete a configuration option from a section
    """
    if client.delete_config_option(section=args.section, option=args.option):
        print('Deleted section \'%s\' option \'%s\'' % (args.section, args.option))
    else:
        print('Section \'%s\' option \'%s\' not found' % (args.section, args.option))
    return SUCCESS


@exception_handler
def add_subscription(args, client, logger, console, spinner):
    """
    %(prog)s add [options] name Filter replication_rules

    Add subscription.

    """
    if args.subs_account:
        account = args.subs_account
    elif args.issuer:
        account = args.issuer
    else:
        account = client.account
    subscription_id = client.add_subscription(name=args.name, account=account, filter_=json.loads(args.filter), replication_rules=json.loads(args.replication_rules),
                                              comments=args.comments, lifetime=args.lifetime, retroactive=False, dry_run=False, priority=args.priority)
    print('Subscription added %s' % (subscription_id))
    return SUCCESS


@exception_handler
def list_subscriptions(args, client, logger, console, spinner):
    """
    %(prog)s list [options] [name]

    List subscriptions.

    """
    if args.subs_account:
        account = args.subs_account
    elif args.issuer:
        account = args.issuer
    else:
        account = client.account

    if cli_config == 'rich':
        spinner.update(status='Fetching subscriptions')
        spinner.start()
        keyword_styles = {**CLITheme.SUBSCRIPTION_STATE, **CLITheme.BOOLEAN}

    subs = client.list_subscriptions(name=args.name, account=account)
    for sub in subs:
        table_data = []
        if args.long:
            if cli_config == 'rich':
                for k, v in sorted(sub.items()):
                    if k == 'filter':
                        filter_tree = Tree('')
                        for filter, values in json.loads(sub['filter']).items():
                            values_str = ', '.join(values)
                            filter_tree.add(f'[{CLITheme.JSON_STR}]{filter}[/]: {values_str}')
                        table_data.append(['filter', filter_tree])
                    elif k == 'replication_rules':
                        rule_tree = Tree('')
                        for i, rule in enumerate(json.loads(sub['replication_rules'])):
                            branch = rule_tree.add(Text('rule:', style='default'))
                            for k, v in rule.items():
                                branch.add(f'[{CLITheme.JSON_STR}]{k}[/]: {v}')
                        table_data.append(['replication_rules', rule_tree])
                    else:
                        table_data.append([str(k), Text(str(v), style=keyword_styles.get(str(v), 'default'))])
            else:
                print('\n'.join('%s: %s' % (str(k), str(v)) for (k, v) in list(sub.items())))
                print()
        else:
            if cli_config == 'rich':
                table_data.append(['account', sub['account']])
                table_data.append(['comments', sub.get('comments', '')])
                filter_tree = Tree('')
                for filter, values in json.loads(sub['filter']).items():
                    values_str = ', '.join(values)
                    filter_tree.add(f'[green]{filter}[/]: {values_str}')
                table_data.append(['filter', filter_tree])
                table_data.append(['name', sub['name']])
                table_data.append(['policyid', str(sub['policyid'])])
                rule_tree = Tree('')
                for i, rule in enumerate(json.loads(sub['replication_rules'])):
                    branch = rule_tree.add(Text('rule:', style='default'))
                    for k, v in rule.items():
                        branch.add(f'[{CLITheme.JSON_STR}]{k}[/]: {v}')
                table_data.append(['replication_rules', rule_tree])
                table_data.append(['state', Text(str(sub['state']), keyword_styles.get(str(sub['state']), 'default'))])
            else:
                print("%s: %s %s\n  priority: %s\n  filter: %s\n  rules: %s\n  comments: %s" % (sub['account'], sub['name'], sub['state'], sub['policyid'], sub['filter'], sub['replication_rules'], sub.get('comments', '')))

        if cli_config == 'rich':
            table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def update_subscription(args, client, logger, console, spinner):
    """
    %(prog)s update [options] name filter replication_rules

    Update a subscription.

    """
    if args.subs_account:
        account = args.subs_account
    elif args.issuer:
        account = args.issuer
    else:
        account = client.account
    client.update_subscription(name=args.name, account=account, filter_=json.loads(args.filter), replication_rules=json.loads(args.replication_rules),
                               comments=args.comments, lifetime=args.lifetime, retroactive=False, dry_run=False, priority=args.priority)
    return SUCCESS


@exception_handler
def reevaluate_did_for_subscription(args, client, logger, console, spinner):
    """
    %(prog)s reevaulate [options] dids

    Reevaluate a list of DIDs against all active subscriptions.

    """
    for did in args.dids.split(','):
        scope, name = get_scope(did, client)
        client.set_metadata(scope, name, 'is_new', True)
    return SUCCESS


@exception_handler
def list_account_attributes(args, client, logger, console, spinner):
    """
    %(prog)s show [options] <field1=value1 field2=value2 ...>

    List the attributes for an account.

    """
    account = args.account or client.account
    attributes = next(client.list_account_attributes(account))
    table_data = []
    for attr in attributes:
        table_data.append([attr['key'], attr['value']])

    if cli_config == 'rich':
        table = generate_table(table_data, headers=['Key', 'Value'], col_alignments=['left', 'left'])
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        print(tabulate(table_data, tablefmt=tablefmt, headers=['Key', 'Value']))
    return SUCCESS


@exception_handler
def add_account_attribute(args, client, logger, console, spinner):
    """
    %(prog)s show [options] <field1=value1 field2=value2 ...>

    Add attribute for an account.

    """
    client.add_account_attribute(account=args.account, key=args.key, value=args.value)
    return SUCCESS


@exception_handler
def delete_account_attribute(args, client, logger, console, spinner):
    """
    %(prog)s show [options] <field1=value1 field2=value2 ...>

    Delete attribute for an account.

    """
    client.delete_account_attribute(account=args.account, key=args.key)
    return SUCCESS


@exception_handler
def quarantine_replicas(args, client, logger, console, spinner):
    """
    %(prog)s quarantine --rse <rse> (--paths <file with replica paths>|<path> ...)
    Quarantine replicas
    """
    chunk = []

    # send requests in chunks
    chunk_size = 1000

    rse = args.rse
    if args.paths_list:
        replicas_list = args.paths_list
    else:
        replicas_list = open(args.paths_file, "r")     # will iterate over file lines

    for line in replicas_list:
        path = line.strip()
        if path:                                        # skip blank lines
            chunk.append(dict(path=path))
            if len(chunk) >= chunk_size:
                client.quarantine_replicas(chunk, rse=rse)
                chunk = []
    if chunk:
        client.quarantine_replicas(chunk, rse=rse)
    return SUCCESS


def __declare_bad_file_replicas_by_lfns(args: object, client) -> object:
    """
    Declare a list of bad replicas using RSE name, scope and list of LFNs.
    """
    if not args.scope or not args.rse:
        raise InputValidationError("--lfns requires using --rse and --scope")
    reason = args.reason
    scope = args.scope
    rse = args.rse
    replicas = []

    # send requests in chunks
    chunk_size = 10000

    def do_declare(client, lst, reason):
        non_declared = client.declare_bad_file_replicas(lst, reason)
        for rse, undeclared in non_declared.items():
            for r in undeclared:
                print(f'{rse} : replica cannot be declared: {r}')

    for line in open(args.lfns, "r"):
        lfn = line.strip()
        if lfn:
            replicas.append({"scope": scope, "rse": rse, "name": lfn})
            if len(replicas) >= chunk_size:
                do_declare(client, replicas, reason)
                replicas = []
    if replicas:
        do_declare(client, replicas, reason)
    return SUCCESS


@exception_handler
def declare_bad_file_replicas(args, client, logger, console, spinner):
    """

    Declare replicas as bad.

    """

    if args.lfns:
        return __declare_bad_file_replicas_by_lfns(args, client)

    if args.inputfile:
        with open(args.inputfile) as infile:
            bad_files = list(filter(None, [line.strip() for line in infile]))
    else:
        bad_files = args.listbadfiles

    # Interpret filenames not in scheme://* format as LFNs and convert them to PFNs
    bad_files_pfns = []
    for bad_file in bad_files:
        if bad_file.find('://') == -1:
            scope, name = get_scope(bad_file, client)
            did_info = client.get_did(scope, name)
            if did_info['type'].upper() != 'FILE' and not args.allow_collection:
                msg = f'DID {scope}:{name} is a collection and --allow-collection was not specified.'
                raise InputValidationError(msg)
            replicas = [replica for rep in client.list_replicas([{'scope': scope, 'name': name}])
                        for replica in list(rep['pfns'].keys())]
            bad_files_pfns.extend(replicas)
        else:
            bad_files_pfns.append(bad_file)
    if args.verbose:
        print("PFNs that will be declared bad:")
        for pfn in bad_files_pfns:
            print(pfn)

    if len(bad_files_pfns) < 100:
        # Using the old API to declare
        non_declared = client.declare_bad_file_replicas(bad_files_pfns, args.reason)
        for rse in non_declared:
            for pfn in non_declared[rse]:
                print('%s : PFN %s cannot be declared.' % (rse, pfn))
    else:
        print('Getting the information about RSE protocols. It can take several seconds')
        dict_rse = client.export_data(distance=False)
        prot_dict = {}
        for rse, dict_attr in dict_rse['rses'].items():
            protocols = dict_attr['protocols']
            for prot in protocols:
                prot_dict[str('%s://%s%s' % (prot['scheme'], prot['hostname'], prot['prefix']))] = rse
                prot_dict[str('%s://%s:%s%s' % (prot['scheme'], prot['hostname'], prot['port'], prot['prefix']))] = rse
        print('Protocol information retrieved')

        chunk_size = 10000
        print('Starting the declaration by chunks of %s' % chunk_size)
        tot_files = len(bad_files)
        tot_file_declared = 0
        cnt = 0
        nchunk = math.ceil(tot_files / chunk_size)
        for chunk in chunks(bad_files_pfns, chunk_size):
            list_bad_pfns = []
            cnt += 1
            previous_pattern = None
            for pfn in clean_pfns(chunk):
                unknown = True
                if previous_pattern:
                    if previous_pattern in pfn:
                        list_bad_pfns.append(pfn)
                        unknown = False
                        continue
                for pattern in prot_dict:
                    if pattern in pfn:
                        previous_pattern = prot_dict[pattern]
                        list_bad_pfns.append(pfn)
                        unknown = False
                        break
                if unknown:
                    print('Cannot find any RSE associated to %s' % pfn)
            client.add_bad_pfns(pfns=list_bad_pfns, reason=args.reason, state='BAD', expires_at=None)
            ndeclared = len(list_bad_pfns)
            tot_file_declared += ndeclared
            print('Chunk %s/%s : %s replicas successfully declared' % (int(cnt), int(nchunk), ndeclared))
        print('--------------------------------')
        print('Summary')
        print('%s/%s replicas successfully declared' % (tot_file_declared, tot_files))

    return SUCCESS


@exception_handler
def declare_temporary_unavailable_replicas(args, client, logger, console, spinner):
    """
    %(prog)s show [options] <field1=value1 field2=value2 ...>

    Declare a list of temporary unavailable replicas.

    """
    bad_files = []
    if args.inputfile:
        with open(args.inputfile) as infile:
            for line in infile:
                bad_file = line.rstrip('\n')
                if '://' not in bad_file:
                    msg = f'{bad_file} is not a valid PFN. Aborting'
                    raise InvalidObject(msg)
                if bad_file != '':
                    bad_files.append(bad_file)
    else:
        bad_files = args.listbadfiles

    if args.duration is None:
        raise InputValidationError("Duration should have been set, something went wrong!")

    expiration_date = (datetime.datetime.utcnow() + datetime.timedelta(seconds=args.duration)).isoformat()

    chunk_size = 10000
    tot_files = len(bad_files)
    cnt = 0
    nchunk = math.ceil(tot_files / chunk_size)
    for chunk in chunks(bad_files, chunk_size):
        cnt += 1
        client.add_bad_pfns(pfns=chunk, reason=args.reason, state='TEMPORARY_UNAVAILABLE', expires_at=expiration_date)
        ndeclared = len(chunk)
        print('Chunk %s/%s : %s replicas successfully declared' % (int(cnt), int(nchunk), ndeclared))
    print('--------------------------------')
    print('Summary')
    print('%s replicas successfully declared' % tot_files)

    return SUCCESS


@exception_handler
def list_pfns(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List the possible PFN for a file at a site.

    """
    dids = args.dids.split(',')
    rse = args.rse
    protocol = args.protocol
    for input_did in dids:
        scope, name = get_scope(input_did, client)
        replicas = [rep for rep in client.list_replicas([{'scope': scope, 'name': name}, ], schemes=[protocol, ])]
        if rse in replicas[0]['rses'] and replicas[0]['rses'][rse]:
            print(replicas[0]['rses'][rse][0])
        else:
            logger.warning('The file has no replica on the specified RSE')
            rse_info = rsemgr.get_rse_info(rse, vo=client.vo)
            proto = rsemgr.create_protocol(rse_info, 'read', scheme=protocol)
            try:
                pfn = proto.lfns2pfns(lfns={'scope': scope, 'name': name})
                result = list(pfn.values())[0]
            except ReplicaNotFound as error:
                result = error
            if isinstance(result, (RSEOperationNotSupported, ReplicaNotFound)):
                if not rse_info['deterministic']:
                    logger.warning('This is a non-deterministic site, so the real PFN might be different from the on suggested')
                    rse_attr = client.list_rse_attributes(rse)
                    naming_convention = rse_attr.get(RseAttr.NAMING_CONVENTION, None)
                    parents = [did for did in client.list_parent_dids(scope, name)]
                    if len(parents) > 1:
                        logger.warning('The file has multiple parents')
                    for did in parents:
                        if did['type'] == 'DATASET':
                            path = construct_non_deterministic_pfn(did['name'], scope, name, naming_convention=naming_convention)
                            pfn = ''.join([proto.attributes['scheme'],
                                           '://',
                                           proto.attributes['hostname'],
                                           ':',
                                           str(proto.attributes['port']),
                                           proto.attributes['prefix'],
                                           path if not path.startswith('/') else path[1:]])
                            print(pfn)
                else:
                    raise RucioException
            else:
                print(result)
    return SUCCESS


@exception_handler
def import_data(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    Import data from JSON file to Rucio.

    """
    import_file_path = args.file_path
    data = None
    if cli_config == 'rich':
        spinner.update(status='Reading file')
        spinner.start()

    try:
        with open(import_file_path) as import_file:
            data_string = import_file.read()
            data = parse_response(data_string)
    except ValueError as error:
        if cli_config == 'rich':
            spinner.stop()
            print_output(f'{CLITheme.FAILURE_ICON} There was problem with decoding your file.', console=console, no_pager=True)
            logger.error(error)
        else:
            print('There was problem with decoding your file.')
            print(error)
        raise ValueError from error
    except OSError as error:
        if cli_config == 'rich':
            spinner.stop()
            print_output(f'{CLITheme.FAILURE_ICON} There was a problem with reading your file.', console=console, no_pager=True)
            logger.error(error)
        else:
            print('There was a problem with reading your file.')
            print(error)
        raise OSError from error

    if data:
        client.import_data(data)
        if cli_config == 'rich':
            spinner.stop()
            print_output(f'{CLITheme.SUCCESS_ICON} Data successfully imported.', console=console, no_pager=True)
        else:
            print('Data successfully imported.')
        return SUCCESS
    else:
        if cli_config == 'rich':
            spinner.stop()
            print_output('Nothing to import.', console=console, no_pager=True)
        else:
            print('Nothing to import.')
        raise ValueError


@exception_handler
def export_data(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    Export data from Rucio to JSON file.

    """
    destination_file_path = args.file_path
    if cli_config == 'rich':
        spinner.update(status='Querying data')
        spinner.start()
    else:
        print('Start querying data.')

    data = client.export_data()
    try:
        with open(destination_file_path, 'w+') as destination_file:
            destination_file.write(render_json(**data))
            if cli_config != 'rich':
                print('File successfully written.')
        if cli_config == 'rich':
            spinner.stop()
            print_output(f'{CLITheme.SUCCESS_ICON} Data successfully exported to {args.file_path}', console=console, no_pager=True)
        else:
            print('Data successfully exported to %s' % args.file_path)
        return SUCCESS
    except OSError as error:
        if cli_config == 'rich':
            spinner.stop()
            print_output(f'{CLITheme.FAILURE_ICON} There was a problem with reading your file.', console=console, no_pager=True)
            logger.error(error)
        else:
            print('There was a problem with reading your file.')
            print(error)
        raise OSError from error


@exception_handler
def set_tombstone(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    Set a tombstone on a list of replicas.
    """
    dids = args.dids
    rse = args.rse
    dids = [dids] if ',' not in dids else dids.split(',')
    replicas = []
    for did in dids:
        scope, name = get_scope(did, client)
        replicas.append({'scope': scope, 'name': name, 'rse': rse})
    client.set_tombstone(replicas)
    logger.info('Set tombstone successfully on: %s', args.dids)
    return SUCCESS


def get_parser():
    """
    Returns the argparse parser.
    """
    oparser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]), add_help=True)

    # required argument was added in Python 3.7 and restores the Python 2 behavior
    required_arg = {'required': True}

    subparsers = oparser.add_subparsers(dest='subcommand', **required_arg)

    # Main arguments
    oparser.add_argument('--version', action='version', version='%(prog)s ' + version.version_string())
    oparser.add_argument('--verbose', '-v', default=False, action='store_true', help="Print more verbose output")
    oparser.add_argument('-H', '--host', dest="host", metavar="ADDRESS", help="The Rucio API host")
    oparser.add_argument('--auth-host', dest="auth_host", metavar="ADDRESS", help="The Rucio Authentication host")
    oparser.add_argument('-a', '--account', dest="issuer", metavar="ACCOUNT", help="Rucio account to use")
    oparser.add_argument('-S', '--auth-strategy', dest="auth_strategy", default=None, help="Authentication strategy (userpass, x509, ssh ...)")
    oparser.add_argument('-T', '--timeout', dest="timeout", type=float, default=None, help="Set all timeout values to SECONDS")
    oparser.add_argument('--user-agent', '-U', dest="user_agent", default='rucio-clients', action='store', help="Rucio User Agent")
    oparser.add_argument('--vo', dest="vo", metavar="VO", default=None, help="VO to authenticate at. Only used in multi-VO mode.")
    oparser.add_argument("--no-pager", dest="no_pager", default=False, action='store_true', help=argparse.SUPPRESS)

    # Options for the userpass auth_strategy
    oparser.add_argument('-u', '--user', dest='username', default=None, help='username')
    oparser.add_argument('-pwd', '--password', dest='password', default=None, help='password')
    # Options for defining the OIDC scope# Options for defining remaining OIDC parameters
    oparser.add_argument('--oidc-user', dest='oidc_username', default=None, help='OIDC username')
    oparser.add_argument('--oidc-password', dest='oidc_password', default=None, help='OIDC password')
    oparser.add_argument('--oidc-scope', dest='oidc_scope', default='openid profile', help='Defines which (OIDC) information user will share with Rucio. '
                         + 'Rucio requires at least -sc="openid profile". To request refresh token for Rucio, scope must include "openid offline_access" and '
                         + 'there must be no active access token saved on the side of the currently used Rucio Client.')
    oparser.add_argument('--oidc-audience', dest='oidc_audience', default=None, help='Defines which audience are tokens requested for.')
    oparser.add_argument('--oidc-auto', dest='oidc_auto', default=False, action='store_true', help='If not specified, username and password credentials are not required and users will be given a URL '
                         + 'to use in their browser. If specified, the users explicitly trust Rucio with their IdP credentials.')
    oparser.add_argument('--oidc-polling', dest='oidc_polling', default=False, action='store_true', help='If not specified, user will be asked to enter a code returned by the browser to the command line. '
                         + 'If --polling is set, Rucio Client should get the token without any further interaction of the user. This option is active only if --auto is *not* specified.')
    oparser.add_argument('--oidc-refresh-lifetime', dest='oidc_refresh_lifetime', default=None, help='Max lifetime in hours for this an access token will be refreshed by asynchronous Rucio daemon. '
                         + 'If not specified, refresh will be stopped after 4 days. This option is effective only if --oidc-scope includes offline_access scope for a refresh token to be granted to Rucio.')
    oparser.add_argument('--oidc-issuer', dest='oidc_issuer', default=None,
                         help='Defines which Identity Provider is going to be used. The issuer string must correspond '
                         + 'to the keys configured in the /etc/idpsecrets.json auth server configuration file.')

    # Options for the x509  auth_strategy
    oparser.add_argument('--certificate', dest='certificate', default=None, help='Client certificate file')
    oparser.add_argument('--client-key', dest='client_key', default=None, help='Client key for x509 Authentication.')
    oparser.add_argument('--ca-certificate', dest='ca_certificate', default=None, help='CA certificate to verify peer against (SSL)')

    # The import export subparser
    data_parser = subparsers.add_parser('data', help='Import and export data')
    data_subparsers = data_parser.add_subparsers(dest='data_subcommand', **required_arg)

    # The import command
    import_parser = data_subparsers.add_parser('import',
                                               help='Import data to Rucio from JSON file.',
                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                               epilog='Usage example\n'
                                                      '"""""""""""""\n'
                                                      'Import data from the file file.json::\n'
                                                      '\n'
                                                      '    $ rucio-admin data import file.json\n'
                                                      '\n')
    import_parser.add_argument('file_path', action='store', help='File path.')
    import_parser.set_defaults(which='import')

    # The export command
    export_parser = data_subparsers.add_parser('export',
                                               help='Export data from  Rucio to JSON file.',
                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                               epilog='Usage example\n'
                                                      '"""""""""""""\n'
                                                      'Export data to the file file.json::\n'
                                                      '\n'
                                                      '    $ rucio-admin data export file.json\n'
                                                      '\n')
    export_parser.add_argument('file_path', action='store', help='File path.')
    export_parser.set_defaults(which='export')

    # The account subparser
    account_parser = subparsers.add_parser('account', help='Account methods')
    account_subparser = account_parser.add_subparsers(dest='account_subcommand', **required_arg)

    # The list_accounts command
    list_account_parser = account_subparser.add_parser('list',
                                                       help='List Rucio accounts.',
                                                       formatter_class=argparse.RawDescriptionHelpFormatter,
                                                       epilog='Usage example\n'
                                                              '"""""""""""""\n'
                                                              '::\n'
                                                              '\n'
                                                              '    $ rucio-admin account list --type USER\n'
                                                              '\n')
    list_account_parser.add_argument('--type', dest='account_type', action='store', help='Account Type (USER, GROUP, SERVICE)')
    list_account_parser.add_argument('--id', dest='identity', action='store', help='Identity (e.g. DN)')
    list_account_parser.add_argument('--filters', dest='filters', action='store', help='Filter arguments in form `key=value,another_key=next_value`')
    list_account_parser.add_argument("--csv", action='store_true', help='List result as a csv')
    list_account_parser.set_defaults(which='list_accounts')

    # The list_account_attributes command
    list_attr_parser = account_subparser.add_parser('list-attributes',
                                                    help='List attributes for an account.',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    epilog='Usage example\n'
                                                           '"""""""""""""\n'
                                                           '::\n'
                                                           '\n'
                                                           '    $ rucio-admin account list-attributes jdoe\n'
                                                           '    +-------+---------+\n'
                                                           '    | Key   | Value   |\n'
                                                           '    |-------+---------|\n'
                                                           '    | admin | False   |\n'
                                                           '    +-------+---------+\n'
                                                           '\n'
                                                           'Note: this table empty in most cases.\n'
                                                           '\n')
    list_attr_parser.add_argument('account', action='store', help='Account name')
    list_attr_parser.set_defaults(which='list_account_attributes')

    # The add_account_attribute command
    add_attr_parser = account_subparser.add_parser('add-attribute',
                                                   help='Add attribute for an account.',
                                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                                   epilog='Usage example\n'
                                                          '"""""""""""""\n'
                                                          '::\n'
                                                          '\n'
                                                          '    $ rucio-admin account add-attribute --key \'test\' --value true jdoe\n'
                                                          '\n'
                                                          'Note: no printed stdout.\n'
                                                          '\n')
    add_attr_parser.add_argument('account', action='store', help='Account name')
    add_attr_parser.add_argument('--key', dest='key', action='store', help='Attribute key', required=True)
    add_attr_parser.add_argument('--value', dest='value', action='store', help='Attribute value', required=True)
    add_attr_parser.set_defaults(which='add_account_attribute')

    # The delete_account_attribute command
    delete_attr_parser = account_subparser.add_parser('delete-attribute',
                                                      help='Delete attribute for an account.',
                                                      formatter_class=argparse.RawDescriptionHelpFormatter,
                                                      epilog='Usage example\n'
                                                             '"""""""""""""\n'
                                                             '::\n'
                                                             '\n'
                                                             '   $ rucio-admin account delete-attribute --key \'test\' jdoe\n'
                                                             '\n'
                                                             'Note: no printed stdout.\n'
                                                             '\n')
    delete_attr_parser.add_argument('account', action='store', help='Account name')
    delete_attr_parser.add_argument('--key', dest='key', action='store', help='Attribute key', required=True)
    delete_attr_parser.set_defaults(which='delete_account_attribute')

    # The add_account command
    add_account_parser = account_subparser.add_parser('add',
                                                      help='Add Rucio account.',
                                                      formatter_class=argparse.RawDescriptionHelpFormatter,
                                                      epilog='Usage example\n'
                                                             '"""""""""""""\n'
                                                             '::\n'
                                                             '\n'
                                                             '    $ rucio-admin account add jdoe-sister\n'
                                                             '    Added new account: jdoe-sister\n'
                                                             '\n')
    add_account_parser.set_defaults(which='add_account')
    add_account_parser.add_argument('account', action='store', help='Account name')
    add_account_parser.add_argument('--type', dest='account_type', default='USER', help='Account Type (USER, GROUP, SERVICE)')
    add_account_parser.add_argument('--email', dest='email', action='store',
                                    help='Email address associated with the account')

    # The disable_account command
    delete_account_parser = account_subparser.add_parser('delete',
                                                         help='Delete Rucio account.',
                                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                                         epilog='Usage example\n'
                                                                '"""""""""""""\n'
                                                                '::\n'
                                                                '\n'
                                                                '    $ rucio-admin account delete jdoe-sister\n'
                                                                '    Deleted account: jdoe-sister\n'
                                                                '\n')
    delete_account_parser.set_defaults(which='delete_account')
    delete_account_parser.add_argument('account', action='store', help='Account name')

    # The info_account command
    info_account_parser = account_subparser.add_parser('info',
                                                       help='Show detailed information about an account.',
                                                       formatter_class=argparse.RawDescriptionHelpFormatter,
                                                       epilog='Usage example\n'
                                                              '"""""""""""""\n'
                                                              '::\n'
                                                              '\n'
                                                              '    $ rucio-admin account info jdoe\n'
                                                              '    status     : ACTIVE\n'
                                                              '    account    : jdoe\n'
                                                              '    account_type : SERVICE\n'
                                                              '    created_at : 2015-02-03T15:51:16\n'
                                                              '    suspended_at : None\n'
                                                              '    updated_at : 2015-02-03T15:51:16\n'
                                                              '    deleted_at : None\n'
                                                              '    email      : None\n'
                                                              '\n')
    info_account_parser.set_defaults(which='info_account')
    info_account_parser.add_argument('account', action='store', help='Account name')

    # The list_account_identities command
    list_account_identities_parser = account_subparser.add_parser('list-identities',
                                                                  help='List all identities (DNs) on an account.',
                                                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                                                  epilog='Usage example\n'
                                                                         '"""""""""""""\n'
                                                                         '::\n'
                                                                         '\n'
                                                                         '    $ rucio-admin account list-identities jdoe\n'
                                                                         '    Identity: CN=Joe Doe,OU=Desy,O=GermanGrid,C=DE, type: X509\n'
                                                                         '    Identity: jdoe@CERN.CH,  type: GSS\n'
                                                                         '    Identity: CN=Joe Doe,CN=707654,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch, type: X509\n'
                                                                         '\n')
    list_account_identities_parser.set_defaults(which='list_identities')
    list_account_identities_parser.add_argument('account', action='store', help='Account name')

    # The set-limits command
    set_account_limits_parser = account_subparser.add_parser('set-limits',
                                                             help='Set the limits for the provided account at given RSE.',
                                                             formatter_class=argparse.RawDescriptionHelpFormatter,
                                                             epilog='Usage example\n'
                                                                    '"""""""""""""\n'
                                                                    '::\n'
                                                                    '\n'
                                                                    '    $ rucio-admin account set-limits jdoe DESY-ZN_DATADISK 1000000000000\n'
                                                                    '    Set account limit for account jdoe on RSE DESY-ZN_DATADISK: 1.000 TB\n'
                                                                    '\n'
                                                                    'Note: the order of perameters is fixed: account, rse, bytes.\n'
                                                                    '\n')
    set_account_limits_parser.set_defaults(which='set_limits')
    set_account_limits_parser.add_argument('account', action='store', help='Account name')
    set_account_limits_parser.add_argument('rse', action='store', help='RSE boolean expression')
    set_account_limits_parser.add_argument('bytes', action='store', help='Value can be specified in bytes ("10000"), with a storage unit ("10GB"), or "infinity"')
    set_account_limits_parser.add_argument('locality', action='store', nargs='?', default='local', choices=['local', 'global'], help='Global or local limit scope. Default: "local"')

    # The account-limit subparser
    get_account_limits_parser = account_subparser.add_parser('get-limits',
                                                             help='To get the account limits on an RSE.',
                                                             formatter_class=argparse.RawDescriptionHelpFormatter,
                                                             epilog='Usage example\n'
                                                                    '"""""""""""""\n'
                                                                    '::\n'
                                                                    '\n'
                                                                    '    $ rucio-admin account get-limits jdoe DESY-ZN_DATADISK\n'
                                                                    '    Quota on DESY-ZN_DATADISK for jdoe : 1.000 TB\n'
                                                                    'Note: the order of parameters is fixed: account, rse.\n'
                                                                    '\n')
    get_account_limits_parser.set_defaults(which='get_limits')
    get_account_limits_parser.add_argument('account', action='store', help='Account name')
    get_account_limits_parser.add_argument('rse', action='store', help='The RSE name')
    get_account_limits_parser.add_argument('locality', action='store', nargs='?', default='local', choices=['local', 'global'], help='Global or local limit scope. Default: "local"')

    # The delete_quota command
    delete_account_limits_parser = account_subparser.add_parser('delete-limits',
                                                                help='Delete limites for an account at given RSE.',
                                                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                                                epilog='Usage example\n'
                                                                       '"""""""""""""\n'
                                                                       '::\n'
                                                                       '\n'
                                                                       '    $ rucio-admain account delete-limits jdoe DESY-ZN_DATADISK\n'
                                                                       '    Deleted account limit for account jdoe and RSE DESY-ZN_DATADISK\n'
                                                                       '\n'
                                                                       'Note: the order of parameters is fixed: account, rse.\n'
                                                                       '\n')
    delete_account_limits_parser.set_defaults(which='delete_limits')
    delete_account_limits_parser.add_argument('account', action='store', help='Account name')
    delete_account_limits_parser.add_argument('rse', action='store', help='RSE name')
    delete_account_limits_parser.add_argument('locality', action='store', nargs='?', default='local', choices=['local', 'global'], help='Global or local limit scope. Default: "local"')

    # Ban/unban operations not implemented yet
    ban_account_limits_parser = account_subparser.add_parser('ban',
                                                             help='Disable an account.',
                                                             formatter_class=argparse.RawDescriptionHelpFormatter,
                                                             epilog='Usage example\n'
                                                                    '"""""""""""""\n'
                                                                    '::\n'
                                                                    '\n'
                                                                    '    $ rucio-admin account ban --account jdoe\n'
                                                                    '    Account jdoe banned\n'
                                                                    '\n'
                                                                    'Note: in case of accidental ban, use unban.\n'
                                                                    'CAUTION: the account is completely disabled.\n'
                                                                    '\n')
    ban_account_limits_parser.set_defaults(which='ban_account')
    ban_account_limits_parser.add_argument('--account', dest='account', action='store', help='Account name', required=True)

    unban_account_limits_parser = account_subparser.add_parser('unban',
                                                               help='Unban a banned account. The account is mandatory parameter.',
                                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                                               epilog='Usage example\n'
                                                                      '"""""""""""""\n'
                                                                      '::\n'
                                                                      '\n'
                                                                      '    $ rucio-admin account unban --account jdoe\n'
                                                                      '    Account jdoe unbanned\n'
                                                                      '\n')
    unban_account_limits_parser.set_defaults(which='unban_account')
    unban_account_limits_parser.add_argument('--account', dest='account', action='store', help='Account name', required=True)

    # Update account subparser
    update_account_parser = account_subparser.add_parser('update',
                                                         help='Update an account.',
                                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                                         epilog='Usage example\n'
                                                                '"""""""""""""\n'
                                                                '::\n'
                                                                '\n'
                                                                '    $ rucio-admin account update --account jdoe --key email --value test\n'
                                                                '    Account jdoe updated\n'
                                                                '\n')
    update_account_parser.set_defaults(which='update_account')
    update_account_parser.add_argument('--account', dest='account', action='store', help='Account name', required=True)
    update_account_parser.add_argument('--key', dest='key', action='store', help='Account parameter', required=True)
    update_account_parser.add_argument('--value', dest='value', action='store', help='Account parameter value', required=True)

    # The identity subparser
    identity_parser = subparsers.add_parser('identity', help='Identity methods')
    identity_subparser = identity_parser.add_subparsers(dest='identity_subcommand', **required_arg)

    # The identity_add command
    identity_add_parser = identity_subparser.add_parser('add',
                                                        help='Grant an identity access to an account.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '\n'
                                                               'To add an identity of X509 type::\n'
                                                               '\n'
                                                               '    $ rucio-admin identity add --account jdoe --type X509 --id \'CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch\' --email jdoe@cern.ch\n'
                                                               '    Added new identity to account: CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch\n'
                                                               '    \n'
                                                               '    $ rucio-admin account list-identities jdoe\n'
                                                               '    Identity: CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch,   type: X509\n'
                                                               '\n'
                                                               'Note: please keep the DN inside quota marks.\n'
                                                               '\n'
                                                               'To add an identity of GSS type::\n'
                                                               '\n'
                                                               '    $ rucio-admin identity add --account jdoe --type GSS --email jdoe@cern.ch --id jdoe@CERN.CH\n'
                                                               '    Added new identity to account: jdoe@CERN.CH-jdoe\n'
                                                               '    \n'
                                                               '    $ rucio-admin account list-identities jdoe\n'
                                                               '    Identity: jdoe@CERN.CH,    type: GSS\n'
                                                               '    Identity: CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch,   type: X509\n'
                                                               '\n')
    identity_add_parser.set_defaults(which='identity_add')
    identity_add_parser.add_argument('--account', dest='account', action='store', help='Account name', required=True)
    identity_add_parser.add_argument('--type', dest='authtype', action='store', choices=['X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC'], help='Authentication type [X509|GSS|USERPASS|SSH|SAML|OIDC]', required=True)
    identity_add_parser.add_argument('--id', dest='identity', action='store', help='Identity', required=True)
    identity_add_parser.add_argument('--email', dest='email', action='store', help='Email address associated with the identity', required=True)
    identity_add_parser.add_argument('--password', dest='password', action='store', help='Password if authtype is USERPASS', required=False)

    # The identity_delete command
    identity_delete_parser = identity_subparser.add_parser('delete',
                                                           help="Revoke an identity's access to an account. The mandatory parameters are account, type and identity.",
                                                           formatter_class=argparse.RawDescriptionHelpFormatter,
                                                           epilog='Usage example\n'
                                                                  '"""""""""""""\n'
                                                                  '::\n'
                                                                  '\n'
                                                                  '    $ rucio-admin identity delete --account jdoe --type X509 --id \'CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch\'\n'
                                                                  '    Deleted identity: CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch\n'
                                                                  '\n'
                                                                  'Note: if the identity was accidentally deleted, use add option.\n'
                                                                  '\n')
    identity_delete_parser.set_defaults(which='identity_delete')
    identity_delete_parser.add_argument('--account', dest='account', action='store', help='Account name', required=True)
    identity_delete_parser.add_argument('--type', dest='authtype', action='store', choices=['X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC'], help='Authentication type [X509|GSS|USERPASS|SSH|SAML|OIDC]', required=True)
    identity_delete_parser.add_argument('--id', dest='identity', action='store', help='Identity', required=True)

    # The RSE subparser
    rse_parser = subparsers.add_parser('rse', help='RSE (Rucio Storage Element) methods')
    rse_subparser = rse_parser.add_subparsers(dest='rse_subcommand', **required_arg)

    # The list_rses command
    list_rse_parser = rse_subparser.add_parser('list',
                                               help='List all RSEs.',
                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                               epilog='Usage example\n'
                                                      '"""""""""""""\n'
                                                      'To list all rses::\n'
                                                      '\n'
                                                      '    $ rucio-admin rse list'
                                                      '\n'
                                                      'Note: same as rucio list-rses\n'
                                                      '\n'
                                                      'To list special class of rses::\n'
                                                      '\n'
                                                      '    $ rucio list-rses --rses \"tier=2&type=DATADISK\"\n'
                                                      '\n')
    list_rse_parser.add_argument("--csv", action='store_true', help='Output a list of RSEs as a csv')
    list_rse_parser.set_defaults(which='list_rses')

    # The add_rse command
    add_rse_parser = rse_subparser.add_parser('add',
                                              help='Add new RSE.',
                                              formatter_class=argparse.RawDescriptionHelpFormatter,
                                              epilog='Example Usage\n'
                                                     '"""""""""""""\n'
                                                     '::\n'
                                                     '\n'
                                                     '    $ rucio-admin rse add JDOE_DATADISK\n'
                                                     '    Added new deterministic RSE: JDOE_DATADISK\n'
                                                     '\n'
                                                     '    $ rucio-admin rse add --non-deterministic JDOE-TEST_DATATAPE\n'
                                                     '    Added new non-deterministic RSE: JDOE-TEST_DATATAPE\n'
                                                     '\n')
    add_rse_parser.set_defaults(which='add_rse')
    add_rse_parser.add_argument('rse', action='store', help='RSE name')
    add_rse_parser.add_argument('--non-deterministic', action='store_true', help='Create RSE in non-deterministic mode')

    # The update_rse command
    update_rse_parser = rse_subparser.add_parser('update',
                                                 help='Update RSE settings.',
                                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                                 epilog='Example Usage\n'
                                                        '"""""""""""""\n'
                                                        '\n'
                                                        '    $ rucio-admin rse update --setting availability_write --value False\n'
                                                        '\n'
                                                        '\n')
    update_rse_parser.set_defaults(which='update_rse')
    update_rse_parser.add_argument('--rse', dest='rse', action='store', help='RSE name', required=True)
    update_rse_parser.add_argument('--setting', dest='param', action='store', help="One of deterministic, rse_type, staging_are, volatile, qos_class, availability_delete, availability_read, availability_write, city, country_name, latitude, longitude, region_code, time_zone", required=True)  # noqa: E501
    update_rse_parser.add_argument('--value', dest='value', action='store', help='Value for the new setting configuration. Use "", None or null to wipe the value', required=True)

    # The info_rse command
    info_rse_parser = rse_subparser.add_parser('info',
                                               help='Information about RSE.',
                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                               epilog='Usage example\n'
                                                      '"""""""""""""\n'
                                                      'Information about a RSE::\n'
                                                      '\n'
                                                      '    $ rucio-admin rse info JDOE_DATADISK\n'
                                                      '    Settings:\n'
                                                      '    =========\n'
                                                      '      rse_type: DISK\n'
                                                      '      domain: [u\'lan\', u\'wan\']\n'
                                                      '      availability_delete: True\n'
                                                      '      rse: JDOE_DATADISK\n'
                                                      '      deterministic: True\n'
                                                      '      staging_area: False\n'
                                                      '      credentials: None\n'
                                                      '      availability_write: True\n'
                                                      '      lfn2pfn_algorithm: default\n'
                                                      '      availability_read: True\n'
                                                      '      volatile: False\n'
                                                      '      id: 9c54c73cbd534450b2202a576f809f1f\n'
                                                      '    Attributes:\n'
                                                      '    ===========\n'
                                                      '      JDOE_DATADISK: True\n'
                                                      '    Protocols:\n'
                                                      '    ==========\n'
                                                      '    Usage:\n'
                                                      '    ======\n'
                                                      '      rucio\n'
                                                      '      used: 0\n'
                                                      '      rse: JDOE_DATADISK\n'
                                                      '      updated_at: 2018-02-16 13:08:28\n'
                                                      '      free: None\n'
                                                      '      source: rucio\n'
                                                      '      total: 0\n'
                                                      '\n'
                                                      'Note: alternatively:  rucio list-rse-usage JDOE_DATADISK.\n'
                                                      '\n')
    info_rse_parser.set_defaults(which='info_rse')
    info_rse_parser.add_argument('rse', action='store', help='RSE name')

    # The set_attribute_rse command
    set_attribute_rse_parser = rse_subparser.add_parser('set-attribute',
                                                        help='Add RSE attribute(key-value pair).',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '::\n'
                                                               '\n'
                                                               '    $ rucio-admin rse set-attribute --rse JDOE_DATADISK --key owner --value jdoe\n'
                                                               '    Added new RSE attribute for JDOE_DATADISK: owner-jdoe\n'
                                                               '\n'
                                                               'CAUTION: the existing attribute can be overwritten. Check rucio list-rse-attributes JDOE_DATADISK before setting an attribute.\n'
                                                               '\n')
    set_attribute_rse_parser.set_defaults(which='set_attribute_rse')
    set_attribute_rse_parser.add_argument('--rse', dest='rse', action='store', help='RSE name', required=True)
    set_attribute_rse_parser.add_argument('--key', dest='key', action='store', help='Attribute key', required=True)
    set_attribute_rse_parser.add_argument('--value', dest='value', action='store', help='Attribute value', required=True)

    # The delete_attribute_rse command
    delete_attribute_rse_parser = rse_subparser.add_parser('delete-attribute',
                                                           help='Delete a RSE attribute(key-value pair).',
                                                           formatter_class=argparse.RawDescriptionHelpFormatter,
                                                           epilog='Usage example\n'
                                                                  '"""""""""""""\n'
                                                                  '::\n'
                                                                  '\n'
                                                                  '    $ rucio-admin rse delete-attribute --rse JDOE_DATADISK --key owner --value jdoe\n'
                                                                  '    Deleted RSE attribute for JDOE_DATADISK: owner-jdoe\n'
                                                                  '\n')
    delete_attribute_rse_parser.set_defaults(which='delete_attribute_rse')
    delete_attribute_rse_parser.add_argument('--rse', dest='rse', action='store', help='RSE name', required=True)
    delete_attribute_rse_parser.add_argument('--key', dest='key', action='store', help='Attribute key', required=True)
    delete_attribute_rse_parser.add_argument('--value', dest='value', action='store', help='Attribute value', required=True)

    # The add_distance_rses command
    add_distance_rses_parser = rse_subparser.add_parser('add-distance',
                                                        help='Set the distance between a pair of RSEs.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '::\n'
                                                               '\n'
                                                               '    $ rucio-admin rse add-distance JDOE_SCRATCHDISK JDOE_DATADISK\n'
                                                               '    Set distance from JDOE_SCRATCHDISK to JDOE_DATADISK to 1/n'
                                                               '\n'
                                                               'Note::\n'
                                                               '\n'
                                                               '    --distance can be any positive integer, 0 is the closest\n'
                                                               'Note: order of RSEs is fixed: source, destination\n'
                                                               '\n')
    add_distance_rses_parser.set_defaults(which='add_distance_rses')
    add_distance_rses_parser.add_argument(dest='source', action='store', help='Source RSE name')
    add_distance_rses_parser.add_argument(dest='destination', action='store', help='Destination RSE name')
    add_distance_rses_parser.add_argument('--distance', dest='distance', default=1, type=int, help='Distance between RSEs')
    add_distance_rses_parser.add_argument('--ranking', '--ranking', dest='ranking', new_option_string='--ranking', default=1, type=int, action=StoreAndDeprecateWarningAction, help='Ranking of link')

    # The update_distance_rses command
    update_distance_rses_parser = rse_subparser.add_parser('update-distance',
                                                           help='Update the existing distance between a pair of RSEs. The mandatory parameters are source, destination and distance or ranking.',
                                                           formatter_class=argparse.RawDescriptionHelpFormatter,
                                                           epilog='Usage example\n'
                                                                  '"""""""""""""\n'
                                                                  '::\n'
                                                                  '\n'
                                                                  '    $ rucio-admin rse update-distance JDOE_DATADISK JDOE_SCRATCHDISK --distance 10\n'
                                                                  '    Update distance information from JDOE_DATADISK to JDOE_SCRATCHDISK:\n'
                                                                  '    - Distance set to 10\n'
                                                                  '\n'
                                                                  'Note::\n'
                                                                  '\n'
                                                                  '    --distance can be any positive integer, 0 is the closest\n'
                                                                  'Note: order of RSEs is fixed: source, destination.\n'
                                                                  '\n')
    update_distance_rses_parser.set_defaults(which='update_distance_rses')
    update_distance_rses_parser.add_argument(dest='source', action='store', help='Source RSE name')
    update_distance_rses_parser.add_argument(dest='destination', action='store', help='Destination RSE name')
    update_distance_rses_parser.add_argument('--distance', dest='distance', type=int, help='Distance between RSEs')
    update_distance_rses_parser.add_argument('--ranking', '--ranking', dest='ranking', new_option_string='--ranking', type=int, action=StoreAndDeprecateWarningAction, help='Ranking of link')

    # The delete_distance_rses command
    delete_distance_rses_parser = rse_subparser.add_parser('delete-distance',
                                                           help='Delete the distance between a pair of RSEs. The mandatory parameters are source and destination.',
                                                           formatter_class=argparse.RawDescriptionHelpFormatter,
                                                           epilog='Usage example\n'
                                                                  '"""""""""""""\n'
                                                                  '::\n'
                                                                  '\n'
                                                                  '    $ rucio-admin rse delete-distance JDOE_DATADISK JDOE_SCRATCHDISK\n'
                                                                  '    Delete distance information from JDOE_DATADISK to JDOE_SCRATCHDISK:\n'
                                                                  '\n')
    delete_distance_rses_parser.set_defaults(which='delete_distance_rses')
    delete_distance_rses_parser.add_argument(dest='source', action='store', help='Source RSE name')
    delete_distance_rses_parser.add_argument(dest='destination', action='store', help='Destination RSE name')

    # The get_distance_rses command
    get_distance_rses_parser = rse_subparser.add_parser('get-distance',
                                                        help='Get the distance information between a pair of RSEs.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '::\n'
                                                               '\n'
                                                               '    $ rucio-admin rse get-distance JDOE_DATADISK JDOE_SCRATCHDISK\n'
                                                               '    Distance information from JDOE_DATADISK to JDOE_SCRATCHDISK: distance=3, ranking=10\n'
                                                               '\n'
                                                               'Note: order of RSEs is fixed: source, destination.\n'
                                                               '\n')
    get_distance_rses_parser.set_defaults(which='get_distance_rses')
    get_distance_rses_parser.add_argument(dest='source', action='store', help='Source RSE name')
    get_distance_rses_parser.add_argument(dest='destination', action='store', help='Destination RSE name')

    # The get_attribute_rse command
    get_attribute_rse_parser = rse_subparser.add_parser('get-attribute',
                                                        help='List RSE attributes.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '::\n'
                                                               '\n'
                                                               '    $ rucio-admin rse get-attribute JDOE_DATADISK\n'
                                                               '    owner: jdoe\n'
                                                               '    JDOE_DATADISK: True\n'
                                                               '\n'
                                                               'Note: alternatively: rucio list-rse-attributes JDOE_DATADISK.\n'
                                                               '\n')
    get_attribute_rse_parser.set_defaults(which='get_attribute_rse')
    get_attribute_rse_parser.add_argument(dest='rse', action='store', help='RSE name')

    # The add_protocol_rse command
    add_protocol_rse_parser = rse_subparser.add_parser('add-protocol',
                                                       help='Add a protocol and its settings to a RSE.',
                                                       formatter_class=argparse.RawDescriptionHelpFormatter,
                                                       epilog='Usage example\n'
                                                              '"""""""""""""\n'
                                                              '::\n'
                                                              '\n'
                                                              '    $ rucio-admin rse add-protocol --hostname jdoes.test.org --scheme gsiftp --prefix \'/atlasdatadisk/rucio/\' --port 8443 JDOE_DATADISK\n'
                                                              '\n'
                                                              'Note: no printed stdout.\n'
                                                              'Note: examples of optional parameters::\n'
                                                              '\n'
                                                              '    --space-token DATADISK\n'
                                                              '    --web-service-path \'/srm/managerv2?SFN=\'\n'
                                                              '    --port 8443\n'
                                                              '    --impl \'rucio.rse.protocols.gfal.Default\'\n'
                                                              '      (for other protocol implementation, replace gfal2 with impl. name, e.g. srm)\n'
                                                              '    --domain-json\n'
                                                              '    --extended-attributes-json example.json\n'
                                                              '      where example.json contains dict {\'attr_name\':\'value\', ...}\n'
                                                              '\n')
    add_protocol_rse_parser.set_defaults(which='add_protocol_rse')
    add_protocol_rse_parser.add_argument(dest='rse', action='store', help='RSE name')
    add_protocol_rse_parser.add_argument('--hostname', dest='hostname', action='store', help='Endpoint hostname', required=True)
    add_protocol_rse_parser.add_argument('--scheme', dest='scheme', action='store', help='Endpoint URL scheme', required=True)
    add_protocol_rse_parser.add_argument('--prefix', dest='prefix', action='store', help='Endpoint URL path prefix', required=True)
    add_protocol_rse_parser.add_argument('--space-token', dest='space_token', action='store', help='Space token name (SRM-only)')
    add_protocol_rse_parser.add_argument('--web-service-path', dest='web_service_path', action='store', help='Web service URL (SRM-only)')
    add_protocol_rse_parser.add_argument('--port', dest='port', action='store', type=int, help='URL port')
    add_protocol_rse_parser.add_argument('--impl', dest='impl', default='rucio.rse.protocols.gfal.Default', action='store', help='Transfer protocol implementation to use')
    add_protocol_rse_parser.add_argument('--domain-json', dest='domain_json', action='store', type=json.loads, help='JSON describing the WAN / LAN setup')
    add_protocol_rse_parser.add_argument('--extended-attributes-json', dest='ext_attr_json', action='store', type=json.loads, help='JSON describing any extended attributes')

    # The del_protocol_rse command
    del_protocol_rse_parser = rse_subparser.add_parser('delete-protocol',
                                                       help='Delete a protocol from a RSE.',
                                                       formatter_class=argparse.RawDescriptionHelpFormatter,
                                                       epilog='Usage example\n'
                                                              '"""""""""""""\n'
                                                              '::\n'
                                                              '\n'
                                                              '   $ rucio-admin rse delete-protocol  --scheme gsiftp JDOE_DATADISK\n'
                                                              '\n'
                                                              'Note: no printed stdout.\n'
                                                              '\n')
    del_protocol_rse_parser.set_defaults(which='del_protocol_rse')
    del_protocol_rse_parser.add_argument(dest='rse', action='store', help='RSE name')
    del_protocol_rse_parser.add_argument('--hostname', dest='hostname', action='store', help='Endpoint hostname')
    del_protocol_rse_parser.add_argument('--scheme', dest='scheme', action='store', help='Endpoint URL scheme', required=True)
    del_protocol_rse_parser.add_argument('--port', dest='port', action='store', type=int, help='URL port')

    # The disable_location command
    disable_rse_parser = rse_subparser.add_parser('delete',
                                                  help='Disable RSE.',
                                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                                  epilog='Usage example\n'
                                                         '"""""""""""""\n'
                                                         '::\n'
                                                         '\n'
                                                         '   $ rucio-admin rse delete JDOE_SCRATCHDISK\n'
                                                         '\n'
                                                         'Note: no printed stdout.\n'
                                                         'CAUTION: all information about the RSE might be lost!\n'
                                                         '\n')
    disable_rse_parser.set_defaults(which='disable_rse')
    disable_rse_parser.add_argument('rse', action='store', help='RSE name')

    # The add_qos_policy command
    add_qos_policy_parser = rse_subparser.add_parser('add-qos-policy',
                                                     help='Add a QoS policy to an RSE.',
                                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                                     epilog='Usage example\n'
                                                            '"""""""""""""\n'
                                                            '\n'
                                                            '   $ rucio-admin rse add-qos-policy JDOE_DATADISK SLOW_BUT_CHEAP')
    add_qos_policy_parser.set_defaults(which='add_qos_policy')
    add_qos_policy_parser.add_argument('rse', action='store', help='RSE name')
    add_qos_policy_parser.add_argument('qos_policy', action='store', help='QoS policy')

    # The delete_qos_policy command
    delete_qos_policy_parser = rse_subparser.add_parser('delete-qos-policy',
                                                        help='Delete a QoS policy from an RSE.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '\n'
                                                               '   $ rucio-admin rse delete-qos-policy JDOE_DATADISK SLOW_BUT_CHEAP')
    delete_qos_policy_parser.set_defaults(which='delete_qos_policy')
    delete_qos_policy_parser.add_argument('rse', action='store', help='RSE name')
    delete_qos_policy_parser.add_argument('qos_policy', action='store', help='QoS policy')

    # The delete_qos_policy command
    list_qos_policies_parser = rse_subparser.add_parser('list-qos-policies',
                                                        help='List all QoS policies of an RSE.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                                        epilog='Usage example\n'
                                                               '"""""""""""""\n'
                                                               '\n'
                                                               '   $ rucio-admin rse list-qos-policies JDOE_DATADISK')
    list_qos_policies_parser.set_defaults(which='list_qos_policies')
    list_qos_policies_parser.add_argument('rse', action='store', help='RSE name')

    # The set_limit_rse command
    set_limit_rse_parser = rse_subparser.add_parser('set-limit',
                                                    help='Set a RSE limit',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    epilog='Usage example\n'
                                                           '"""""""""""""\n'
                                                           '\n'
                                                           '  $ rucio-admin rse set-limit XRD1 MinFreeSpace 10000')
    set_limit_rse_parser.set_defaults(which='set_limit_rse')
    set_limit_rse_parser.add_argument('rse', action='store', help='RSE name')
    set_limit_rse_parser.add_argument('name', action='store', help='Name of the limit')
    set_limit_rse_parser.add_argument('value', action='store', help='Value of the limit')

    # The delete_limit_rse command
    set_limit_rse_parser = rse_subparser.add_parser('delete-limit',
                                                    help='Delete a RSE limit',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    epilog='Usage example\n'
                                                           '"""""""""""""\n'
                                                           '\n'
                                                           '  $ rucio-admin rse delete-limit XRD3 MinFreeSpace')
    set_limit_rse_parser.set_defaults(which='delete_limit_rse')
    set_limit_rse_parser.add_argument('rse', action='store', help='RSE name')
    set_limit_rse_parser.add_argument('name', action='store', help='Name of the limit')

    # The scope subparser
    scope_parser = subparsers.add_parser('scope', help='Scope methods')
    scope_subparser = scope_parser.add_subparsers(dest='scope_subcommand', **required_arg)

    # The add_scope command
    add_scope_parser = scope_subparser.add_parser('add',
                                                  help='Add scope.',
                                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                                  epilog='Usage example\n'
                                                         '"""""""""""""\n'
                                                         '::\n'
                                                         '\n'
                                                         '    $ rucio-admin scope add --scope user.jdoe --account jdoe\n'
                                                         '    Added new scope to account: user.jdoe-jdoe\n'
                                                         '\n')
    add_scope_parser.set_defaults(which='add_scope')
    add_scope_parser.add_argument('--account', dest='account', action='store', help='Account name', required=True)
    add_scope_parser.add_argument('--scope', dest='scope', action='store', help='Scope name', required=True)

    # The list_scope command
    list_scope_parser = scope_subparser.add_parser('list',
                                                   help='List scopes.',
                                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                                   epilog='Usage example\n'
                                                          '"""""""""""""\n'
                                                          '::\n'
                                                          '\n'
                                                          '    $ rucio-admin scope list --account jdoe\n'
                                                          '    user.jdoe\n'
                                                          '\n'
                                                          'Note: alternatively: rucio list-scopes.\n'
                                                          '\n')
    list_scope_parser.set_defaults(which='list_scopes')
    list_scope_parser.add_argument('--account', dest='account', action='store', help='Account name')
    list_scope_parser.add_argument('--csv', action='store_true', help='Output a list of scopes as a csv')

    # The config subparser
    config_parser = subparsers.add_parser('config',
                                          help='Configuration methods. The global configuration of data management system can by modified.',
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          epilog='''e.g. quotas, daemons, rses''')
    config_subparser = config_parser.add_subparsers(dest='config_subcommand', **required_arg)

    # The get_config command
    get_config_parser = config_subparser.add_parser('get',
                                                    help='Get matching configuration.',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    epilog='Usage example\n'
                                                           '"""""""""""""\n'
                                                           '::\n'
                                                           '\n'
                                                           '    $ rucio-admin config get --section quota\n'
                                                           '    [quota]\n'
                                                           '    LOCALGROUPDISK=95\n'
                                                           '    SCRATCHDISK=30\n'
                                                           '    USERDISK=30\n'
                                                           '\n'
                                                           'Note: to list other sections: rucio-admin config get.\n'
                                                           '\n')
    get_config_parser.set_defaults(which='get_config')
    get_config_parser.add_argument('--section', dest='section', action='store', help='Section name', required=False)
    get_config_parser.add_argument('--option', dest='option', action='store', help='Option name', required=False)

    # The set_config_option command
    set_config_parser = config_subparser.add_parser('set',
                                                    help='Set matching configuration.',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    epilog='Usage example\n'
                                                           '"""""""""""""\n'
                                                           '::\n'
                                                           '\n'
                                                           '    $ rucio-admin config set --section limitsscratchdisk --option testlimit --value 30\n'
                                                           '    Set configuration: limitsscratchdisk.testlimit=30\n'
                                                           '\n'
                                                           'CAUTION: you might not intend to change global configuration!\n'
                                                           '\n')
    set_config_parser.set_defaults(which='set_config_option')
    set_config_parser.add_argument('--section', dest='section', action='store', help='Section name', required=True)
    set_config_parser.add_argument('--option', dest='option', action='store', help='Option name', required=True)
    set_config_parser.add_argument('--value', dest='value', action='store', help='String-encoded value', required=True)

    # The delete_config_option command
    delete_config_parser = config_subparser.add_parser('delete',
                                                       help='Delete matching configuration.',
                                                       formatter_class=argparse.RawDescriptionHelpFormatter,
                                                       epilog='Usage example\n'
                                                              '"""""""""""""\n'
                                                              '::\n'
                                                              '\n'
                                                              '    $ rucio-admin config delete --section limitsscratchdisk --option testlimit\n'
                                                              '    Deleted section \'limitsscratchdisk\' option \'testlimit\'\n'
                                                              '\n'
                                                              'CAUTION: you might not intend to change global configuration!\n'
                                                              '\n')
    delete_config_parser.set_defaults(which='delete_config_option')
    delete_config_parser.add_argument('--section', dest='section', action='store', help='Section name', required=True)
    delete_config_parser.add_argument('--option', dest='option', action='store', help='Option name', required=True)

    # The subscription parser
    subs_parser = subparsers.add_parser('subscription', help='Subscription methods. The methods for automated and regular processing of some specific rules.')
    subs_subparser = subs_parser.add_subparsers(dest='subscription_subcommand', **required_arg)

    # The add-subscription command
    add_sub_parser = subs_subparser.add_parser('add',
                                               help='Add subscription',
                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                               epilog='Usage example\n'
                                                      '"""""""""""""\n'
                                                      '::\n'
                                                      '\n'
                                                      '    $ rucio-admin subscription add --lifetime 2 --account jdoe --priority 1 jdoes_txt_files_on_datadisk\n'
                                                      '    \'{\"scope\": [\"user.jdoe\"], \"datatype\": [\"txt\"]}\' \'[{\"copies\": 1, \"rse_expression\": \"JDOE_DATADISK\", \"lifetime\": 3600, \"activity\": \"User Subscriptions\"}]\'\n'
                                                      '    \'keeping replica on jdoes disk for 60 mins\'\n'
                                                      '    Subscription added 9a89cc8e692f4cabb8836fdafd884c5a\n'
                                                      '\n'
                                                      'Note: priority can range from 1 to infinity. Internal share for given account.\n'
                                                      '\n')
    add_sub_parser.set_defaults(which='add_subscription')
    add_sub_parser.add_argument(dest='name', action='store', help='Subscription name')
    add_sub_parser.add_argument(dest='filter', action='store', help='DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')')
    add_sub_parser.add_argument(dest='replication_rules', action='store', help='Replication rules (eg \'[{"copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "activity": "Functional Tests", "weight": "mou"}]\')')
    add_sub_parser.add_argument(dest='comments', action='store', help='Comments on subscription')
    add_sub_parser.add_argument('--lifetime', dest='lifetime', action='store', type=int, help='Subscription lifetime (in days)')
    add_sub_parser.add_argument('--account', dest='subs_account', action='store', help='Account name')
    add_sub_parser.add_argument('--priority', dest='priority', action='store', help='The priority of the subscription')
    # retroactive and dry_run hard-coded for now

    # The list-subscriptions command
    list_sub_parser = subs_subparser.add_parser('list',
                                                help='List subscriptions',
                                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                                epilog='Usage example\n'
                                                       '"""""""""""""\n'
                                                       '::\n'
                                                       '\n'
                                                       '    $ rucio-admin subscription list --account jdoe\n'
                                                       '    jdoe: jdoes_txt_files_on_datadisk UPDATED\n'
                                                       '    priority: 1\n'
                                                       '    filter: {\'datatype\': [\'txt\'], \'scope\': [\'user.jdoe\']}\n'
                                                       '    rules: [{\'lifetime\': 3600, \'rse_expression\': \'JDOE_DATADISK\', \'copies\': 1, \'activity\': \'User Subscriptions\'}]\n'
                                                       '    comments: keeping replica on jdoes disk for 60 mins\n'
                                                       '\n')
    list_sub_parser.set_defaults(which='list_subscriptions')
    list_sub_parser.add_argument('--account', dest='subs_account', action='store', help='Account name')
    list_sub_parser.add_argument('--long', dest='long', action='store_true', help='Long listing')
    list_sub_parser.add_argument(dest='name', nargs='?', action='store', help='Subscription name')

    # The update-subscription command
    update_sub_parser = subs_subparser.add_parser('update',
                                                  help='Update subscription',
                                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                                  epilog='Usage example\n'
                                                         '"""""""""""""\n'
                                                         '::\n'
                                                         '\n'
                                                         '    $ rucio-admin subscription update --lifetime 3 --account jdoe --priority 1 jdoes_txt_files_on_datadisk\n'
                                                         '    \'{\"scope\": [\"user.jdoe\"], \"datatype\": [\"txt\"]}\' \'[{\"copies\": 1, \"rse_expression\": \"JDOE_DATADISK\", \"lifetime\": 3600, \"activity\": \"User Subscriptions\"}]\n'
                                                         '    keeping replica on jdoes disk for 60 mins, valid until 23.2.2018\n'
                                                         '\n'
                                                         'Note: no printed stdout.\n'
                                                         'Note: all the input parameters are mandatory.\n'
                                                         '::\n'
                                                         '\n'
                                                         '    $ rucio-admin subscription list --account jdoe\n'
                                                         '    jdoe: jdoes_txt_files_on_datadisk UPDATED\n'
                                                         '    priority: 1\n'
                                                         '    filter: {\"datatype\": [\"txt\"], \"scope\": [\"user.jdoe\"]}\n'
                                                         '    rules: [{\"lifetime\": 3600, \"rse_expression\": \"JDOE_DATADISK\", \"copies\": 1, \"activity\": \"User Subscriptions\"}]\n'
                                                         '    comments: keeping replica on jdoes disk for 60 mins, valid until 23.2.2018\n'
                                                         '\n')
    update_sub_parser.set_defaults(which='update_subscription')
    update_sub_parser.add_argument(dest='name', action='store', help='Subscription name')
    update_sub_parser.add_argument(dest='filter', action='store', help='DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')')
    update_sub_parser.add_argument(dest='replication_rules', action='store', help='Replication rules (eg \'[{"activity": "Functional Tests", "copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "weight": "mou"}]\')')
    update_sub_parser.add_argument(dest='comments', action='store', help='Comments on subscription')
    update_sub_parser.add_argument('--lifetime', dest='lifetime', action='store', type=int, help='Subscription lifetime (in days)')
    update_sub_parser.add_argument('--account', dest='subs_account', action='store', help='Account name')
    update_sub_parser.add_argument('--priority', dest='priority', action='store', help='The priority of the subscription')
    # subscription policy, retroactive and dry_run hard-coded for now

    # The reevaluate command
    reevaluate_did_for_subscription_parser = subs_subparser.add_parser('reevaluate',
                                                                       help='Reevaluate a list of DIDs against all active subscriptions',
                                                                       formatter_class=argparse.RawDescriptionHelpFormatter,
                                                                       epilog='Usage example\n'
                                                                              '"""""""""""""\n'
                                                                              '::\n'
                                                                              '\n'
                                                                              '    $ rucio-admin subscription reevaluate user.jdoe:jdoes.test.dataset\n'
                                                                              '\n'
                                                                              'Note: no printed stdout.\n'
                                                                              '\n')
    reevaluate_did_for_subscription_parser.set_defaults(which='reevaluate_did_for_subscription')
    reevaluate_did_for_subscription_parser.add_argument(dest='dids', action='store', help='List of DIDs (coma separated)')

    # The replica parser
    rep_parser = subparsers.add_parser('replicas', help='Replica methods')
    rep_subparser = rep_parser.add_subparsers(dest='replicas_subcommand', **required_arg)

    # The add-quarantined command
    quarantine_parser = rep_subparser.add_parser('quarantine', help="Add quarantined replicas",
                                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                                 epilog=dedent("""\
                                                         Usage example
                                                         =============
                                                         ::
                                                             $ cat replica_list.txt
                                                             /path/to/file_1.data
                                                             /path/to/another/file.data
                                                             $ rucio admin replicas quarantine --rse STORAGE --paths replica_list.txt

                                                             $ rucio admin replicas quarantine --rse STORAGE /path/to/a/data_file /path/to/some/other/file
                                                     """))
    quarantine_parser.set_defaults(which='quarantine_replicas')
    quarantine_parser.add_argument("--paths", dest="paths_file", action="store", help="A file with replica paths, one path per line")
    quarantine_parser.add_argument("--rse", dest="rse", action="store", help="RSE name")
    quarantine_parser.add_argument(dest='paths_list', action='store', nargs='*', help='List of replica paths')

    # The declare-bad command
    declare_bad_file_replicas_parser = rep_subparser.add_parser('declare-bad',
                                                                help='Declare bad file replicas',
                                                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                                                epilog='Usage example\n'
                                                                       '"""""""""""""\n'
                                                                       '::\n'
                                                                       '\n'
                                                                       '    $ rucio-admin replicas declare-bad\n'
                                                                       '    srm://se.bfg.uni-freiburg.de:8443/srm/managerv2?SFN=/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --reason \'test only\'\n'
                                                                       '\n'
                                                                       'Note: no printed stdout.\n'
                                                                       '\n'
                                                                       'Note: pfn can be provided, see rucio-admin replicas list-pfns or rucio list-file-replicas\n'
                                                                       '\n')
    declare_bad_file_replicas_parser.set_defaults(which='declare_bad_file_replicas')
    declare_bad_file_replicas_parser.add_argument(dest='listbadfiles', action='store', nargs='*', help='List of bad items. Each can be a PFN (for one replica) or an LFN (for all replicas of the LFN) or a collection DID (for all file replicas in the DID)')
    declare_bad_file_replicas_parser.add_argument('--reason', dest='reason', required=True, action='store', help='Reason')
    declare_bad_file_replicas_parser.add_argument('--inputfile', dest='inputfile', nargs='?', action='store', help='File containing list of bad items')
    declare_bad_file_replicas_parser.add_argument('--allow-collection', dest='allow_collection', action='store_true', help='Allow passing a collection DID as bad item')

    declare_bad_file_replicas_parser.add_argument('--lfns', dest='lfns', nargs='?', action='store', help='File containing list of LFNs for bad replicas. Requires --rse and --scope')
    declare_bad_file_replicas_parser.add_argument('--scope', dest='scope', nargs='?', action='store', help='Common scope for bad replicas specified with LFN list, ignored without --lfns')
    declare_bad_file_replicas_parser.add_argument('--rse', dest='rse', nargs='?', action='store', help='Common RSE for bad replicas specified with LFN list, ignored without --lfns')

    # The declare-temporary-unavailable command
    declare_temporary_unavailable_replicas_parser = rep_subparser.add_parser('declare-temporary-unavailable',
                                                                             help='Declare temporary unavailable replicas',
                                                                             formatter_class=argparse.RawDescriptionHelpFormatter,
                                                                             epilog='Usage example\n'
                                                                                    '"""""""""""""\n'
                                                                                    '::\n'
                                                                                    '\n'
                                                                                    '    $ rucio-admin replicas declare-temporary-unavailable\n'
                                                                                    '    srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --duration 3600 --reason \'test only\'\n')
    declare_temporary_unavailable_replicas_parser.set_defaults(which='declare_temporary_unavailable_replicas')
    declare_temporary_unavailable_replicas_parser.add_argument(dest='listbadfiles', action='store', nargs='*', help='List of replicas. Each needs to be a proper PFN including the protocol')
    declare_temporary_unavailable_replicas_parser.add_argument('--reason', dest='reason', required=True, action='store', help='Reason')
    declare_temporary_unavailable_replicas_parser.add_argument('--inputfile', dest='inputfile', nargs='?', action='store', help='File containing list of replicas')
    declare_temporary_unavailable_replicas_parser.add_argument('--expiration-date', '--duration', new_option_string='--duration', dest='duration', required=True, action=StoreAndDeprecateWarningAction, type=int, help='Timeout in seconds when the replicas will become available again.')  # NOQA: E501

    # The list-pfns command
    list_pfns_parser = rep_subparser.add_parser('list-pfns',
                                                help='List the possible PFN for a file at a site.',
                                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                                epilog='Usage example\n'
                                                       '"""""""""""""\n'
                                                       '::\n'
                                                       '\n'
                                                       '    $ rucio-admin replicas list-pfns \n'
                                                       '    user.jdoe:jdoe.TXT.txt CERN-PROD_SCRATCHDISK srm \'{\"all_states\": False, \"schemes\": [\"srm\"], \"dids\": [{\"scope\": \"user.jdoe\", \"name\": \"jdoe.TXT.txt\"}]}\'\n'
                                                       '    srm://srm-eosatlas.cern.ch:8443/srm/v2/server?SFN=/eos/atlas/atlasscratchdisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt'
                                                       '\n')
    list_pfns_parser.set_defaults(which='list_pfns')
    list_pfns_parser.add_argument(dest='dids', action='store', help='List of DIDs (coma separated)')
    list_pfns_parser.add_argument(dest='rse', action='store', help='RSE')
    list_pfns_parser.add_argument(dest='protocol', action='store', default='srm', help='The protocol, by default srm, can be one of [root|srm|http(s)].')

    # The set-tombstone command
    set_tombstone_parser = rep_subparser.add_parser('set-tombstone',
                                                    help='Set a tombstone on a replica manually to force deletion. Only works if there is no lock on the replica.',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    epilog='Usage example\n'
                                                           '"""""""""""""\n'
                                                           '::\n'
                                                           '\n'
                                                           '    $ rucio-admin replicas set-tombstone mock:file --rse MOCK'
                                                           '\n')
    set_tombstone_parser.add_argument('dids', action='store', help='One or multiple comma separated DIDs.')
    set_tombstone_parser.add_argument('--rse', action='store', required=True, help='RSE')
    set_tombstone_parser.set_defaults(which='set_tombstone')

    return oparser


def main():
    oparser = get_parser()
    if EXTRA_MODULES['argcomplete']:
        argcomplete.autocomplete(oparser)

    if len(sys.argv) == 1:
        oparser.print_help()
        sys.exit(FAILURE)

    args = oparser.parse_args()

    if not hasattr(args, 'which'):
        oparser.print_help()
        sys.exit(FAILURE)
    else:
        commands = {'add_account': add_account,
                    'list_accounts': list_accounts,
                    'list_account_attributes': list_account_attributes,
                    'add_account_attribute': add_account_attribute,
                    'delete_account_attribute': delete_account_attribute,
                    'delete_account': delete_account,
                    'info_account': info_account,
                    'ban_account': ban_account,
                    'unban_account': unban_account,
                    'update_account': update_account,
                    'get_limits': get_limits,
                    'set_limits': set_limits,
                    'delete_limits': delete_limits,
                    'list_identities': list_identities,
                    'identity_add': identity_add,
                    'identity_delete': identity_delete,
                    'add_rse': add_rse,
                    'update_rse': update_rse,
                    'set_attribute_rse': set_attribute_rse,
                    'get_attribute_rse': get_attribute_rse,
                    'delete_attribute_rse': delete_attribute_rse,
                    'add_distance_rses': add_distance_rses,
                    'update_distance_rses': update_distance_rses,
                    'get_distance_rses': get_distance_rses,
                    'delete_distance_rses': delete_distance_rses,
                    'add_protocol_rse': add_protocol_rse,
                    'del_protocol_rse': del_protocol_rse,
                    'list_rses': list_rses,
                    'disable_rse': disable_rse,
                    'add_qos_policy': add_qos_policy,
                    'delete_qos_policy': delete_qos_policy,
                    'list_qos_policies': list_qos_policies,
                    'add_scope': add_scope,
                    'list_scopes': list_scopes,
                    'info_rse': info_rse,
                    'get_config': get_config,
                    'set_config_option': set_config_option,
                    'delete_config_option': delete_config_option,
                    'add_subscription': add_subscription,
                    'list_subscriptions': list_subscriptions,
                    'update_subscription': update_subscription,
                    'reevaluate_did_for_subscription': reevaluate_did_for_subscription,
                    'declare_bad_file_replicas': declare_bad_file_replicas,
                    'quarantine_replicas': quarantine_replicas,
                    'declare_temporary_unavailable_replicas': declare_temporary_unavailable_replicas,
                    'list_pfns': list_pfns,
                    'import': import_data,
                    'export': export_data,
                    'set_tombstone': set_tombstone,
                    'set_limit_rse': set_limit_rse,
                    'delete_limit_rse': delete_limit_rse,
                    }

        pager = get_pager()
        console = Console(theme=Theme(CLITheme.LOG_THEMES), soft_wrap=True)
        console.width = max(MIN_CONSOLE_WIDTH, console.width)

        cli_config = get_cli_config()
        spinner = Status('Initializing spinner', spinner=CLITheme.SPINNER, spinner_style=CLITheme.SPINNER_STYLE, console=console)

        if cli_config == 'rich':
            install(console=console, word_wrap=True, width=min(console.width, MAX_TRACEBACK_WIDTH))  # Make rich exception tracebacks the default.
            logger = setup_rich_logger(module_name=__name__, logger_name='user', verbose=args.verbose, console=console)
        else:
            logger = setup_logger(module_name=__name__, logger_name='user', verbose=args.verbose)

        signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, logger))
        setup_gfal2_logger()
        start_time = time.time()
        command = commands.get(args.which)
        client = get_client(args, logger)
        result = command(args, client, logger, console, spinner)  # type: ignore

        end_time = time.time()
        if cli_config == 'rich':
            spinner.stop()
        if console.is_terminal and not args.no_pager:
            command_output = console.end_capture()
            if command_output == '' and args.verbose:
                print("Completed in %-0.4f sec." % (end_time - start_time))
            else:
                if args.verbose:
                    command_output += "Completed in %-0.4f sec." % (end_time - start_time)
                # Ignore SIGINT during pager execution.
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                pager(command_output)
        else:
            if args.verbose:
                print("Completed in %-0.4f sec." % (end_time - start_time))
        sys.exit(result)


if __name__ == '__main__':
    main()
