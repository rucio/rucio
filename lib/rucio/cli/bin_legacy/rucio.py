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
import itertools
import math
import os
import signal
import sys
import time
import unittest
import uuid
from copy import deepcopy
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.padding import Padding
from rich.status import Status
from rich.text import Text
from rich.theme import Theme
from rich.traceback import install
from tabulate import tabulate

# rucio module has the same name as this executable module, so this rule fails. pylint: disable=no-name-in-module
from rucio import version
from rucio.cli.utils import exception_handler, get_client, setup_gfal2_logger, signal_handler
from rucio.client.richclient import MAX_TRACEBACK_WIDTH, MIN_CONSOLE_WIDTH, CLITheme, generate_table, get_cli_config, get_pager, print_output, setup_rich_logger
from rucio.common.client import detect_client_location
from rucio.common.config import config_get, config_get_float
from rucio.common.constants import ReplicaState
from rucio.common.exception import (
    DuplicateRule,
    InputValidationError,
    InvalidObject,
    InvalidType,
    RSENotFound,
    RucioException,
    ScopeNotFound,
    UnsupportedOperation,
)
from rucio.common.extra import import_extras
from rucio.common.test_rucio_server import TestRucioServer
from rucio.common.utils import Color, StoreAndDeprecateWarningAction, chunks, extract_scope, parse_did_filter_from_string, parse_did_filter_from_string_fe, setup_logger, sizefmt

if TYPE_CHECKING:
    from rucio.common.types import FileToUploadDict

EXTRA_MODULES = import_extras(['argcomplete'])

if EXTRA_MODULES['argcomplete']:
    import argcomplete  # pylint: disable=E0401

SUCCESS = 0
FAILURE = 1

DEFAULT_SECURE_PORT = 443
DEFAULT_PORT = 80

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
    return None, did


def __resolve_containers_to_datasets(scope, name, client):
    """
    Helper function to resolve a container into its dataset content.
    """
    datasets = []
    for did in client.list_content(scope, name):
        if did['type'] == 'DATASET':
            datasets.append({'scope': did['scope'], 'name': did['name']})
        elif did['type'] == 'CONTAINER':
            datasets.extend(__resolve_containers_to_datasets(did['scope'], did['name'], client))
    return datasets


@exception_handler
def ping(args, client, logger, console, spinner):
    """
    Pings a Rucio server.
    """
    server_info = client.ping()
    if server_info:
        print(server_info['version'])
        return SUCCESS
    raise RucioException('Ping failed')


@exception_handler
def whoami_account(args, client, logger, console, spinner):
    """
    %(prog)s show [options] <field1=value1 field2=value2 ...>

    Show extended information of a given account
    """
    info = client.whoami()
    if cli_config == 'rich':
        keyword_styles = {**CLITheme.ACCOUNT_STATUS, **CLITheme.ACCOUNT_TYPE}
        table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for (k, v) in sorted(info.items())]
        table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for k in info:
            print(k.ljust(10) + ' : ' + str(info[k]))
    return SUCCESS


@exception_handler
def list_dataset_replicas(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List dataset replicas
    """

    result = {}
    datasets = []

    def _append_to_datasets(scope, name):
        filedid = {'scope': scope, 'name': name}
        if filedid not in datasets:
            datasets.append(filedid)

    def _fetch_datasets_for_meta(meta):
        """Internal function to fetch datasets and recurse into files."""
        if meta['did_type'] != 'DATASET':
            dids = client.scope_list(scope=meta['scope'], name=meta['name'], recursive=True)
            for did in dids:
                if did['type'] == 'FILE':
                    _append_to_datasets(did['parent']['scope'], did['parent']['name'])
        else:
            _append_to_datasets(meta['scope'], meta['name'])

    def _append_result(dsn, replica):
        if dsn not in result:
            result[dsn] = {}
        result[dsn][replica['rse']] = [replica['rse'], replica['available_length'], replica['length']]

    if cli_config == 'rich':
        spinner.update(status='Fetching dataset replicas')
        spinner.start()

    if len(args.dids) == 1:
        scope, name = get_scope(args.dids[0], client)
        dmeta = client.get_metadata(scope, name)
        _fetch_datasets_for_meta(meta=dmeta)
    else:
        extractdids = (get_scope(did, client) for did in args.dids)
        splitdids = [{'scope': scope, 'name': name} for scope, name in extractdids]
        for dmeta in client.get_metadata_bulk(dids=splitdids):
            _fetch_datasets_for_meta(meta=dmeta)

    if args.deep or len(datasets) < 2:
        for did in datasets:
            dsn = f"{did['scope']}:{did['name']}"
            for rep in client.list_dataset_replicas(scope=did['scope'], name=did['name'], deep=args.deep):
                _append_result(dsn=dsn, replica=rep)
    else:
        for rep in client.list_dataset_replicas_bulk(dids=datasets):
            dsn = f"{rep['scope']}:{rep['name']}"
            _append_result(dsn=dsn, replica=rep)

    if args.csv:
        for dsn in result:
            for rse in list(result[dsn].values()):
                print(rse[0], rse[1], rse[2], sep=',')

        if cli_config == 'rich':
            spinner.stop()
    else:
        output = []
        for i, dsn in enumerate(result):
            if cli_config == 'rich':
                if i > 0:
                    output.append(Text(f'\nDATASET: {dsn}', style=CLITheme.TEXT_HIGHLIGHT))
                elif len(result) > 1:
                    output.append(Text(f'DATASET: {dsn}', style=CLITheme.TEXT_HIGHLIGHT))

                table = generate_table(list(result[dsn].values()), headers=['RSE', 'FOUND', 'TOTAL'], col_alignments=['left', 'right', 'right'])
                output.append(table)
            else:
                print(f'\nDATASET: {dsn}')
                print(tabulate(list(result[dsn].values()), tablefmt=tablefmt, headers=['RSE', 'FOUND', 'TOTAL']))

        if cli_config == 'rich':
            spinner.stop()
            print_output(*output, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def list_file_replicas(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List file replicas
    """
    if args.missing:
        args.all_states = True

    protocols = None
    if args.protocols:
        protocols = args.protocols.split(',')

    table_data = []
    dids = []
    if args.missing and not args.rses:
        raise InputValidationError('Cannot use --missing without specifying a RSE')
    if args.link and ':' not in args.link:
        raise ValueError('The substitution parameter must equal --link="/pfn/dir:/dst/dir"')

    if cli_config == 'rich':
        spinner.update(status='Fetching file replicas')
        spinner.start()

    for did in args.dids:
        scope, name = get_scope(did, client)
        client.get_metadata(scope=scope, name=name)  # Break with Exception before streaming replicas if DID does not exist.
        dids.append({'scope': scope, 'name': name})

    replicas = client.list_replicas(dids, schemes=protocols,
                                    ignore_availability=True,
                                    all_states=args.all_states,
                                    rse_expression=args.rses,
                                    metalink=args.metalink,
                                    client_location=detect_client_location(),
                                    sort=args.sort, domain=args.domain,
                                    resolve_archives=not args.no_resolve_archives)
    rses = [rse["rse"] for rse in client.list_rses(rse_expression=args.rses)]

    if args.metalink:
        print(replicas[:-1])  # Last character is newline, no need to print that.
        return SUCCESS

    if args.missing:
        for replica, rse in itertools.product(replicas, rses):
            if 'states' in replica and rse in replica['states'] and replica['states'].get(rse) != 'AVAILABLE':
                if cli_config == 'rich':
                    replica_state = f"[{CLITheme.REPLICA_STATE.get(ReplicaState[replica['states'].get(rse)].value, 'default')}]{ReplicaState[replica['states'].get(rse)].value}[/]"
                    table_data.append([replica['scope'], replica['name'], '({0}) {1}'.format(replica_state, rse)])
                else:
                    table_data.append([replica['scope'], replica['name'], "({0}) {1}".format(ReplicaState[replica['states'].get(rse)].value, rse)])
        if cli_config == 'rich':
            table = generate_table(table_data, headers=['SCOPE', 'NAME', '(STATE) RSE'], col_alignments=['left', 'left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt=tablefmt, headers=['SCOPE', 'NAME', '(STATE) RSE']))

    elif args.link:
        pfn_dir, dst_dir = args.link.split(':')
        if args.rses:
            for replica, rse in itertools.product(replicas, rses):
                if replica['rses'].get(rse):
                    for pfn in replica['rses'][rse]:
                        os.symlink(dst_dir + pfn.rsplit(pfn_dir)[-1], replica['name'])
        else:
            for replica in replicas:
                for rse in replica['rses']:
                    if replica['rses'][rse]:
                        for pfn in replica['rses'][rse]:
                            os.symlink(dst_dir + pfn.rsplit(pfn_dir)[-1], replica['name'])
    elif args.pfns:
        if args.rses:
            for replica in replicas:
                for pfn in replica['pfns']:
                    rse = replica['pfns'][pfn]['rse']
                    if replica['rses'].get(rse):
                        if cli_config == 'rich':
                            table_data.append([pfn])
                        else:
                            print(pfn)
        else:
            for replica in replicas:
                for pfn in replica['pfns']:
                    rse = replica['pfns'][pfn]['rse']
                    if replica['rses'][rse]:
                        if cli_config == 'rich':
                            table_data.append([pfn])
                        else:
                            print(pfn)
        if cli_config == 'rich':
            table = generate_table(table_data, headers=['PFN'], col_alignments=['left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
    else:
        if args.all_states:
            header = ['SCOPE', 'NAME', 'FILESIZE', 'ADLER32', '(STATE) RSE: REPLICA']
        else:
            header = ['SCOPE', 'NAME', 'FILESIZE', 'ADLER32', 'RSE: REPLICA']
        for replica in replicas:
            if 'bytes' in replica:
                for pfn in replica['pfns']:
                    rse = replica['pfns'][pfn]['rse']
                    if args.all_states:
                        if cli_config == 'rich':
                            replica_state = f"[{CLITheme.REPLICA_STATE.get(ReplicaState[replica['states'][rse]].value, 'default')}]{ReplicaState[replica['states'][rse]].value}[/]"
                            # Less does not display hyperlinks well if the table is very wide.
                            if args.no_pager:
                                rse_string = f'({replica_state}) {rse}: [u bright_blue link={pfn}]{pfn}[/]'
                            else:
                                rse_string = f'({replica_state}) {rse}: [u bright_blue]{pfn}[/]'
                        else:
                            rse_string = '({2}) {0}: {1}'.format(rse, pfn, ReplicaState[replica['states'][rse]].value)
                    else:
                        if cli_config == 'rich':
                            # Less does not display hyperlinks well if the table is very wide.
                            if args.no_pager:
                                rse_string = f'{rse}: [u bright_blue link={pfn}]{pfn}[/]'
                            else:
                                rse_string = f'{rse}: [u bright_blue]{pfn}[/]'
                        else:
                            rse_string = '{0}: {1}'.format(rse, pfn)
                    if args.rses:
                        for selected_rse in rses:
                            if rse == selected_rse:
                                table_data.append([replica['scope'], replica['name'], sizefmt(replica['bytes'], args.human), replica['adler32'], rse_string])
                    else:
                        table_data.append([replica['scope'], replica['name'], sizefmt(replica['bytes'], args.human), replica['adler32'], rse_string])

        if cli_config == 'rich':
            table = generate_table(table_data, headers=header, col_alignments=['left', 'left', 'right', 'left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt=tablefmt, headers=header, disable_numparse=True))
    return SUCCESS


@exception_handler
def add_dataset(args, client, logger, console, spinner):
    """
    %(prog)s add-dataset [options] <dsn>

    Add a dataset identifier.
    """

    scope, name = get_scope(args.did, client)
    client.add_dataset(scope=scope, name=name, statuses={'monotonic': args.monotonic}, lifetime=args.lifetime)
    print('Added %s:%s' % (scope, name))
    return SUCCESS


@exception_handler
def add_container(args, client, logger, console, spinner):
    """
    %(prog)s add-container [options] <dsn>

    Add a container identifier.
    """

    scope, name = get_scope(args.did, client)
    client.add_container(scope=scope, name=name, statuses={'monotonic': args.monotonic}, lifetime=args.lifetime)
    print('Added %s:%s' % (scope, name))
    return SUCCESS


@exception_handler
def attach(args, client, logger, console, spinner):
    """
    %(prog)s attach [options] <field1=value1 field2=value2 ...>

    Attach a data identifier.
    """

    scope, name = get_scope(args.todid, client)
    dids = args.dids
    limit = 499

    if args.fromfile:
        if len(dids) > 1:
            raise ValueError('If --fromfile option is active, only one file is supported. The file should contain a list of dids, one per line.')
        try:
            f = open(dids[0], 'r')
            dids = [did.rstrip() for did in f.readlines()]
        except OSError as error:
            logger.error("Can't open file '%s'.", dids[0],)
            raise OSError from error

    dids = [{'scope': get_scope(did, client)[0], 'name': get_scope(did, client)[1]} for did in dids]
    if len(dids) <= limit:
        client.attach_dids(scope=scope, name=name, dids=dids)
    else:
        logger.warning("You are trying to attach too much DIDs. Therefore they will be chunked and attached in multiple commands.")
        missing_dids = []
        for i, chunk in enumerate(chunks(dids, limit)):
            logger.info("Try to attach chunk %s/%s", i, int(math.ceil(float(len(dids)) / float(limit))))
            try:
                client.attach_dids(scope=scope, name=name, dids=chunk)
            except Exception:
                content = [{'scope': did['scope'], 'name': did['name']} for did in client.list_content(scope=scope, name=name)]
                missing_dids += [did for did in chunk if did not in content]

        if missing_dids:
            for chunk in chunks(missing_dids, limit):
                client.attach_dids(scope=scope, name=name, dids=chunk)

    print('DIDs successfully attached to %s:%s' % (scope, name))
    return SUCCESS


@exception_handler
def detach(args, client, logger, console, spinner):
    """
    %(prog)s detach [options] <field1=value1 field2=value2 ...>

    Detach data identifier.
    """

    scope, name = get_scope(args.fromdid, client)
    dids = []
    for did in args.dids:
        cscope, cname = get_scope(did, client)
        dids.append({'scope': cscope, 'name': cname})
    client.detach_dids(scope=scope, name=name, dids=dids)
    print('DIDs successfully detached from %s:%s' % (scope, name))
    return SUCCESS


@exception_handler
def list_dids(args, client, logger, console, spinner):
    """
    %(prog)s list-dids scope[:*|:name] [--filter 'value' | --recursive]

    List the data identifiers for a given scope.
    """

    filters = {}
    table_data = []

    try:
        scope, name = get_scope(args.did[0], client)
        if name == '':
            name = '*'
    except InvalidObject:
        scope = args.did[0]
        name = '*'

    if scope not in client.list_scopes():
        raise ScopeNotFound

    if args.recursive and '*' in name:
        raise InputValidationError('Option recursive cannot be used with wildcards.')
    else:
        if filters:
            if ('name' in filters) and (name != '*'):
                raise ValueError('Must have a wildcard in did name if filtering by name.')

    filters, type_ = parse_did_filter_from_string_fe(args.filter, name)

    if cli_config == 'rich':
        spinner.update(status='Fetching DIDs')
        spinner.start()

    for did in client.list_dids(scope, filters=filters, did_type=type_, long=True, recursive=args.recursive):
        if cli_config == 'rich':
            table_data.append([f"{did['scope']}:{did['name']}", Text(did['did_type'], style=CLITheme.DID_TYPE.get(did['did_type'], 'default'))])
        else:
            table_data.append([f"{did['scope']}:{did['name']}", did['did_type']])

    if args.short:
        for did, _ in table_data:
            print(did)
    else:
        if cli_config == 'rich':
            table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt=tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))

    return SUCCESS


@exception_handler
def list_dids_extended(args, client, logger, console, spinner):
    """
    %(prog)s list-dids-extended scope[:*|:name] [--filter 'key=value' | --recursive]

    List the data identifiers for a given scope (DEPRECATED).
    """
    raise UnsupportedOperation('This command has been deprecated. Please use list_dids instead.')


@exception_handler
def list_scopes(args, client, logger, console, spinner):
    """
    %(prog)s list-scopes <scope>

    List scopes.
    """
    if (cli_config == 'rich') or (not args.csv):
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
def list_files(args, client, logger, console, spinner):
    """
    %(prog)s list-files [options] <field1=value1 field2=value2 ...>

    List data identifier contents.
    """

    if cli_config == 'rich':
        spinner.update(status='Fetching files')
        spinner.start()

    if args.csv:
        for did in args.dids:
            scope, name = get_scope(did, client)
            for f in client.list_files(scope=scope, name=name):
                guid = f['guid']
                if guid:
                    guid = f'{guid[0:8]}-{guid[8:12]}-{guid[12:16]}-{guid[16:20]}-{guid[20:32]}'
                else:
                    guid = '(None)'
                print('{}:{}'.format(f['scope'], f['name']), guid, f['adler32'], sizefmt(f['bytes'], args.human), f['events'], sep=',')
        if cli_config == 'rich':
            spinner.stop()
        return SUCCESS
    elif args.LOCALPATH:
        full_str = ''
        if cli_config == 'rich':
            header = '''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!DOCTYPE POOLFILECATALOG SYSTEM "InMemory">
<POOLFILECATALOG>'''
            full_str = header
        else:
            print('''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!DOCTYPE POOLFILECATALOG SYSTEM "InMemory">
<POOLFILECATALOG>''')

        file_str = ''' <File ID="%s">
  <physical>
   <pfn filetype="ROOT_All" name="%s/%s"/>
  </physical>
  <logical>
   <lfn name="%s"/>
  </logical>
 </File>'''

        for did in args.dids:
            scope, name = get_scope(did, client)
            for f in client.list_files(scope=scope, name=name):
                guid = f['guid']
                if guid:
                    guid = f'{guid[0:8]}-{guid[8:12]}-{guid[12:16]}-{guid[16:20]}-{guid[20:32]}'
                else:
                    guid = '(None)'

                if cli_config == 'rich':
                    full_str += '\n' + file_str % (guid, args.LOCALPATH, f['name'], f['name'])
                else:
                    print(file_str % (guid, args.LOCALPATH, f['name'], f['name']))

        if cli_config == 'rich':
            spinner.stop()
            print_output(full_str + '\n</POOLFILECATALOG>', console=console, no_pager=True)
        else:
            print('</POOLFILECATALOG>')
        return SUCCESS
    else:
        table_data = []
        for did in args.dids:
            totfiles = 0
            totsize = 0
            totevents = 0
            scope, name = get_scope(did, client)
            for file in client.list_files(scope=scope, name=name):
                totfiles += 1
                totsize += int(file['bytes'])
                if file['events']:
                    totevents += int(file.get('events', 0))
                guid = file['guid']
                if guid:
                    guid = f'{guid[0:8]}-{guid[8:12]}-{guid[12:16]}-{guid[16:20]}-{guid[20:32]}'
                else:
                    guid = '(None)'
                table_data.append([f"{file['scope']}:{file['name']}", guid, f"ad:{file['adler32']}", sizefmt(file['bytes'], args.human), file['events']])

            if cli_config == 'rich':
                table = generate_table(table_data, headers=['SCOPE:NAME', 'GUID', 'ADLER32', 'FILESIZE', 'EVENTS'], col_alignments=['left', 'left', 'left', 'right', 'right'])
                summary_data = [['Total files', str(totfiles)], ['Total size', sizefmt(totsize, args.human)]]
                if totevents:
                    summary_data.append(['Total events', str(totevents)])
                summary_table = generate_table(summary_data, col_alignments=['left', 'left'], row_styles=['none'])
                spinner.stop()
                print_output(table, summary_table, console=console, no_pager=args.no_pager)
            else:
                print(tabulate(table_data, tablefmt=tablefmt, headers=['SCOPE:NAME', 'GUID', 'ADLER32', 'FILESIZE', 'EVENTS'], disable_numparse=True))
                print('Total files : %s' % totfiles)
                print('Total size : %s' % sizefmt(totsize, args.human))
                if totevents:
                    print('Total events : %s' % totevents)
        return SUCCESS


@exception_handler
def list_content(args, client, logger, console, spinner):
    """
    %(prog)s list-content [options] <field1=value1 field2=value2 ...>

    List data identifier contents.
    """

    table_data = []
    if cli_config == 'rich':
        spinner.update(status='Fetching dataset contents')
        spinner.start()

    for did in args.dids:
        scope, name = get_scope(did, client)
        for content in client.list_content(scope=scope, name=name):
            if cli_config == 'rich':
                table_data.append([f"{content['scope']}:{content['name']}", Text(content['type'].upper(), style=CLITheme.DID_TYPE.get(content['type'].upper(), 'default'))])
            else:
                table_data.append([f"{content['scope']}:{content['name']}", content['type'].upper()])

    if args.short:
        for did, dummy in table_data:
            print(did)
    else:
        if cli_config == 'rich':
            table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt=tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))

    return SUCCESS


@exception_handler
def list_content_history(args, client, logger, console, spinner):
    """
    %(prog)s list-content-history [options] <field1=value1 field2=value2 ...>

    List data identifier contents.
    """

    table_data = []
    if cli_config == 'rich':
        spinner.update(status='Fetching content history')
        spinner.start()

    for did in args.dids:
        scope, name = get_scope(did, client)
        for content in client.list_content_history(scope=scope, name=name):
            if cli_config == 'rich':
                table_data.append([f"{content['scope']}:{content['name']}", Text(content['type'].upper(), style=CLITheme.DID_TYPE.get(content['type'].upper(), 'default'))])
            else:
                table_data.append([f"{content['scope']}:{content['name']}", content['type'].upper()])

    if cli_config == 'rich':
        table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        print(tabulate(table_data, tablefmt=tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))
    return SUCCESS


@exception_handler
def list_parent_dids(args, client, logger, console, spinner):
    """
    %(prog)s list-parent-dids

    List parent data identifier.
    """

    if cli_config == 'rich':
        spinner.update(status='Fetching parent DIDs')
        spinner.start()

    if args.did:
        table_data = []
        scope, name = get_scope(args.did, client)
        for dataset in client.list_parent_dids(scope=scope, name=name):
            if cli_config == 'rich':
                table_data.append([f"{dataset['scope']}:{dataset['name']}", Text(dataset['type'], style=CLITheme.DID_TYPE.get(dataset['type'], 'default'))])
            else:
                table_data.append([f"{dataset['scope']}:{dataset['name']}", dataset['type']])

        if cli_config == 'rich':
            table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt=tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))
    else:
        raise InputValidationError('A DID must be provided. Use -h to list the options.')
    return SUCCESS


@exception_handler
def close(args, client, logger, console, spinner):
    """
    %(prog)s close [options] <field1=value1 field2=value2 ...>

    Close a dataset or container.
    """

    for did in args.dids:
        scope, name = get_scope(did, client)
        client.set_status(scope=scope, name=name, open=False)
        print(f'{scope}:{name} has been closed.')
    return SUCCESS


@exception_handler
def reopen(args, client, logger, console, spinner):
    """
    %(prog)s reopen [options] <field1=value1 field2=value2 ...>

    Reopen a dataset or container (only for privileged users).
    """

    for did in args.dids:
        scope, name = get_scope(did, client)
        client.set_status(scope=scope, name=name, open=True)
        print(f'{scope}:{name} has been reopened.')
    return SUCCESS


@exception_handler
def stat(args, client, logger, console, spinner):
    """
    %(prog)s stat [options] <field1=value1 field2=value2 ...>

    List attributes and statuses about data identifiers..
    """

    if cli_config == 'rich':
        spinner.update(status='Fetching DID stats')
        spinner.start()
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE}

    output = []
    for i, did in enumerate(args.dids):
        scope, name = get_scope(did, client)
        info = client.get_did(scope=scope, name=name, dynamic_depth='DATASET')
        if cli_config == 'rich':
            if i > 0:
                output.append(Text(f'\nDID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            elif len(args.dids) > 1:
                output.append(Text(f'DID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for (k, v) in sorted(info.items())]
            table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
            output.append(table)
        else:
            if i > 0:
                print('------')
            table = [(k + ':', str(v)) for (k, v) in sorted(info.items())]
            print(tabulate(table, tablefmt='plain', disable_numparse=True))

    if cli_config == 'rich':
        spinner.stop()
        print_output(*output, console=console, no_pager=args.no_pager)
    return SUCCESS


def erase(args, client, logger, console, spinner):
    """
    %(prog)s erase [options] <field1=value1 field2=value2 ...>

    Delete data identifier.
    """

    for did in args.dids:
        if '*' in did:
            logger.warning("This command doesn't support wildcards! Skipping DID: %s", did)
            continue
        try:
            scope, name = get_scope(did, client)
        except RucioException as error:
            logger.warning('DID is in wrong format: %s', did)
            logger.debug('Error: %s', error)
            continue

        if args.undo:
            try:
                client.set_metadata(scope=scope, name=name, key='lifetime', value=None)
                logger.info('Erase undo for DID: %s:%s', scope, name)
            except Exception:
                logger.warning('Cannot undo erase operation on DID. DID not existent or grace period of 24 hours already expired.')
                logger.warning('    DID: %s:%s', scope, name)
        else:
            try:
                # set lifetime to expire in 24 hours (value is in seconds).
                client.set_metadata(scope=scope, name=name, key='lifetime', value=86400)
                logger.info('CAUTION! erase operation is irreversible after 24 hours. To cancel this operation you can run the following command:')
                print("rucio erase --undo {0}:{1}".format(scope, name))
            except RucioException as error:
                logger.warning('Failed to erase DID: %s', did)
                logger.debug('Error: %s', error)
    return SUCCESS


@exception_handler
def upload(args, client, logger, console, spinner):
    """
    rucio upload [scope:datasetname] [folder/] [files1 file2 file3]
    %(prog)s upload [options] <field1=value1 field2=value2 ...>

    Upload files into Rucio
    """
    if args.lifetime and args.expiration_date:
        raise InputValidationError("--lifetime and --expiration-date cannot be specified at the same time.")
    elif args.expiration_date:
        expiration_date = datetime.strptime(args.expiration_date, "%Y-%m-%d-%H:%M:%S")
        if expiration_date < datetime.utcnow():
            raise ValueError("The specified expiration date should be in the future!")
        args.lifetime = (expiration_date - datetime.utcnow()).total_seconds()

    dsscope = None
    dsname = None
    for arg in args.args:
        did = arg.split(':')
        if not dsscope and len(did) == 2:
            dsscope = did[0]
            dsname = did[1]
        elif len(did) == 2:
            logger.warning('Ignoring input %s because dataset DID is already set %s:%s', arg, dsscope, dsname)

    items: list[FileToUploadDict] = []
    for arg in args.args:
        if arg.count(':') > 0:
            continue
        if args.pfn and args.impl:
            logger.warning('Ignoring --impl option because --pfn option given')
            args.impl = None

        item: FileToUploadDict = {'path': arg, 'rse': args.rse}

        if args.scope:
            item['did_scope'] = args.scope
        if args.name:
            item['did_name'] = args.name
        if dsscope:
            item['dataset_scope'] = dsscope
        if dsname:
            item['dataset_name'] = dsname
        if args.impl:
            item['impl'] = args.impl
        if args.protocol:
            item['force_scheme'] = args.protocol
        if args.pfn:
            item['pfn'] = args.pfn
        if args.no_register:
            item['no_register'] = True
        if args.register_after_upload:
            item['register_after_upload'] = True
        if args.lifetime is not None:
            item['lifetime'] = int(args.lifetime)
        if args.transfer_timeout is not None:
            item['transfer_timeout'] = int(args.transfer_timeout)
        if args.guid:
            item['guid'] = args.guid
        if args.recursive:
            item['recursive'] = True

        items.append(item)

    if len(items) < 1:
        raise InputValidationError('No files could be extracted from the given arguments')

    if len(items) > 1 and args.guid:
        logger.error("A single GUID was specified on the command line, but there are multiple files to upload.")
        logger.error("If GUID auto-detection is not used, only one file may be uploaded at a time")
        raise InputValidationError('Invalid input argument composition')

    if len(items) > 1 and args.name:
        logger.error("A single LFN was specified on the command line, but there are multiple files to upload.")
        logger.error("If LFN auto-detection is not used, only one file may be uploaded at a time")
        raise InputValidationError('Invalid input argument composition')

    if args.recursive and args.pfn:
        logger.error("It is not possible to create the folder structure into collections with a non-deterministic way.")
        logger.error("If PFN is specified, you cannot use --recursive")
        raise InputValidationError('Invalid input argument composition')

    from rucio.client.uploadclient import UploadClient
    upload_client = UploadClient(client, logger=logger)
    summary_file_path = 'rucio_upload.json' if args.summary else None
    upload_client.upload(items=items, summary_file_path=summary_file_path)
    return SUCCESS


@exception_handler
def download(args, client, logger, console, spinner):
    """
    %(prog)s download [options] <field1=value1 field2=value2 ...>

    Download files from Rucio using new threaded model and RSE expression support
    """
    # Input validation
    if not args.dids and not args.filter and not args.metalink_file:
        raise InputValidationError('At least one did is mandatory')
    elif not args.dids and args.filter and not args.scope:
        raise InputValidationError('The argument scope is mandatory')

    if args.filter and args.metalink_file:
        raise InputValidationError('Arguments filter and metalink cannot be used together.')

    if args.dids and args.metalink_file:
        raise InputValidationError('Arguments dids and metalink cannot be used together.')

    if args.ignore_checksum and args.check_local_with_filesize_only:
        raise InputValidationError('Arguments ignore-checksum and check-local-with-filesize-only cannot be used together.')

    trace_pattern = {}

    if args.trace_appid:
        trace_pattern['appid'] = args.trace_appid
    if args.trace_dataset:
        trace_pattern['dataset'] = args.trace_dataset
    if args.trace_datasetscope:
        trace_pattern['datasetScope'] = args.trace_datasetscope
    if args.trace_eventtype:
        trace_pattern['eventType'] = args.trace_eventtype
    if args.trace_pq:
        trace_pattern['pq'] = args.trace_pq
    if args.trace_taskid:
        trace_pattern['taskid'] = args.trace_taskid
    if args.trace_usrdn:
        trace_pattern['usrdn'] = args.trace_usrdn
    deactivate_file_download_exceptions = args.deactivate_file_download_exceptions if args.deactivate_file_download_exceptions is not None else False

    from rucio.client.downloadclient import DownloadClient
    download_client = DownloadClient(client=client, logger=logger, check_admin=args.allow_tape)

    result = None
    item_defaults = {}
    item_defaults['rse'] = args.rses
    item_defaults['base_dir'] = args.dir
    item_defaults['no_subdir'] = args.no_subdir
    item_defaults['transfer_timeout'] = args.transfer_timeout
    item_defaults['no_resolve_archives'] = args.no_resolve_archives
    item_defaults['ignore_checksum'] = args.ignore_checksum
    item_defaults['check_local_with_filesize_only'] = args.check_local_with_filesize_only
    archive_did = args.archive_did
    if archive_did:
        logger.warning("Archives are treated transparently. --archive-did option is being obsoleted.")  # TODO

    # Get filters
    filters = {}
    type_ = 'all'
    if args.filter:
        try:
            filters, type_ = parse_did_filter_from_string(args.filter)
            if args.scope:
                filters['scope'] = args.scope
        except (InvalidType, ValueError) as error:
            logger.error(error)
            raise error
        except Exception as error:
            logger.error("Invalid Filter. Filter must be 'key=value', 'key>=value', 'key>value', 'key<=value', 'key<value'")
            raise error
        item_defaults['filters'] = filters

    if not args.pfn:
        item_defaults['impl'] = args.impl
        item_defaults['force_scheme'] = args.protocol
        item_defaults['nrandom'] = args.nrandom
        item_defaults['transfer_speed_timeout'] = args.transfer_speed_timeout \
            if args.transfer_speed_timeout is not None \
            else config_get_float('download', 'transfer_speed_timeout', False, 500)
        items = []
        if args.dids:
            for did in args.dids:
                if args.scope:
                    did = f"{args.scope}:{did}"
                item = {'did': did}
                item.update(item_defaults)
                items.append(item)
        else:
            items.append(item_defaults)

        if args.aria:
            result = download_client.download_aria2c(items, trace_pattern, deactivate_file_download_exceptions=deactivate_file_download_exceptions, sort=args.sort)
        elif args.metalink_file:
            result = download_client.download_from_metalink_file(items[0], args.metalink_file, deactivate_file_download_exceptions=deactivate_file_download_exceptions)
            if args.sort:
                logger.warning('Ignoring --replica-selection option because --metalink option given')
        else:
            result = download_client.download_dids(items, args.ndownloader, trace_pattern, deactivate_file_download_exceptions=deactivate_file_download_exceptions, sort=args.sort)
    else:
        if args.aria:
            logger.warning('Ignoring --aria option because --pfn option given')
        if args.impl:
            logger.warning('Ignoring --impl option because --pfn option given')
        if args.protocol:
            logger.warning('Ignoring --protocol option because --pfn option given')
        if args.transfer_speed_timeout:
            logger.warning("Download with --pfn doesn't support --transfer-speed-timeout")
        num_dids = len(args.dids)
        did_str = args.dids[0]
        if num_dids > 1:
            logger.warning('Download with --pfn option only supports one DID but %s DIDs were given. Considering only first DID: %s', num_dids, did_str)
            logger.debug(args.dids)
        item_defaults['pfn'] = args.pfn
        item_defaults['did'] = did_str
        if args.rses is None:
            logger.warning("No RSE was given, selecting one.")
            if not args.scope:
                scope = did_str.split(':')[0]
                did = did_str.split(':')[-1]
            else:
                scope = args.scope
                did = did_str.split(':')[-1]

            replicas = client.list_replicas(
                [{"scope": scope, "name": did}],
                schemes=args.protocol,
                ignore_availability=False,
                client_location=detect_client_location(),
                resolve_archives=not args.no_resolve_archives
            )

            download_rse = _get_rse_for_pfn(replicas, args.pfn)
            if download_rse is None:
                raise RSENotFound("Could not find RSE for pfn %s" % args.pfn)
            else:
                item_defaults['rse'] = download_rse

        result = download_client.download_pfns([item_defaults], 1, trace_pattern, deactivate_file_download_exceptions=deactivate_file_download_exceptions)

    if not result:
        raise RucioException('Download API failed')

    summary = {}
    for item in result:
        for did, did_stats in item.get('input_dids', {}).items():
            did_summary = summary.setdefault(did, {'length': did_stats.get('length'), 'DONE': 0, 'ALREADY_DONE': 0, '_total': 0})
            did_summary['_total'] += 1
            state = item['clientState'].upper()
            if state in did_summary:
                did_summary[state] += 1

    print('----------------------------------')
    print('Download summary')
    if not len(summary):
        print('-' * 40)
        print('No DID matching the pattern')

    for summary_key, did_summary in summary.items():
        print('-' * 40)
        print('DID %s' % summary_key)
        length = did_summary['length']
        ds_total = did_summary['_total']
        downloaded_files = did_summary['DONE']
        local_files = did_summary['ALREADY_DONE']
        not_downloaded_files = ds_total - downloaded_files - local_files

        if length:
            print('{0:40} {1:6d}'.format('Total files (DID): ', length))
            print('{0:40} {1:6d}'.format('Total files (filtered):   ', ds_total))
        else:
            print('{0:40} {1:6d}'.format('Total files:   ', ds_total))
        print('{0:40} {1:6d}'.format('Downloaded files: ', downloaded_files))
        print('{0:40} {1:6d}'.format('Files already found locally: ', local_files))
        print('{0:40} {1:6d}'.format('Files that cannot be downloaded: ', not_downloaded_files))

    return SUCCESS


def _get_rse_for_pfn(replicas, pfn) -> Optional[str]:
    # Check each rse in the replica list for the pfn. If no pfn is found, returns None.
    # If it is found, stop the generator and return the item.
    for replica in replicas:
        try:
            download_rse = next(
                rse for rse in replica['rses']
                if pfn in replica['rses'][rse]
            )
        except StopIteration:
            continue
        else:
            return download_rse


@exception_handler
def get_metadata(args, client, logger, console, spinner):
    """
    %(prog)s get_metadata [options] <field1=value1 field2=value2 ...>

    Get data identifier metadata
    """

    if args.plugin:
        plugin = args.plugin
    else:
        plugin = config_get('client', 'metadata_default_plugin', default='DID_COLUMN')

    if cli_config == 'rich':
        spinner.update(status='Fetching metadata')
        spinner.start()
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE, **CLITheme.AVAILABILITY}

    output = []
    for i, did in enumerate(args.dids):
        scope, name = get_scope(did, client)
        meta = client.get_metadata(scope=scope, name=name, plugin=plugin)
        if cli_config == 'rich':
            if i > 0:
                output.append(Text(f'\nDID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            elif len(args.dids) > 1:
                output.append(Text(f'DID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for (k, v) in sorted(meta.items())]
            table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
            output.append(table)
        else:
            if i > 0:
                print('------')
            table = [(k + ':', str(v)) for (k, v) in sorted(meta.items())]
            print(tabulate(table, tablefmt='plain', disable_numparse=True))

    if cli_config == 'rich':
        spinner.stop()
        print_output(*output, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def set_metadata(args, client, logger, console, spinner):
    """
    %(prog)s set_metadata [options] <field1=value1 field2=value2 ...>

    Set data identifier metadata
    """

    value = args.value
    if args.key == 'lifetime':
        value = None if args.value.lower() == 'none' else float(args.value)
    scope, name = get_scope(args.did, client)
    client.set_metadata(scope=scope, name=name, key=args.key, value=value)
    return SUCCESS


@exception_handler
def delete_metadata(args, client, logger, console, spinner):
    """
    %(prog)s set_metadata [options] <field1=value1 field2=value2 ...>

    Delete data identifier metadata
    """

    scope, name = get_scope(args.did, client)
    client.delete_metadata(scope=scope, name=name, key=args.key)
    return SUCCESS


@exception_handler
def add_rule(args, client, logger, console, spinner):
    """
    %(prog)s add-rule <did> <copies> <rse-expression> [options]

    Add a rule to a DID.
    """

    dids = []
    rule_ids = []
    for did in args.dids:
        scope, name = get_scope(did, client)
        dids.append({'scope': scope, 'name': name})
    try:
        rule_ids = client.add_replication_rule(dids=dids,
                                               copies=args.copies,
                                               rse_expression=args.rse_expression,
                                               weight=args.weight,
                                               lifetime=args.lifetime,
                                               grouping=args.grouping,
                                               account=args.rule_account,
                                               locked=args.locked,
                                               source_replica_expression=args.source_replica_expression,
                                               notify=args.notify,
                                               activity=args.activity,
                                               comment=args.comment,
                                               ask_approval=args.ask_approval,
                                               asynchronous=args.asynchronous,
                                               delay_injection=args.delay_injection)
    except DuplicateRule as error:
        if args.ignore_duplicate:
            for did in dids:
                try:
                    rule_id = client.add_replication_rule(dids=[did],
                                                          copies=args.copies,
                                                          rse_expression=args.rse_expression,
                                                          weight=args.weight,
                                                          lifetime=args.lifetime,
                                                          grouping=args.grouping,
                                                          account=args.rule_account,
                                                          locked=args.locked,
                                                          source_replica_expression=args.source_replica_expression,
                                                          notify=args.notify,
                                                          activity=args.activity,
                                                          comment=args.comment,
                                                          ask_approval=args.ask_approval,
                                                          asynchronous=args.asynchronous,
                                                          delay_injection=args.delay_injection)
                    rule_ids.extend(rule_id)
                except DuplicateRule:
                    print('Duplicate rule for %s:%s found; Skipping.' % (did['scope'], did['name']))
        else:
            raise error

    for rule in rule_ids:
        print(rule)
    return SUCCESS


@exception_handler
def delete_rule(args, client, logger, console, spinner):
    """
    %(prog)s delete-rule [options] <ruleid>

    Delete a rule.
    """

    try:
        # Test if the rule_id is a real rule_id
        uuid.UUID(args.rule_id)
        client.delete_replication_rule(rule_id=args.rule_id, purge_replicas=args.purge_replicas)
    except ValueError:
        # Otherwise, trying to extract the scope, name from args.rule_id
        if not args.rses:
            raise InputValidationError('A RSE expression must be specified if you do not provide a rule_id but a DID')
        scope, name = get_scope(args.rule_id, client)
        rules = client.list_did_rules(scope=scope, name=name)
        if args.rule_account is None:
            account = client.account
        else:
            account = args.rule_account
        deletion_success = False
        for rule in rules:
            if args.delete_all:
                account_checked = True
            else:
                account_checked = rule['account'] == account
            if rule['rse_expression'] == args.rses and account_checked:
                client.delete_replication_rule(rule_id=rule['id'], purge_replicas=args.purge_replicas)
                deletion_success = True
        if not deletion_success:
            raise RucioException('No replication rule was deleted from the DID')
    return SUCCESS


@exception_handler
def update_rule(args, client, logger, console, spinner):
    """
    %(prog)s update-rule [options] <ruleid>

    Update a rule.
    """

    options = {}
    if args.lifetime:
        options['lifetime'] = None if args.lifetime.lower() == "none" else int(args.lifetime)
    if args.locked:
        if args.locked.title() == "True":
            options['locked'] = True
        elif args.locked.title() == "False":
            options['locked'] = False
        else:
            raise InputValidationError('Locked must be True or False')

    if args.comment:
        options['comment'] = args.comment
    if args.rule_account:
        options['account'] = args.rule_account
    if args.state_stuck:
        options['state'] = 'STUCK'
    if args.state_suspended:
        options['state'] = 'SUSPENDED'
    if args.rule_activity:
        options['activity'] = args.rule_activity
    if args.source_replica_expression:
        options['source_replica_expression'] = None if args.source_replica_expression.lower() == 'none' else args.source_replica_expression
    if args.cancel_requests:
        if 'state' not in options:
            raise InputValidationError('--stuck or --suspend must be specified when running --cancel-requests')
        options['cancel_requests'] = True
    if args.priority:
        options['priority'] = int(args.priority)
    if args.child_rule_id:
        if args.child_rule_id.lower() == 'none':
            options['child_rule_id'] = None
        else:
            options['child_rule_id'] = args.child_rule_id
    if args.boost_rule:
        options['boost_rule'] = args.boost_rule
    client.update_replication_rule(rule_id=args.rule_id, options=options)
    print('Updated Rule')
    return SUCCESS


@exception_handler
def move_rule(args, client, logger, console, spinner):
    """
    %(prog)s move-rule [options] <ruleid> <rse_expression>

    Update a rule.
    """

    override = {}
    if args.activity:
        override['activity'] = args.activity
    if args.source_replica_expression:
        override['source_replica_expression'] = None if args.source_replica_expression.lower() == "none" else args.source_replica_expression

    print(client.move_replication_rule(rule_id=args.rule_id,
                                       rse_expression=args.rse_expression,
                                       override=override))
    return SUCCESS


@exception_handler
def info_rule(args, client, logger, console, spinner):
    """
    %(prog)s rule-info [options] <ruleid>

    Retrieve information about a rule.
    """

    if cli_config == 'rich':
        spinner.update(status='Fetching rule info')
        spinner.start()

    if args.examine:
        output = []
        analysis = client.examine_replication_rule(rule_id=args.rule_id)
        if cli_config == 'rich':
            keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE, **CLITheme.RULE_STATE}
            rule_status = " ".join([f'[{keyword_styles.get(word, "default")}]{word}[/]' for word in analysis['rule_error'].split()])
            output.append(f'Status of the replication rule: {rule_status}')
            if analysis['transfers']:
                output.append('[b]STUCK Requests:[/]')
                for transfer in analysis['transfers']:
                    output.append(Padding.indent(Text(f"{transfer['scope']}:{transfer['name']}", style=CLITheme.SUBHEADER_HIGHLIGHT), 2))
                    table_data = [['RSE:', str(transfer['rse'])],
                                  ['Attempts:', str(transfer['attempts'])],
                                  ['Last retry:', str(transfer['last_time'])],
                                  ['Last error:', str(transfer['last_source'])],
                                  ['Available sources:', ', '.join([source[0] for source in transfer['sources'] if source[1]])],
                                  ['Blocklisted sources:', ', '.join([source[0] for source in transfer['sources'] if not source[1]])]]
                    table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
                    output.append(Padding.indent(table, 2))

            spinner.stop()
            print_output(*output, console=console, no_pager=args.no_pager)
        else:
            analysis = client.examine_replication_rule(rule_id=args.rule_id)
            print('Status of the replication rule: %s' % analysis['rule_error'])
            if analysis['transfers']:
                print('STUCK Requests:')
                for transfer in analysis['transfers']:
                    print('  %s:%s' % (transfer['scope'], transfer['name']))
                    print('    RSE:                  %s' % str(transfer['rse']))
                    print('    Attempts:             %s' % str(transfer['attempts']))
                    print('    Last Retry:           %s' % str(transfer['last_time']))
                    print('    Last error:           %s' % str(transfer['last_error']))
                    print('    Last source:          %s' % str(transfer['last_source']))
                    print('    Available sources:    %s' % ', '.join([source[0] for source in transfer['sources'] if source[1]]))
                    print('    Blocklisted sources:  %s' % ', '.join([source[0] for source in transfer['sources'] if not source[1]]))
    else:
        rule = client.get_replication_rule(rule_id=args.rule_id)
        if cli_config == 'rich':
            keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE, **CLITheme.RULE_STATE}
            table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for k, v in sorted(rule.items())]
            table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print("Id:                         %s" % rule['id'])
            print("Account:                    %s" % rule['account'])
            print("Scope:                      %s" % rule['scope'])
            print("Name:                       %s" % rule['name'])
            print("RSE Expression:             %s" % rule['rse_expression'])
            print("Copies:                     %s" % rule['copies'])
            print("State:                      %s" % rule['state'])
            print("Locks OK/REPLICATING/STUCK: %s/%s/%s" % (rule['locks_ok_cnt'], rule['locks_replicating_cnt'], rule['locks_stuck_cnt']))
            print("Grouping:                   %s" % rule['grouping'])
            print("Expires at:                 %s" % rule['expires_at'])
            print("Locked:                     %s" % rule['locked'])
            print("Weight:                     %s" % rule['weight'])
            print("Created at:                 %s" % rule['created_at'])
            print("Updated at:                 %s" % rule['updated_at'])
            print("Error:                      %s" % rule['error'])
            print("Subscription Id:            %s" % rule['subscription_id'])
            print("Source replica expression:  %s" % rule['source_replica_expression'])
            print("Activity:                   %s" % rule['activity'])
            print("Comment:                    %s" % rule['comments'])
            print("Ignore Quota:               %s" % rule['ignore_account_limit'])
            print("Ignore Availability:        %s" % rule['ignore_availability'])
            print("Purge replicas:             %s" % rule['purge_replicas'])
            print("Notification:               %s" % rule['notification'])
            print("End of life:                %s" % rule['eol_at'])
            print("Child Rule Id:              %s" % rule['child_rule_id'])
    return SUCCESS


@exception_handler
def list_rules(args, client, logger, console, spinner):
    """
    %(prog)s list-rules ...

    List rules.
    """

    if cli_config == 'rich':
        spinner.update(status='Fetching rules')
        spinner.start()

    if args.rule_id:
        rules = [client.get_replication_rule(args.rule_id)]
    elif args.file:
        scope, name = get_scope(args.file, client)
        rules = client.list_associated_rules_for_file(scope=scope, name=name)
    elif args.traverse:
        scope, name = get_scope(args.did, client)
        locks = client.get_dataset_locks(scope=scope, name=name)
        rules = []
        for rule_id in list(set([lock['rule_id'] for lock in locks])):
            rules.append(client.get_replication_rule(rule_id))
    elif args.did:
        scope, name = get_scope(args.did, client)
        meta = client.get_metadata(scope=scope, name=name)
        rules = client.list_did_rules(scope=scope, name=name)
        try:
            next(rules)
            rules = client.list_did_rules(scope=scope, name=name)
        except StopIteration:
            rules = []
            # looking for other rules
            if meta['did_type'] == 'CONTAINER':
                for dsn in client.list_content(scope, name):
                    rules.extend(client.list_did_rules(scope=dsn['scope'], name=dsn['name']))
                if rules:
                    print('No rules found, listing rules for content')
            if meta['did_type'] == 'DATASET':
                for container in client.list_parent_dids(scope, name):
                    rules.extend(client.list_did_rules(scope=container['scope'], name=container['name']))
                if rules:
                    print('No rules found, listing rules for parents')
    elif args.rule_account:
        rules = client.list_account_rules(account=args.rule_account)
    elif args.subscription:
        account = args.rule_account if args.rule_account else client.account
        name = args.subscription
        rules = client.list_subscription_rules(account=account, name=name)
    else:
        raise InputValidationError('At least one option has to be given. Use -h to list the options.')
    if args.csv:
        for rule in rules:
            print(rule['id'],
                  rule['account'],
                  f"{rule['scope']}:{rule['name']}",
                  f"{rule['state']}[{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}]",
                  rule['rse_expression'],
                  rule['copies'],
                  sizefmt(rule['bytes'], args.human) if rule['bytes'] is not None else 'N/A',
                  rule['expires_at'],
                  rule['created_at'],
                  sep=',')

        if cli_config == 'rich':
            spinner.stop()
    else:
        table_data = []
        for rule in rules:
            if cli_config == 'rich':
                table_data.append([rule['id'],
                                   rule['account'],
                                   f"{rule['scope']}:{rule['name']}",
                                   f"[{CLITheme.RULE_STATE.get(rule['state'], 'default')}]{rule['state']}[/][{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}]",
                                   rule['rse_expression'],
                                   rule['copies'],
                                   sizefmt(rule['bytes'], args.human) if rule['bytes'] is not None else 'N/A',
                                   rule['expires_at'],
                                   rule['created_at']])
            else:
                table_data.append([rule['id'],
                                   rule['account'],
                                   f"{rule['scope']}:{rule['name']}",
                                   f"{rule['state']}[{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}]",
                                   rule['rse_expression'],
                                   rule['copies'],
                                   sizefmt(rule['bytes'], args.human) if rule['bytes'] is not None else 'N/A',
                                   rule['expires_at'],
                                   rule['created_at']])

        if cli_config == 'rich':
            table = generate_table(table_data, headers=['ID', 'ACCOUNT', 'SCOPE:NAME', 'STATE[OK/REPL/STUCK]', 'RSE EXPRESSION', 'COPIES', 'SIZE', 'EXPIRES (UTC)', 'CREATED (UTC)'],
                                   col_alignments=['left', 'left', 'left', 'right', 'left', 'right', 'right', 'left', 'left'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt='simple', headers=['ID', 'ACCOUNT', 'SCOPE:NAME', 'STATE[OK/REPL/STUCK]', 'RSE_EXPRESSION', 'COPIES', 'SIZE', 'EXPIRES (UTC)', 'CREATED (UTC)'], disable_numparse=True))
    return SUCCESS


@exception_handler
def list_rules_history(args, client, logger, console, spinner):
    """
    %(prog)s list-rules_history ...

    List replication rules history for a DID.
    """
    rule_dict = []
    if cli_config == 'rich':
        spinner.update(status='Fetching rules history')
        spinner.start()

    scope, name = get_scope(args.did, client)
    table_data = []
    for rule in client.list_replication_rule_full_history(scope, name):
        if rule['rule_id'] not in rule_dict:
            rule_dict.append(rule['rule_id'])
            if cli_config == 'rich':
                table_data.append(['Insertion', rule['account'], rule['rse_expression'], rule['created_at']])
            else:
                print('-' * 40)
                print('Rule insertion')
                print('Account : %s' % rule['account'])
                print('RSE expression : %s' % (rule['rse_expression']))
                print('Time : %s' % (rule['created_at']))
        else:
            rule_dict.remove(rule['rule_id'])
            if cli_config == 'rich':
                table_data.append(['Deletion', rule['account'], rule['rse_expression'], rule['updated_at']])
            else:
                print('-' * 40)
                print('Rule deletion')
                print('Account : %s' % rule['account'])
                print('RSE expression : %s' % (rule['rse_expression']))
                print('Time : %s' % (rule['updated_at']))

    if cli_config == 'rich':
        table_data = sorted(table_data, key=lambda entry: entry[-1], reverse=True)
        table = generate_table(table_data, headers=['ACTION', 'ACCOUNT', 'RSE EXPRESSION', 'TIME'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def list_rses(args, client, logger, console, spinner):
    """
    %(prog)s list-rses [options] <field1=value1 field2=value2 ...>

    List rses.

    """
    if cli_config == 'rich':
        spinner.update(status='Fetching RSEs')
        spinner.start()

    rses = client.list_rses(args.rses)
    if args.csv:
        print(*(rse['rse'] for rse in rses), sep='\n')
    elif cli_config == 'rich':
        table = generate_table([[rse['rse']] for rse in sorted(rses, key=lambda elem: elem['rse'])], headers=['RSE'], col_alignments=['left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        for rse in rses:
            print('%(rse)s' % rse)
    return SUCCESS


@exception_handler
def list_suspicious_replicas(args, client, logger, console, spinner):
    """
    %(prog)s list-suspicious-replicas [options] <field1=value1 field2=value2 ...>

    List replicas marked as suspicious.

    """

    rse_expression = None
    younger_than = None
    nattempts = None
    if args.rse_expression:
        rse_expression = args.rse_expression
    if args.younger_than:
        younger_than = args.younger_than
    if args.nattempts:
        nattempts = args.nattempts

    if cli_config == 'rich':
        spinner.update(status='Fetching suspicious replicas')
        spinner.start()

    # Generator is a list with one entry, which itself is a list of lists.
    replicas_gen = client.list_suspicious_replicas(rse_expression, younger_than, nattempts)
    for i in replicas_gen:
        replicas = i
    table = []
    table_data = []
    for rep in replicas:
        table_data.append([rep['rse'], rep['scope'], rep['created_at'], rep['cnt'], rep['name']])

    if cli_config == 'rich':
        table = generate_table(table_data, headers=['RSE EXPRESSION', 'SCOPE', 'CREATED AT', 'N-ATTEMPTS', 'FILE NAME'], col_alignments=['left', 'left', 'left', 'right', 'left'])
        spinner.stop()
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        print(tabulate(table_data, headers=(['RSE Expression:', 'Scope:', 'Created at:', 'Nattempts:', 'File Name:'])))
    return SUCCESS


@exception_handler
def list_rse_attributes(args, client, logger, console, spinner):
    """
    %(prog)s list-rse-attributes [options] <field1=value1 field2=value2 ...>

    List rses.

    """

    attributes = client.list_rse_attributes(rse=args.rse)
    if cli_config == 'rich':
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.RSE_TYPE}
        table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for k, v in sorted(attributes.items())]  # columns have mixed datatypes
        table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
        print_output(table, console=console, no_pager=args.no_pager)
    else:
        table = [(k + ':', str(v)) for (k, v) in sorted(attributes.items())]  # columns have mixed datatypes
        print(tabulate(table, tablefmt='plain', disable_numparse=True))  # disabling number parsing
    return SUCCESS


@exception_handler
def list_rse_usage(args, client, logger, console, spinner):
    """
    %(prog)s list-rse-usage [options] <rse>

    Show the space usage of a given rse

    """

    if cli_config == 'rich':
        spinner.update(status='Fetching RSE usage')
        spinner.start()

    all_usages = client.get_rse_usage(rse=args.rse, filters={'per_account': args.show_accounts})
    select_usages = [u for u in all_usages if u['source'] not in ('srm', 'gsiftp', 'webdav')]

    if cli_config == 'rich':
        output = []
        table_data = []
        header = ['SOURCE', 'USED', 'FILES', 'FREE', 'TOTAL', 'UPDATED AT']
        header_account_data = ['ACCOUNT', 'USED', 'PERCENTAGE %']
        key2id = {header[i].lower().replace(' ', '_'): i for i in range(len(header))}
        account_data = {}
    for usage in select_usages:
        if cli_config == 'rich':
            row = [''] * len(header)
        for elem in usage:
            if elem in ['free', 'total'] and usage['source'] != 'storage' or elem == 'files' and usage['source'] != 'rucio':
                continue
            elif elem in ['used', 'free', 'total']:
                if cli_config == 'rich':
                    row[key2id[elem]] = sizefmt(usage[elem], args.human)
                else:
                    print('  {0}: {1}'.format(elem, sizefmt(usage[elem], args.human)))
            elif elem == 'account_usages':
                if cli_config == 'rich':
                    if usage[elem]:
                        for account in usage[elem]:
                            if cli_config == 'rich':
                                account_data[usage['source']].append([account['account'], sizefmt(account['used'], args.human), str(account['percentage'])])
                else:
                    account_usages_title = '  per account:'
                    if not usage[elem]:
                        account_usages_title += ' no usage'
                    else:
                        print(account_usages_title)
                        print('  ------')
                        col_width = max(len(str(entry[1])) for account in usage[elem] for entry in list(account.items())) + 16
                        for account in usage[elem]:
                            base_string = '    '
                            used_string = 'used: {0}'.format(sizefmt(account['used'], args.human))
                            account_string = 'account: {0}'.format(account['account'])
                            percentage_string = 'percentage: {0}'.format(account['percentage'])
                            print(base_string + account_string.ljust(col_width) + used_string.ljust(col_width) + percentage_string.ljust(col_width))
                            print('  ------')
            else:
                if cli_config == 'rich':
                    if elem in key2id:
                        row[key2id[elem]] = str(usage[elem])
                    if elem == 'source':
                        account_data[usage[elem]] = []
                else:
                    print('  {0}: {1}'.format(elem, usage[elem]))

        if cli_config == 'rich':
            table_data.append(row)

    if cli_config == 'rich':
        table = generate_table(table_data, headers=header, col_alignments=['left', 'right', 'right', 'right', 'right', 'left'])
        output.append(table)

        if args.show_accounts:
            output.append('\n[b]USAGE PER ACCOUNT:')
            for source in account_data:
                if len(account_data[source]) > 0:
                    output.append(Padding.indent(Text(f'source: {source}', style=CLITheme.SUBHEADER_HIGHLIGHT), 2))
                    account_table = generate_table(account_data[source], headers=header_account_data, col_alignments=['left', 'right', 'right'])
                    output.append(Padding.indent(account_table, 2))

        spinner.stop()
        print_output(*output, console=console, no_pager=args.no_pager)
    else:
        print('------')
    return SUCCESS


@exception_handler
def list_account_limits(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List account limits.

    """
    if cli_config == 'rich':
        spinner.update(status='Fetching account limits')
        spinner.start()

    if args.rse:
        limits = client.get_local_account_limit(account=args.limit_account, rse=args.rse)
    else:
        limits = client.get_local_account_limits(account=args.limit_account)

    table_data = []
    for limit in list(limits.items()):
        table_data.append([limit[0], sizefmt(limit[1], args.human)])
    table_data.sort()

    if cli_config == 'rich':
        table1 = generate_table(table_data, headers=['RSE', 'LIMIT'], col_alignments=['left', 'right'])
    else:
        print(tabulate(table_data, tablefmt=tablefmt, headers=['RSE', 'LIMIT']))

    table_data = []
    limits = client.get_global_account_limits(account=args.limit_account)
    for limit in list(limits.items()):
        if (args.rse and args.rse in limit[1]['resolved_rses']) or not args.rse:
            table_data.append([limit[0], sizefmt(limit[1]['limit'], args.human)])
    table_data.sort()

    if cli_config == 'rich':
        table2 = generate_table(table_data, headers=['RSE EXPRESSION', 'LIMIT'], col_alignments=['left', 'right'])
    else:
        print(tabulate(table_data, tablefmt=tablefmt, headers=['RSE EXPRESSION', 'LIMIT']))

    if cli_config == 'rich':
        spinner.stop()
        print_output(table1, table2, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def list_account_usage(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List account usage.

    """
    if cli_config == 'rich':
        spinner.update(status='Fetching account usage')
        spinner.start()

    usage = client.get_local_account_usage(account=args.usage_account, rse=args.rse)
    table_data = []
    for item in usage:
        remaining = 0 if float(item['bytes_remaining']) < 0 else float(item['bytes_remaining'])
        table_data.append([item['rse'], sizefmt(item['bytes'], args.human), sizefmt(item['bytes_limit'], args.human), sizefmt(remaining, args.human)])
    table_data.sort()

    if cli_config == 'rich':
        table1 = generate_table(table_data, headers=['RSE', 'USAGE', 'LIMIT', 'QUOTA LEFT'], col_alignments=['left', 'right', 'right', 'right'])
    else:
        print(tabulate(table_data, tablefmt=tablefmt, headers=['RSE', 'USAGE', 'LIMIT', 'QUOTA LEFT']))

    table_data = []
    usage = client.get_global_account_usage(account=args.usage_account)
    for item in usage:
        if (args.rse and args.rse in item['rse_expression']) or not args.rse:
            remaining = 0 if float(item['bytes_remaining']) < 0 else float(item['bytes_remaining'])
            table_data.append([item['rse_expression'], sizefmt(item['bytes'], args.human), sizefmt(item['bytes_limit'], args.human), sizefmt(remaining, args.human)])
    table_data.sort()

    if cli_config == 'rich':
        table2 = generate_table(table_data, headers=['RSE EXPRESSION', 'USAGE', 'LIMIT', 'QUOTA LEFT'], col_alignments=['left', 'right', 'right', 'right'])
    else:
        print(tabulate(table_data, tablefmt=tablefmt, headers=['RSE EXPRESSION', 'USAGE', 'LIMIT', 'QUOTA LEFT']))

    if cli_config == 'rich':
        spinner.stop()
        print_output(table1, table2, console=console, no_pager=args.no_pager)
    return SUCCESS


@exception_handler
def list_datasets_rse(args, client, logger, console, spinner):
    """
    %(prog)s list [options] <field1=value1 field2=value2 ...>

    List the datasets in a site.

    """

    if cli_config == 'rich':
        spinner.update(status='Fetching datasets at RSE')
        spinner.start()

    if args.long:
        table_data = []
        for dsn in client.list_datasets_per_rse(args.rse):
            table_data.append([f"{dsn['scope']}:{dsn['name']}"
                               f"{str(dsn['available_length'])}/{str(dsn['length'])}",
                               f"{str(dsn['available_bytes'])}/{str(dsn['bytes'])}"])

        if cli_config == 'rich':
            table_data.sort()
            table = generate_table(table_data, headers=['SCOPE:NAME', 'LOCAL FILES/TOTAL FILES', 'LOCAL BYTES/TOTAL BYTES'], col_alignments=['left', 'right', 'right'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print(tabulate(table_data, tablefmt=tablefmt, headers=['DID', 'LOCAL FILES/TOTAL FILES', 'LOCAL BYTES/TOTAL BYTES']))
    else:
        dsns = list(set([f"{dsn['scope']}:{dsn['name']}" for dsn in client.list_datasets_per_rse(args.rse)]))
        dsns.sort()
        if cli_config == 'rich':
            table = generate_table([[dsn] for dsn in dsns], headers=['SCOPE:NAME'])
            spinner.stop()
            print_output(table, console=console, no_pager=args.no_pager)
        else:
            print("SCOPE:NAME")
            print('----------')
            for dsn in dsns:
                print(dsn)
    return SUCCESS


@exception_handler
def add_lifetime_exception(args, client, logger, console, spinner):
    """
    %(prog)s add_lifetime_exception [options] <field1=value1 field2=value2 ...>

    Declare a lifetime model exception.

    """

    if not args.reason:
        raise InputValidationError('reason for the extension is mandatory')
    reason = args.reason
    if not args.expiration:
        raise InputValidationError('expiration is mandatory')
    try:
        expiration = datetime.strptime(args.expiration, "%Y-%m-%d")
    except Exception as err:
        msg = f'Cannot parse expiration date: {err}'
        raise ValueError(msg)

    if not args.inputfile:
        raise InputValidationError('inputfile is mandatory')
    with open(args.inputfile) as infile:
        # Deduplicate the content of the input file and ignore empty lines.
        dids = set(did for line in infile if (did := line.strip()))

    dids_list = []
    containers = []
    datasets = []
    for did in dids:
        scope, name = get_scope(did, client)
        dids_list.append({'scope': scope, 'name': name})
    error_summary = {
        "total_dids": {"description": "Total DIDs", "count": len(dids_list)},
        "files_ignored": {"description": "DID not submitted because it is a file", "count": 0},
        "containers_resolved": {"description": "DID that are containers and were resolved", "count": 0},
        "not_in_lifetime_model": {"description": "DID not submitted because it is not part of the lifetime campaign", "count": 0},
        "successfully_submitted": {"description": "DID successfully submitted including the one from containers resolved", "count": 0},
    }
    chunk_limit = 500  # Server should be able to accept 1000
    dids_list_copy = deepcopy(dids_list)
    for chunk in chunks(dids_list_copy, chunk_limit):
        for meta in client.get_metadata_bulk(chunk):
            scope, name = meta['scope'], meta['name']
            dids_list.remove({'scope': scope, 'name': name})
            if meta['did_type'] == 'FILE':
                logger.warning('%s:%s is a file. Will be ignored', scope, name)
                error_summary["files_ignored"]["count"] += 1
            elif meta['did_type'] == 'CONTAINER':
                logger.warning('%s:%s is a container. It needs to be resolved', scope, name)
                containers.append({'scope': scope, 'name': name})
                error_summary["containers_resolved"]["count"] += 1
            elif not meta['eol_at']:
                logger.warning('%s:%s is not affected by the lifetime model', scope, name)
                error_summary["not_in_lifetime_model"]["count"] += 1
            else:
                logger.info('%s:%s will be declared', scope, name)
                datasets.append({'scope': scope, 'name': name})
                error_summary["successfully_submitted"]["count"] += 1

    for did in dids_list:
        scope = did['scope']
        name = did['name']
        logger.warning('%s:%s does not exist', scope, name)

    if containers:
        logger.warning('One or more DIDs are containers. They will be resolved into a list of datasets to request exception. Full list below')
        for container in containers:
            logger.info('Resolving %s:%s into datasets :', container['scope'], container['name'])
            list_datasets = __resolve_containers_to_datasets(container['scope'], container['name'], client)
            for chunk in chunks(list_datasets, chunk_limit):
                for meta in client.get_metadata_bulk(chunk):
                    scope, name = meta['scope'], meta['name']
                    logger.debug('%s:%s', scope, name)
                    if not meta['eol_at']:
                        logger.warning('%s:%s is not affected by the lifetime model', scope, name)
                        error_summary["not_in_lifetime_model"]["count"] += 1
                    else:
                        logger.info('%s:%s will be declared', scope, name)
                        datasets.append({'scope': scope, 'name': name})
                        error_summary["successfully_submitted"]["count"] += 1
    if not datasets:
        logger.error('Nothing to submit')
        return SUCCESS

    client.add_exception(dids=datasets, account=client.account, pattern='', comments=reason, expires_at=expiration)

    logger.info('Exception successfully submitted. Summary below:')
    for key, data in error_summary.items():
        print('{0:100} {1:6d}'.format(data["description"], data["count"]))
    return SUCCESS


def test_server(args, client, logger, console, spinner):
    """"
    %(prog)s test-rucio-server [options] <field1=value1 field2=value2 ...>
    Test the client against a server.
    """
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRucioServer)
    unittest.TextTestRunner(verbosity=2).run(suite)
    return SUCCESS


def touch(args, client, logger, console, spinner):
    """
    %(prog)s touch [options] <did1 did2 ...>
    """

    for did in args.dids:
        scope, name = get_scope(did, client)
        client.touch(scope, name, args.rse)


def rse_completer(prefix, parsed_args, **kwargs):
    """
    Completes the argument with a list of RSEs
    """
    client = get_client(parsed_args, logger=None)
    return ["%(rse)s" % rse for rse in client.list_rses()]


def get_parser():
    """
    Returns the argparse parser.
    """
    oparser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]), add_help=True, exit_on_error=False)
    subparsers = oparser.add_subparsers()

    # Main arguments
    oparser.add_argument('--version', action='version', version='%(prog)s ' + version.version_string())
    oparser.add_argument('--config', dest="config", help="The Rucio configuration file to use.")
    oparser.add_argument('--verbose', '-v', default=False, action='store_true', help="Print more verbose output.")
    oparser.add_argument('-H', '--host', dest="host", metavar="ADDRESS", help="The Rucio API host.")
    oparser.add_argument('--auth-host', dest="auth_host", metavar="ADDRESS", help="The Rucio Authentication host.")
    oparser.add_argument('-a', '--account', dest="issuer", help="Rucio account to use.")
    oparser.add_argument('-S', '--auth-strategy', dest="auth_strategy", default=None, help="Authentication strategy (userpass, x509...)")
    oparser.add_argument('-T', '--timeout', dest="timeout", type=float, default=None, help="Set all timeout values to seconds.")
    oparser.add_argument('--robot', '-R', dest="human", default=True, action='store_false', help="All output in bytes and without the units. This output format is preferred by parsers and scripts.")
    oparser.add_argument('--user-agent', '-U', dest="user_agent", default='rucio-clients', action='store', help="Rucio User Agent")
    oparser.add_argument('--vo', dest="vo", metavar="VO", default=None, help="VO to authenticate at. Only used in multi-VO mode.")
    oparser.add_argument("--no-pager", dest="no_pager", default=False, action='store_true', help=argparse.SUPPRESS)

    # Options for the userpass or OIDC auth_strategy
    oparser.add_argument('-u', '--user', dest='username', default=None, help='username')
    oparser.add_argument('-pwd', '--password', dest='password', default=None, help='password')
    # Options for defining remaining OIDC parameters
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
    oparser.add_argument('--certificate', dest='certificate', default=None, help='Client certificate file for x509 Authentication.')
    oparser.add_argument('--client-key', dest='client_key', default=None, help='Client key for x509 Authentication.')
    oparser.add_argument('--ca-certificate', dest='ca_certificate', default=None, help='CA certificate to verify peer against (SSL).')

    # Ping command
    ping_parser = subparsers.add_parser('ping', formatter_class=argparse.RawDescriptionHelpFormatter, help='Ping Rucio server.',
                                        epilog='Usage example\n'
                                               '"""""""""""""\n'
                                               '\n'
                                               'To ping the server::\n'
                                               '\n'
                                               '    $ rucio ping\n'
                                               '    1.14.8\n'
                                               '\n'
                                               'The returned value is the version of Rucio installed on the server.'
                                               '\n')
    ping_parser.set_defaults(function=ping)

    # The whoami command
    whoami_parser = subparsers.add_parser('whoami', help='Get information about account whose token is used.', formatter_class=argparse.RawDescriptionHelpFormatter,
                                          epilog='''Usage example
"""""""""""""
::

    $ rucio whoami
    jdoe

The returned value is the account currently used.
                                                 ''')

    whoami_parser.set_defaults(function=whoami_account)

    # The list-file-replicas command
    list_file_replicas_parser = subparsers.add_parser('list-file-replicas', help='List the replicas of a DID and its PFNs.', description='This method allows to list all the replicas of a given Data IDentifier (DID). \
The only mandatory parameter is the DID which can be a container/dataset/files. By default all the files replicas in state available are returned.', formatter_class=argparse.RawDescriptionHelpFormatter,
                                                      epilog='''Usage example
^^^^^^^^^^^^^

To list the file replicas for a given dataset::

    $ rucio list-file-replicas user.jdoe:user.jdoe.test.data.1234.1
    +-----------+---------------------------------+------------+-----------+-----------------------------------------------------------------------------------+
    | SCOPE     | NAME                            | FILESIZE   | ADLER32   | RSE: REPLICA                                                                      |
    |-----------+---------------------------------+------------+-----------+-----------------------------------------------------------------------------------|
    | user.jdoe | user.jdoe.test.data.1234.file.1 | 94.835 MB  | 5d000974  | SITE1_DISK: srm://blahblih/path/to/file/user.jdoe/user.jdoe.test.data.1234.file.1 |
    | user.jdoe | user.jdoe.test.data.1234.file.1 | 94.835 MB  | 5d000974  | SITE2_DISK: file://another/path/to/file/user.jdoe/user.jdoe.test.data.1234.file.1 |
    | user.jdoe | user.jdoe.test.data.1234.file.2 | 82.173 MB  | 01e56f23  | SITE2_DISK: file://another/path/to/file/user.jdoe/user.jdoe.test.data.1234.file.2 |
    +-----------+---------------------------------+------------+-----------+-----------------------------------------------------------------------------------+

To list the missing replica of a dataset of a given RSE-expression::

    $ rucio list-file-replicas --rses SITE1_DISK user.jdoe:user.jdoe.test.data.1234.1
    +-----------+---------------------------------+------------+-----------+-----------------------------------------------------------------------------------+
    | SCOPE     | NAME                            | FILESIZE   | ADLER32   | RSE: REPLICA                                                                      |
    |-----------+---------------------------------+------------+-----------+-----------------------------------------------------------------------------------|
    | user.jdoe | user.jdoe.test.data.1234.file.1 | 94.835 MB  | 5d000974  | SITE1_DISK: srm://blahblih/path/to/file/user.jdoe/user.jdoe.test.data.1234.file.1 |
    +-----------+---------------------------------+------------+-----------+-----------------------------------------------------------------------------------+
    ''')
    list_file_replicas_parser.set_defaults(function=list_file_replicas)
    list_file_replicas_parser.add_argument('--protocols', dest='protocols', action='store', help='List of comma separated protocols. (i.e. https, root, srm).', required=False)
    list_file_replicas_parser.add_argument('--all-states', dest='all_states', action='store_true', default=False, help='To select all replicas (including unavailable ones).\
            Also gets information about the current state of a DID in each RSE.\
            Legend: ' + ', '.join(["{0} = {1}".format(state.value, state.name) for state in ReplicaState]), required=False)
    list_file_replicas_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')
    list_file_replicas_parser.add_argument('--pfns', default=False, action='store_true', help='Show only the PFNs.', required=False)
    list_file_replicas_parser.add_argument('--domain', default=None, action='store', help='Force the networking domain. Available options: wan, lan, all.', required=False)
    list_file_replicas_parser.add_argument('--link', dest='link', default=None, action='store', help='Symlink PFNs with directory substitution.\
            For example: rucio list-file-replicas --rse RSE_TEST --link /eos/:/eos/ scope:datasetname', required=False)
    list_file_replicas_parser.add_argument('--missing', dest='missing', default=False, action='store_true', help='To list missing replicas at a RSE-Expression. Must be used with --rses option', required=False)
    list_file_replicas_parser.add_argument('--metalink', dest='metalink', default=False, action='store_true', help='Output available replicas as metalink.', required=False)
    list_file_replicas_parser.add_argument('--no-resolve-archives', dest='no_resolve_archives', default=False, action='store_true', help='Do not resolve archives which may contain the files.', required=False)
    list_file_replicas_parser.add_argument('--sort', dest='sort', default=None, action='store', help='Replica sort algorithm. Available options: geoip (default), random', required=False)
    list_file_replicas_parser.add_argument('--rses', dest='rses', default=None, action='store', help='The RSE filter expression. A comprehensive help about RSE expressions\
            can be found in ' + Color.BOLD + 'https://rucio.cern.ch/documentation/started/concepts/rse_expressions' + Color.END)

    # The list-dataset-replicas command
    list_dataset_replicas_parser = subparsers.add_parser('list-dataset-replicas', help='List the dataset replicas.',
                                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                                         epilog='''Usage example
"""""""""""""
::

    $ rucio list-dataset-replicas user.jdoe:user.jdoe.test.data.1234.1

    DATASET: user.jdoe:user.jdoe.test.data.1234.1
    +------------+---------+---------+
    | RSE        |   FOUND |   TOTAL |
    |------------+---------+---------|
    | SITE1_DISK |       1 |       2 |
    | SITE2_DISK |       2 |       2 |
    +------------+---------+---------+
    ''')
    list_dataset_replicas_parser.set_defaults(function=list_dataset_replicas)
    list_dataset_replicas_parser.add_argument(dest='dids', action='store', nargs='+', help='The name of the DID to search.')
    list_dataset_replicas_parser.add_argument('--deep', action='store_true', help='Make a deep check.')
    list_dataset_replicas_parser.add_argument('--csv', dest='csv', action='store_true', default=False, help='Comma Separated Value output.',)

    # The add-dataset command
    add_dataset_parser = subparsers.add_parser('add-dataset', help='Add a dataset to Rucio Catalog.',
                                               formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio add-dataset user.jdoe:user.jdoe.test.data.1234.1
    Added user.jdoe:user.jdoe.test.data.1234.1

    ''')

    add_dataset_parser.set_defaults(function=add_dataset)
    add_dataset_parser.add_argument('--monotonic', action='store_true', help='Monotonic status to True.')
    add_dataset_parser.add_argument(dest='did', action='store', help='The name of the dataset to add.')
    add_dataset_parser.add_argument('--lifetime', dest='lifetime', action='store', type=int, help='Lifetime in seconds.')

    # The add-container command
    add_container_parser = subparsers.add_parser('add-container', help='Add a container to Rucio Catalog.',
                                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio add-container user.jdoe:user.jdoe.test.cont.1234.1
    Added user.jdoe:user.jdoe.test.cont.1234.1

    ''')

    add_container_parser.set_defaults(function=add_container)
    add_container_parser.add_argument('--monotonic', action='store_true', help='Monotonic status to True.')
    add_container_parser.add_argument(dest='did', action='store', help='The name of the container to add.')
    add_container_parser.add_argument('--lifetime', dest='lifetime', action='store', type=int, help='Lifetime in seconds.')

    # The attach command
    attach_parser = subparsers.add_parser('attach', help='Attach a list of DIDs to a parent DID.',
                                          description='Attach a list of Data IDentifiers (file, dataset or container) to an other Data IDentifier (dataset or container).',
                                          formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio attach user.jdoe:user.jdoe.test.cont.1234.1 user.jdoe:user.jdoe.test.data.1234.1
    DIDs successfully attached to user.jdoe:user.jdoe.test.cont.1234.1

    ''')

    attach_parser.set_defaults(function=attach)
    attach_parser.add_argument(dest='todid', action='store', help='Destination Data IDentifier (either dataset or container).')
    attach_parser.add_argument('-f', '--from-file', dest='fromfile', action='store_true', default=False, help='Attach the DIDs contained in a file. The file should contain one did per line.')
    attach_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers (or a file containing one did per line, if -f is present).')

    # The detach command
    detach_parser = subparsers.add_parser('detach', help='Detach a list of DIDs from a parent DID.',
                                          description='Detach a list of Data Identifiers (file, dataset or container) from an other Data Identifier (dataset or container).',
                                          formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio detach user.jdoe:user.jdoe.test.cont.1234.1 user.jdoe:user.jdoe.test.data.1234.1
    DIDs successfully detached from user.jdoe:user.jdoe.test.cont.1234.1

    ''')

    detach_parser.set_defaults(function=detach)
    detach_parser.add_argument(dest='fromdid', action='store', help='Target Data IDentifier (must be a dataset or container).')
    detach_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

    # The list command
    ls_parser = subparsers.add_parser('ls', help='List the data identifiers matching some metadata (synonym for list-dids).', description='List the Data IDentifiers matching certain pattern. \
Only the collections (i.e. dataset or container) are returned by default. With the filter option, you can specify a list of metadata that the Data IDentifier should match.',
                                      formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
You can query the DIDs matching a certain pattern. It always requires to specify the scope in which you want to search::

    $ rucio ls user.jdoe:*
    +-------------------------------------------+--------------+
    | SCOPE:NAME                                | [DID TYPE]   |
    |-------------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
    | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
    | user.jdoe:user.jdoe.test.cont.1234.2      | CONTAINER    |
    | user.jdoe:user.jdoe.test.dataset.1        | DATASET      |
    | user.jdoe:user.jdoe.test.dataset.2        | DATASET      |
    | user.jdoe:user.jdoe.test.data.1234.1      | DATASET      |
    | user.jdoe:test.file.1                     | FILE         |
    | user.jdoe:test.file.2                     | FILE         |
    | user.jdoe:test.file.3                     | FILE         |
    +-------------------------------------------+--------------+

You can filter by key/value, e.g.::

    $ rucio ls --filter type=CONTAINER
    +-------------------------------------------+--------------+
    | SCOPE:NAME                                | [DID TYPE]   |
    |-------------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
    | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
    | user.jdoe:user.jdoe.test.cont.1234.2      | CONTAINER    |
    +-------------------------------------------+--------------+
    ''')

    ls_parser.set_defaults(function=list_dids)
    ls_parser.add_argument('-r', '--recursive', dest='recursive', action='store_true', default=False, help='List data identifiers recursively.')
    ls_parser.add_argument('--filter', dest='filter', action='store', help='Filter arguments in form `key=value,another_key=next_value`. Valid keys are name, type.')
    ls_parser.add_argument('--short', dest='short', action='store_true', help='Just dump the list of DIDs.')
    ls_parser.add_argument(dest='did', nargs=1, action='store', default=None, help='Data IDentifier pattern.')

    list_parser = subparsers.add_parser('list-dids',
                                        help='List the data identifiers matching some metadata (synonym for ls).',
                                        description='''List the Data IDentifiers matching certain pattern.
Only the collections (i.e. dataset or container) are returned by default.
With the filter option, you can specify a list of metadata that the Data IDentifier should match.
Please use the filter option `--filter type=all` to find all types of Data IDentifiers.''',
                                        formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""

You can query the DIDs matching a certain pattern. It always requires to specify the scope in which you want to search::

    $ rucio list-dids --filter 'type=all' user.jdoe:*
    +-------------------------------------------+--------------+
    | SCOPE:NAME                                | [DID TYPE]   |
    |-------------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
    | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
    | user.jdoe:user.jdoe.test.cont.1234.2      | CONTAINER    |
    | user.jdoe:user.jdoe.test.dataset.1        | DATASET      |
    | user.jdoe:user.jdoe.test.dataset.2        | DATASET      |
    | user.jdoe:user.jdoe.test.data.1234.1      | DATASET      |
    | user.jdoe:test.file.1                     | FILE         |
    | user.jdoe:test.file.2                     | FILE         |
    | user.jdoe:test.file.3                     | FILE         |
    +-------------------------------------------+--------------+

You can filter by key/value, e.g.::

    $ rucio list-dids --filter 'type=CONTAINER'
    +-------------------------------------------+--------------+
    | SCOPE:NAME                                | [DID TYPE]   |
    |-------------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
    | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
    | user.jdoe:user.jdoe.test.cont.1234.2      | CONTAINER    |
    +-------------------------------------------+--------------+''')

    list_parser.set_defaults(function=list_dids)
    list_parser.add_argument('--recursive', dest='recursive', action='store_true', default=False, help='List data identifiers recursively.')
    list_parser.add_argument('--filter', dest='filter', action='store', help='Single or logically combined filtering expression(s) either in the form <key><operator><value> or <value1><operator1><key><operator2><value2> (compound inequality). Keys are equivalent to columns in the DID table. Operators must belong to the set of (<=, >=, ==, !=, >, <). The following conventions for combining expressions are used: ";" represents the logical OR operator; "," represents the logical AND operator.')  # noqa: E501
    list_parser.add_argument('--short', dest='short', action='store_true', help='Just dump the list of DIDs.')
    list_parser.add_argument(dest='did', nargs=1, action='store', default=None, help='Data IDentifier pattern')

    # The extended version of list_dids that goes through the plugin mechanism
    list_extended_parser = subparsers.add_parser('list-dids-extended',
                                                 help='List the data identifiers matching some metadata (extended version to include metadata from various resources).',
                                                 description='''List the Data IDentifiers matching certain pattern.
Only the collections (i.e. dataset or container) are returned by default.
With the filter option, you can specify a list of metadata that the Data IDentifier should match.
Please use the filter option `--filter type=all` to find all types of Data IDentifiers.''',
                                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""

You can query the DIDs matching a certain pattern. It always requires to specify the scope in which you want to search::

    $ rucio list-dids --filter 'type=all' user.jdoe:*
    +-------------------------------------------+--------------+
    | SCOPE:NAME                                | [DID TYPE]   |
    |-------------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
    | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
    | user.jdoe:user.jdoe.test.cont.1234.2      | CONTAINER    |
    | user.jdoe:user.jdoe.test.dataset.1        | DATASET      |
    | user.jdoe:user.jdoe.test.dataset.2        | DATASET      |
    | user.jdoe:user.jdoe.test.data.1234.1      | DATASET      |
    | user.jdoe:test.file.1                     | FILE         |
    | user.jdoe:test.file.2                     | FILE         |
    | user.jdoe:test.file.3                     | FILE         |
    +-------------------------------------------+--------------+

You can filter by key/value, e.g.::

    $ rucio list-dids --filter 'type=CONTAINER'
    +-------------------------------------------+--------------+
    | SCOPE:NAME                                | [DID TYPE]   |
    |-------------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
    | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
    | user.jdoe:user.jdoe.test.cont.1234.2      | CONTAINER    |
    +-------------------------------------------+--------------+''')

    list_extended_parser.set_defaults(function=list_dids_extended)

    # The list parent-dids command
    list_parent_parser = subparsers.add_parser('list-parent-dids', help='List parent DIDs for a given DID', description='List all parents Data IDentifier that contains the target Data IDentifier.',
                                               formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio list-parent-dids user.jdoe:user.jdoe.test.data.1234.1
    +--------------------------------------+--------------+
    | SCOPE:NAME                           | [DID TYPE]   |
    |--------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.cont.1234.2 | CONTAINER    |
    +--------------------------------------+--------------+

    ''')
    list_parent_parser.set_defaults(function=list_parent_dids)
    list_parent_parser.add_argument(dest='did', action='store', nargs='?', default=None, help='Data identifier.')

    # argparse 2.7 does not allow aliases for commands, thus the list-parent-datasets is a copy&paste from list-parent-dids
    list_parent_datasets_parser = subparsers.add_parser('list-parent-datasets', help='List parent DIDs for a given DID', description='List all parents Data IDentifier that contains the target Data IDentifier.',
                                                        formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio list-parent-datasets user.jdoe:user.jdoe.test.data.1234.1
    +--------------------------------------+--------------+
    | SCOPE:NAME                           | [DID TYPE]   |
    |--------------------------------------+--------------|
    | user.jdoe:user.jdoe.test.cont.1234.2 | CONTAINER    |
    +--------------------------------------+--------------+

    ''')

    list_parent_datasets_parser.set_defaults(function=list_parent_dids)
    list_parent_datasets_parser.add_argument(dest='did', action='store', nargs='?', default=None, help='Data identifier.')

    # The list-scopes command
    scope_list_parser = subparsers.add_parser('list-scopes', help='List all available scopes.',
                                              formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio list-scopes
    mc
    data
    user.jdoe
    user.janedoe

    ''')

    scope_list_parser.set_defaults(function=list_scopes)
    scope_list_parser.add_argument("--csv", action="store_true", default=False, help="Comma Separated Value output.")
    scope_list_parser.add_argument('--account', help='Filter scopes by account')

    # The close command
    close_parser = subparsers.add_parser('close', help='Close a dataset or container.')
    close_parser.set_defaults(function=close)
    close_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

    # The reopen command
    reopen_parser = subparsers.add_parser('reopen', help='Reopen a dataset or container (only for privileged users).')
    reopen_parser.set_defaults(function=reopen)
    reopen_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

    # The stat command
    stat_parser = subparsers.add_parser('stat', help='List attributes and statuses about data identifiers.')
    stat_parser.set_defaults(function=stat)
    stat_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

    # The erase command
    erase_parser = subparsers.add_parser('erase', help='Delete a data identifier.', description='This command sets the lifetime of the DID in order to expire in the next 24 hours.\
            After this time, the dataset is eligible for deletion. The deletion is not reversible after 24 hours grace time period expired.')
    erase_parser.set_defaults(function=erase)
    erase_parser.add_argument('--undo', dest='undo', action='store_true', default=False, help='Undo erase DIDs. Only works if has been less than 24 hours since erase operation.')
    erase_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

    # The list_files command
    list_files_parser = subparsers.add_parser('list-files', help='List DID contents', description='List all the files in a Data IDentifier. The DID can be a container, dataset or a file.\
                                                                  What is returned is a list of files in the DID with : <scope>:<name>\t<guid>\t<checksum>\t<filesize>')
    list_files_parser.set_defaults(function=list_files)
    list_files_parser.add_argument('--csv', dest='csv', action='store_true', default=False, help='Comma Separated Value output. This output format is preferred for easy parsing and scripting.')
    list_files_parser.add_argument('--pfc', dest='LOCALPATH', action='store', default=False, help='Outputs the list of files in the dataset with the LOCALPATH prepended as a PoolFileCatalog')
    list_files_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

    # The list_content command
    list_content_parser = subparsers.add_parser('list-content', help='List the content of a collection.')
    list_content_parser.set_defaults(function=list_content)
    list_content_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')
    list_content_parser.add_argument('--short', dest='short', action='store_true', help='Just dump the list of DIDs.')

    # The list_content_history command
    list_content_history_parser = subparsers.add_parser('list-content-history', help='List the content history of a collection.')
    list_content_history_parser.set_defaults(function=list_content_history)
    list_content_history_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')

# The upload subparser
    upload_parser = subparsers.add_parser('upload', help='Upload method.')
    upload_parser.set_defaults(function=upload)
    upload_parser.add_argument('--rse', dest='rse', action='store', help='Rucio Storage Element (RSE) name.', required=True).completer = rse_completer
    upload_parser.add_argument('--lifetime', type=int, action='store', help='Lifetime of the rule in seconds.')
    upload_parser.add_argument('--expiration-date', action='store', help='The date when the rule expires in UTC, format: <year>-<month>-<day>-<hour>:<minute>:<second>. E.g. 2022-10-20-20:00:00')
    upload_parser.add_argument('--scope', dest='scope', action='store', help='Scope name.')
    upload_parser.add_argument('--impl', dest='impl', action='store', help='Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone).')
    # The --no-register option is hidden. This is pilot ONLY. Users should not use this. Will lead to unregistered data on storage!
    upload_parser.add_argument('--no-register', dest='no_register', action='store_true', default=False, help=argparse.SUPPRESS)
    upload_parser.add_argument('--register-after-upload', dest='register_after_upload', action='store_true', default=False, help='Register the file only after successful upload.')
    upload_parser.add_argument('--summary', dest='summary', action='store_true', default=False, help='Create rucio_upload.json summary file')
    upload_parser.add_argument('--guid', dest='guid', action='store', help='Manually specify the GUID for the file.')
    upload_parser.add_argument('--protocol', action='store', help='Force the protocol to use')
    upload_parser.add_argument('--pfn', dest='pfn', action='store', help='Specify the exact PFN for the upload.')
    upload_parser.add_argument('--name', dest='name', action='store', help='Specify the exact LFN for the upload.')
    upload_parser.add_argument('--transfer-timeout', dest='transfer_timeout', type=float, action='store', default=config_get_float('upload', 'transfer_timeout', False, 360), help='Transfer timeout (in seconds).')
    upload_parser.add_argument(dest='args', action='store', nargs='+', help='files and datasets.')
    upload_parser.add_argument('--recursive', dest='recursive', action='store_true', default=False, help='Convert recursively the folder structure into collections')

    # The download and get subparser
    get_parser = subparsers.add_parser('get', help='Download method (synonym for download)')
    download_parser = subparsers.add_parser('download', help='Download method (synonym for get)')
    for selected_parser in [get_parser, download_parser]:
        selected_parser.set_defaults(function=download)
        selected_parser.add_argument('--dir', dest='dir', default='.', action='store', help='The directory to store the downloaded file.')
        selected_parser.add_argument(dest='dids', nargs='*', action='store', help='List of space separated data identifiers.')
        selected_parser.add_argument('--allow-tape', action='store_true', default=False, help="Also consider tape endpoints as source of the download.")
        selected_parser.add_argument('--rses', action='store', help='RSE Expression to specify allowed sources')
        selected_parser.add_argument('--impl', dest='impl', action='store', help='Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone).')
        selected_parser.add_argument('--protocol', action='store', help='Force the protocol to use.')
        selected_parser.add_argument('--nrandom', type=int, action='store', help='Download N random files from the DID.')
        selected_parser.add_argument('--ndownloader', type=int, default=3, action='store', help='Choose the number of parallel processes for download.')
        selected_parser.add_argument('--no-subdir', action='store_true', default=False, help="Don't create a subdirectory for the scope of the files.")
        selected_parser.add_argument('--pfn', dest='pfn', action='store', help="Specify the exact PFN for the download.")
        selected_parser.add_argument('--archive-did', action='store', dest='archive_did', help="Download from archive is transparent. This option is obsolete.")
        selected_parser.add_argument('--no-resolve-archives', action='store_true', default=False, help="If set archives will not be considered for download.")
        selected_parser.add_argument('--ignore-checksum', action='store_true', default=False, help="Don't validate checksum for downloaded files.")
        selected_parser.add_argument('--check-local-with-filesize-only', action='store_true', default=False, help="Don't use checksum verification for already downloaded files, use filesize instead.")
        selected_parser.add_argument('--transfer-timeout', dest='transfer_timeout', type=float, action='store', default=config_get_float('download', 'transfer_timeout', False, None), help='Transfer timeout (in seconds). Default: computed dynamically from --transfer-speed-timeout. If set to any value >= 0, --transfer-speed-timeout is ignored.')  # NOQA: E501
        selected_parser.add_argument('--transfer-speed-timeout', dest='transfer_speed_timeout', type=float, action='store', default=None, help='Minimum allowed average transfer speed (in KBps). Default: 500. Used to dynamically compute the timeout if --transfer-timeout not set. Is not supported for --pfn.')  # NOQA: E501
        selected_parser.add_argument('--aria', action='store_true', default=False, help="Use aria2c utility if possible. (EXPERIMENTAL)")
        selected_parser.add_argument('--trace_appid', '--trace-appid', new_option_string='--trace-appid', dest='trace_appid', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_APPID', None), help=argparse.SUPPRESS)
        selected_parser.add_argument('--trace_dataset', '--trace-dataset', new_option_string='--trace-dataset', dest='trace_dataset', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_DATASET', None), help=argparse.SUPPRESS)
        selected_parser.add_argument('--trace_datasetscope', '--trace-datasetscope', new_option_string='--trace-datasetscope', dest='trace_datasetscope', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_DATASETSCOPE', None), help=argparse.SUPPRESS)  # NOQA: E501
        selected_parser.add_argument('--trace_eventtype', '--trace-eventtype', new_option_string='--trace-eventtype', dest='trace_eventtype', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_EVENTTYPE', None), help=argparse.SUPPRESS)  # NOQA: E501
        selected_parser.add_argument('--trace_pq', '--trace-pq', new_option_string='--trace-pq', dest='trace_pq', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_PQ', None), help=argparse.SUPPRESS)
        selected_parser.add_argument('--trace_taskid', '--trace-taskid', new_option_string='--trace-taskid', dest='trace_taskid', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_TASKID', None), help=argparse.SUPPRESS)
        selected_parser.add_argument('--trace_usrdn', '--trace-usrdn', new_option_string='--trace-usrdn', dest='trace_usrdn', action=StoreAndDeprecateWarningAction, default=os.environ.get('RUCIO_TRACE_USRDN', None), help=argparse.SUPPRESS)
        selected_parser.add_argument('--filter', dest='filter', action='store', help='Filter files by key-value pairs like guid=2e2232aafac8324db452070304f8d745.')
        selected_parser.add_argument('--scope', dest='scope', action='store', help='Scope to use as a filter or to use with DID names.')
        selected_parser.add_argument('--metalink', dest='metalink_file', action='store', help='Path to a metalink file.')
        selected_parser.add_argument('--deactivate-file-download-exceptions', dest='deactivate_file_download_exceptions', action='store_true', help='Does not raise NoFilesDownloaded, NotAllFilesDownloaded or incorrect number of output queue files Exception.')  # NOQA: E501
        selected_parser.add_argument('--replica-selection', dest='sort', action='store', help='Select the best replica using a replica sorting algorithm provided by replica sorter (e.g., random, geoip).')

    # The get-metadata subparser
    get_metadata_parser = subparsers.add_parser('get-metadata', help='Get metadata for DIDs.')
    get_metadata_parser.set_defaults(function=get_metadata)
    get_metadata_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')
    get_metadata_parser.add_argument('--plugin', dest='plugin', action='store', help='Filter down to metadata from specific metadata plugin', required=False)

    # The set-metadata subparser
    set_metadata_parser = subparsers.add_parser('set-metadata', help='set-metadata method')
    set_metadata_parser.set_defaults(function=set_metadata)
    set_metadata_parser.add_argument('--did', dest='did', action='store', help='Data identifier whose metadata will be set', required=True)
    set_metadata_parser.add_argument('--key', dest='key', action='store', help='Attribute key', required=True)
    set_metadata_parser.add_argument('--value', dest='value', action='store', help='Attribute value', required=True)

    # delete-did-meta subparser
    delete_metadata_parser = subparsers.add_parser('delete-metadata', help='delete metadata')
    delete_metadata_parser.set_defaults(function=delete_metadata)
    delete_metadata_parser.add_argument('--did', dest='did', action='store', help='Data identifier to delete', required=True)
    delete_metadata_parser.add_argument('--key', dest='key', action='store', help='Attribute key', required=True)

    # The list-rse-usage subparser
    list_rse_usage_parser = subparsers.add_parser('list-rse-usage', help='Shows the total/free/used space for a given RSE. This values can differ for different RSE source.')
    list_rse_usage_parser.set_defaults(function=list_rse_usage)
    list_rse_usage_parser.add_argument(dest='rse', action='store', help='Rucio Storage Element (RSE) name.').completer = rse_completer
    list_rse_usage_parser.add_argument('--history', dest='history', default=False, action='store', help='List RSE usage history. [Unimplemented]')
    list_rse_usage_parser.add_argument('--show-accounts', dest='show_accounts', action='store_true', default=False, help='List accounts usages of RSE')

    # The list-account-usage subparser
    list_account_usage_parser = subparsers.add_parser('list-account-usage', help='Shows the space used, the quota limit and the quota left for an account for every RSE where the user have quota.')
    list_account_usage_parser.set_defaults(function=list_account_usage)
    list_account_usage_parser.add_argument(dest='usage_account', action='store', help='Account name.')
    list_account_usage_parser.add_argument('--rse', action='store', help='Show usage for only for this RSE.')

    # The list-account-limits subparser
    list_account_limits_parser = subparsers.add_parser('list-account-limits', help='List quota limits for an account in every RSEs.')
    list_account_limits_parser.set_defaults(function=list_account_limits)
    list_account_limits_parser.add_argument('limit_account', action='store', help='The account name.')
    list_account_limits_parser.add_argument('--rse', dest='rse', action='store', help='If this option is given, the results are restricted to only this RSE.').completer = rse_completer

    # Add replication rule subparser
    add_rule_parser = subparsers.add_parser('add-rule', help='Add replication rule.')
    add_rule_parser.set_defaults(function=add_rule)
    add_rule_parser.add_argument(dest='dids', action='store', nargs='+', help='DID(s) to apply the rule to')
    add_rule_parser.add_argument(dest='copies', action='store', type=int, help='Number of copies')
    add_rule_parser.add_argument(dest='rse_expression', action='store', help='RSE Expression')
    add_rule_parser.add_argument('--weight', dest='weight', action='store', help='RSE Weight')
    add_rule_parser.add_argument('--lifetime', dest='lifetime', action='store', type=int, help='Rule lifetime (in seconds)')
    add_rule_parser.add_argument('--grouping', dest='grouping', action='store', choices=['DATASET', 'ALL', 'NONE'], help='Rule grouping')
    add_rule_parser.add_argument('--locked', dest='locked', action='store_true', help='Rule locking')
    add_rule_parser.add_argument('--source-replica-expression', dest='source_replica_expression', action='store', help='RSE Expression for RSEs to be considered for source replicas')
    add_rule_parser.add_argument('--notify', dest='notify', action='store', help='Notification strategy : Y (Yes), N (No), C (Close)')
    add_rule_parser.add_argument('--activity', dest='activity', action='store', help='Activity to be used (e.g. User, Data Consolidation)')
    add_rule_parser.add_argument('--comment', dest='comment', action='store', help='Comment about the replication rule')
    add_rule_parser.add_argument('--ask-approval', dest='ask_approval', action='store_true', help='Ask for rule approval')
    add_rule_parser.add_argument('--asynchronous', dest='asynchronous', action='store_true', help='Create rule asynchronously')
    add_rule_parser.add_argument('--delay-injection', dest='delay_injection', action='store', type=int, help='Delay (in seconds) to wait before starting applying the rule. This option implies --asynchronous.')
    add_rule_parser.add_argument('--account', dest='rule_account', action='store', help='The account owning the rule')
    add_rule_parser.add_argument('--skip-duplicates', dest='ignore_duplicate', action='store_true', help='Skip duplicate rules')

    # Delete replication rule subparser
    delete_rule_parser = subparsers.add_parser('delete-rule', help='Delete replication rule.')
    delete_rule_parser.set_defaults(function=delete_rule)
    delete_rule_parser.add_argument(dest='rule_id', action='store', help='Rule id or DID. If DID, the RSE expression is mandatory.')
    delete_rule_parser.add_argument('--purge-replicas', dest='purge_replicas', action='store_true', help='Purge rule replicas')
    delete_rule_parser.add_argument('--all', dest='delete_all', action='store_true', default=False, help='Delete all the rules, even the ones that are not owned by the account')
    delete_rule_parser.add_argument('--rses', dest='rses', action='store', help='The RSE expression. Must be specified if a DID is provided.')
    delete_rule_parser.add_argument('--account', dest='rule_account', action='store', help='The account of the rule that must be deleted')

    # Info replication rule subparser
    info_rule_parser = subparsers.add_parser('rule-info', help='Retrieve information about a rule.')
    info_rule_parser.set_defaults(function=info_rule)
    info_rule_parser.add_argument(dest='rule_id', action='store', help='The rule ID')
    info_rule_parser.add_argument('--examine', dest='examine', action='store_true', help='Detailed analysis of transfer errors')

    # The list_rules command
    list_rules_parser = subparsers.add_parser('list-rules', help='List replication rules.', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""

You can list the rules for a particular DID::

    $ rucio list-rules user.jdoe:user.jdoe.test.container.1234.1
    ID                                ACCOUNT    SCOPE:NAME                                 STATE[OK/REPL/STUCK]    RSE_EXPRESSION        COPIES  EXPIRES (UTC)
    --------------------------------  ---------  -----------------------------------------  ----------------------  ------------------  --------  -------------------
    a12e5664555a4f12b3cc6991db5accf9  jdoe       user.jdoe:user.jdoe.test.container.1234.1  OK[3/0/0]               tier=1&disk=1       1         2018-02-09 03:57:46
    b0fcde2acbdb489b874c3c4537595adc  janedoe    user.jdoe:user.jdoe.test.container.1234.1  REPLICATING[4/1/1]      tier=1&tape=1       2
    4a6bd85c13384bd6836fbc06e8b316d7  mc         user.jdoe:user.jdoe.test.container.1234.1  OK[3/0/0]               tier=1&tape=1       2

You can filter by account::

    $ rucio list-rules --account jdoe
    ID                                ACCOUNT    SCOPE:NAME                                 STATE[OK/REPL/STUCK]    RSE_EXPRESSION        COPIES  EXPIRES (UTC)
    --------------------------------  ---------  -----------------------------------------  ----------------------  ------------------  --------  -------------------
    a12e5664555a4f12b3cc6991db5accf9  jdoe       user.jdoe:user.jdoe.test.container.1234.1  OK[3/0/0]               tier=1&disk=1       1         2018-02-09 03:57:46
    08537b2176843d92e05317938a89d148  jdoe       user.jdoe:user.jdoe.test.data.1234.1       OK[2/0/0]               SITE2_DISK          1

                                              ''')

    list_rules_parser.set_defaults(function=list_rules)
    list_rules_parser.add_argument(dest='did', action='store', nargs='?', default=None, help='List by did')
    list_rules_parser.add_argument('--id', dest='rule_id', action='store', help='List by rule id')
    list_rules_parser.add_argument('--traverse', dest='traverse', action='store_true', help='Traverse the did tree and search for rules affecting this did')
    list_rules_parser.add_argument('--csv', dest='csv', action='store_true', default=False, help='Comma Separated Value output')
    list_rules_parser.add_argument('--file', dest='file', action='store', help='List associated rules of an affected file')
    list_rules_parser.add_argument('--account', dest='rule_account', action='store', help='List by account')
    list_rules_parser.add_argument('--subscription', dest='subscription', action='store', help='List by subscription name')

    # The list_rules_history command
    list_rules_history_parser = subparsers.add_parser('list-rules-history', help='List replication rules history for a DID.')
    list_rules_history_parser.set_defaults(function=list_rules_history)
    list_rules_history_parser.add_argument(dest='did', action='store', help='The Data IDentifier.')

    # The update_rule command
    update_rule_parser = subparsers.add_parser('update-rule', help='Update replication rule.')
    update_rule_parser.set_defaults(function=update_rule)
    update_rule_parser.add_argument(dest='rule_id', action='store', help='Rule id')
    update_rule_parser.add_argument('--lifetime', dest='lifetime', action='store', help='Lifetime in seconds.')
    update_rule_parser.add_argument('--locked', dest='locked', action='store', help='Locked (True/False).')
    update_rule_parser.add_argument('--account', dest='rule_account', action='store', help='Account to change.')
    update_rule_parser.add_argument('--stuck', dest='state_stuck', action='store_true', help='Set state to STUCK.')
    update_rule_parser.add_argument('--suspend', dest='state_suspended', action='store_true', help='Set state to SUSPENDED.')
    update_rule_parser.add_argument('--activity', dest='rule_activity', action='store', help='Activity of the rule.')
    update_rule_parser.add_argument('--source-replica-expression', dest='source_replica_expression', action='store', help='Source replica expression of the rule.')
    update_rule_parser.add_argument('--comment', dest='comment', action='store', help="Update comment for the rule")
    update_rule_parser.add_argument('--cancel-requests', dest='cancel_requests', action='store_true', help='Cancel requests when setting rules to stuck.')
    update_rule_parser.add_argument('--priority', dest='priority', action='store', help='Priority of the requests of the rule.')
    update_rule_parser.add_argument('--child-rule-id', dest='child_rule_id', action='store', help='Child rule id of the rule. Use "None" to remove an existing parent/child relationship.')
    update_rule_parser.add_argument('--boost-rule', dest='boost_rule', action='store_true', help='Quickens the transition of a rule from STUCK to REPLICATING.')

    # The move_rule command
    move_rule_parser = subparsers.add_parser('move-rule', help='Move a replication rule to another RSE.')
    move_rule_parser.set_defaults(function=move_rule)
    move_rule_parser.add_argument(dest='rule_id', action='store', help='Rule id')
    move_rule_parser.add_argument(dest='rse_expression', action='store', help='RSE expression of new rule')
    move_rule_parser.add_argument('--activity', dest='activity', action='store', help='Update activity for moved rule.')
    move_rule_parser.add_argument('--source-replica-expression', dest='source_replica_expression', action='store', help='Update source-replica-expression for moved rule. Use "None" to remove the old value.')

    # The list-rses command
    list_rses_parser = subparsers.add_parser('list-rses', help='Show the list of all the registered Rucio Storage Elements (RSEs).')
    list_rses_parser.set_defaults(function=list_rses)
    list_rses_parser.add_argument('--rses', dest='rses', action='store', help='The RSE filter expression. A comprehensive help about RSE expressions \
can be found in ' + Color.BOLD + 'https://rucio.cern.ch/documentation/started/concepts/rse_expressions' + Color.END)
    list_rses_parser.add_argument("--csv", action='store_true', help='Output a list of RSEs as a csv')

    # The list-suspicious-replicas command
    list_suspicious_replicas_parser = subparsers.add_parser('list-suspicious-replicas', help='Show the list of all replicas marked "suspicious".')
    list_suspicious_replicas_parser.set_defaults(function=list_suspicious_replicas)
    list_suspicious_replicas_parser.add_argument('--expression', dest='rse_expression', action='store', help='The RSE filter expression. A comprehensive help about RSE expressions \
can be found in ' + Color.BOLD + 'https://rucio.cern.ch/documentation/started/concepts/rse_expressions' + Color.END)
    list_suspicious_replicas_parser.add_argument('--younger_than', '--younger-than', new_option_string='--younger-than', dest='younger_than', action=StoreAndDeprecateWarningAction, help='List files that have been marked suspicious since the date "younger_than", e.g. 2021-11-29T00:00:00.')  # NOQA: E501
    list_suspicious_replicas_parser.add_argument('--nattempts', dest='nattempts', action='store', help='Minimum number of failed attempts to access a suspicious file.')

    # The list-rses-attributes command
    list_rse_attributes_parser = subparsers.add_parser('list-rse-attributes', help='List the attributes of an RSE.', description='This command is useful to create RSE filter expressions.')
    list_rse_attributes_parser.set_defaults(function=list_rse_attributes)
    list_rse_attributes_parser.add_argument(dest='rse', action='store', help='The RSE name').completer = rse_completer

    # The list-datasets-rse command
    list_datasets_rse_parser = subparsers.add_parser('list-datasets-rse', help='List all the datasets at a RSE', description='This method allows to list all the datasets on a given Rucio Storage Element.\
        ' + Color.BOLD + 'Warning: ' + Color.END + 'This command can take a long time depending on the number of datasets in the RSE.')
    list_datasets_rse_parser.set_defaults(function=list_datasets_rse)
    list_datasets_rse_parser.add_argument(dest='rse', action='store', default=None, help='The RSE name').completer = rse_completer
    list_datasets_rse_parser.add_argument('--long', dest='long', action='store_true', default=False, help='The long option')

    # The test-server command
    test_server_parser = subparsers.add_parser('test-rucio-server', help='Test Server', description='Run a bunch of tests against the Rucio Servers.')
    test_server_parser.set_defaults(function=test_server)

    # The get-metadata subparser
    touch_parser = subparsers.add_parser('touch', help='Touch one or more DIDs and set the last accessed date to the current date')
    touch_parser.set_defaults(function=touch)
    touch_parser.add_argument(dest='dids', nargs='+', action='store', help='List of space separated data identifiers.')
    touch_parser.add_argument('--rse', dest='rse', action='store', help="The RSE of the DIDs that are touched.").completer = rse_completer

    # The add-lifetime-exception command
    add_lifetime_exception_parser = subparsers.add_parser('add-lifetime-exception', help='Add an exception to the lifetime model.',
                                                          formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Usage example
"""""""""""""
::

    $ rucio add-lifetime-exception --inputfile myfile.txt --reason "Needed for my analysis" --expiration 2015-10-30

    ''')

    add_lifetime_exception_parser.set_defaults(function=add_lifetime_exception)
    add_lifetime_exception_parser.add_argument('--inputfile', action='store', help='File where the list of datasets requested to be extended are located.', required=True)
    add_lifetime_exception_parser.add_argument('--reason', action='store', help='The reason for the extension.', required=True)
    add_lifetime_exception_parser.add_argument('--expiration', action='store', help='The expiration date format YYYY-MM-DD', required=True)

    return oparser


def main():

    pager = get_pager()
    console = Console(theme=Theme(CLITheme.LOG_THEMES), soft_wrap=True)
    console.width = max(MIN_CONSOLE_WIDTH, console.width)
    spinner = Status('Initializing spinner', spinner=CLITheme.SPINNER, spinner_style=CLITheme.SPINNER_STYLE, console=console)

    arguments = sys.argv[1:]
    # set the configuration before anything else, if the config parameter is present
    for argi in range(len(arguments)):
        if arguments[argi] == '--config' and (argi + 1) < len(arguments):
            os.environ['RUCIO_CONFIG'] = arguments[argi + 1]

    oparser = get_parser()
    if EXTRA_MODULES['argcomplete']:
        argcomplete.autocomplete(oparser)

    if len(sys.argv) == 1:
        oparser.print_help()
        sys.exit(FAILURE)

    args = oparser.parse_args(arguments)

    if cli_config == 'rich':
        install(console=console, word_wrap=True, width=min(console.width, MAX_TRACEBACK_WIDTH))  # Make rich exception tracebacks the default.
        logger = setup_rich_logger(module_name=__name__, logger_name='user', verbose=args.verbose, console=console)
    else:
        logger = setup_logger(module_name=__name__, logger_name='user', verbose=args.verbose)

    setup_gfal2_logger()
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, logger))

    start_time = time.time()
    client = get_client(args, logger)
    result = args.function(args, client, logger, console, spinner)
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
