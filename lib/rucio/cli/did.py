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
import math
from typing import Literal, Optional, Union

import click
from rich.text import Text
from tabulate import tabulate

from rucio.cli.utils import get_scope
from rucio.client.richclient import CLITheme, generate_table, print_output
from rucio.common.config import config_get
from rucio.common.exception import InputValidationError, InvalidObject, RucioException, ScopeNotFound
from rucio.common.utils import chunks, parse_did_filter_from_string_fe


@click.group()
def did() -> None:
    """Manage Data Identifiers - the source data objects"""


@did.command("list")
@click.option("-r", "--recursive", default=False, is_flag=True, help="List data identifiers recursively.")
@click.option(
    "--filter", "filter_",
    help="""
    Single or logically combined filtering expression(s) either in the form <key><operator><value>
    or <value1><operator1><key><operator2><value2> (compound inequality).
    Keys are equivalent to columns in the DID table.
    Operators must belong to the set of (<=, >=, ==, !=, >, <). The following conventions for combining expressions
    are used: ";" represents the logical OR operator; "," represents the logical AND operator',
    """,
)  # TODO Shorten this help and make supplying this easier
@click.option("--short", is_flag=True, default=False, help="Just dump the list of DIDs.")
@click.argument("did-pattern", nargs=1, required=True)
@click.option("--parent", default=False, is_flag=True, help="List the parents of the DID - must use a full DID scope and name")
@click.pass_context
def list_(ctx: click.Context, did_pattern: str, recursive: bool, filter_: str, short: bool, parent: bool) -> None:
    """
    List the Data IDentifiers matching certain pattern.
    Only the collections (i.e. dataset or container) are returned by default.
    With the filter option, you can specify a list of metadata that the Data IDentifier should match
    """
    if parent:
        if ctx.obj.use_rich:
            ctx.obj.spinner.update(status='Fetching parent DIDs')
            ctx.obj.spinner.start()

        table_data = []
        scope, name = get_scope(did_pattern, ctx.obj.client)
        for dataset in ctx.obj.client.list_parent_dids(scope=scope, name=name):
            if ctx.obj.use_rich:
                table_data.append([f"{dataset['scope']}:{dataset['name']}", Text(dataset['type'], style=CLITheme.DID_TYPE.get(dataset['type'], 'default'))])
            else:
                table_data.append([f"{dataset['scope']}:{dataset['name']}", dataset['type']])

        if ctx.obj.use_rich:
            table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))

    else:
        table_data = []

        try:
            scope, name = get_scope(did_pattern, ctx.obj.client)
            if name == '':
                name = '*'
        except InvalidObject:
            scope = did_pattern
            name = '*'

        if scope not in ctx.obj.client.list_scopes():
            raise ScopeNotFound

        if recursive and '*' in name:
            raise InputValidationError('Option recursive cannot be used with wildcards.')
        else:
            if filter_:
                if ('name' in filter_) and (name != '*'):
                    raise ValueError('Must have a wildcard in did name if filtering by name.')

        filters, type_ = parse_did_filter_from_string_fe(filter_, name)

        if ctx.obj.use_rich:
            ctx.obj.spinner.update(status='Fetching DIDs')
            ctx.obj.spinner.start()

        for did in ctx.obj.client.list_dids(scope, filters=filters, did_type=type_, long=True, recursive=recursive):
            if ctx.obj.use_rich:
                table_data.append([f"{did['scope']}:{did['name']}", Text(did['did_type'], style=CLITheme.DID_TYPE.get(did['did_type'], 'default'))])
            else:
                table_data.append([f"{did['scope']}:{did['name']}", did['did_type']])

        if short:
            for did, _ in table_data:
                print(did)
        else:
            if ctx.obj.use_rich:
                table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
                ctx.obj.spinner.stop()
                print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
            else:
                print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))


@did.command("show")
@click.argument("dids", nargs=-1)
@click.pass_context
def show(ctx: click.Context, dids: tuple[str, ...]) -> None:
    """List attributes, statuses, or parents for data identifiers"""
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching DID stats')
        ctx.obj.spinner.start()
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE}

    output = []
    for i, did in enumerate(dids):
        scope, name = get_scope(did, ctx.obj.client)
        info = ctx.obj.client.get_did(scope=scope, name=name, dynamic_depth='DATASET')
        if ctx.obj.use_rich:
            if i > 0:
                output.append(Text(f'\nDID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            elif len(dids) > 1:
                output.append(Text(f'DID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for (k, v) in sorted(info.items())]
            table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
            output.append(table)
        else:
            if i > 0:
                print('------')
            table = [(k + ':', str(v)) for (k, v) in sorted(info.items())]
            print(tabulate(table, tablefmt='plain', disable_numparse=True))

    if ctx.obj.use_rich:
        ctx.obj.spinner.stop()
        print_output(*output, console=ctx.obj.console, no_pager=ctx.obj.no_pager)


@did.command("add")
@click.argument("did-name")
@click.option("--type", "dtype", type=click.Choice(["container", "dataset"]))
@click.option("--monotonic", is_flag=True, default=False, help="Monotonic status to True.")
@click.option("--lifetime", type=int, help="Lifetime in seconds.")
@click.pass_context
def add_(ctx: click.Context, did_name: str, dtype: Literal['container', 'dataset'], monotonic: bool, lifetime: Optional[int]) -> None:
    """Create a new collection-type DID"""
    scope, name = get_scope(did_name, ctx.obj.client)
    if dtype == "container":
        ctx.obj.client.add_container(scope=scope, name=name, statuses={'monotonic': monotonic}, lifetime=lifetime)
    else:
        ctx.obj.client.add_dataset(scope=scope, name=name, statuses={'monotonic': monotonic}, lifetime=lifetime)
    print(f'Added {scope}:{name}')


@did.command("update")
@click.argument("dids", nargs=-1)
@click.option("--rse", "--rse-name", help="The RSE of the DIDs")
@click.option("--touch", "operation", flag_value="touch", default=True, help="Touch one or more DIDs and set the last accessed date to the current date")
@click.option("--open", "operation", flag_value="open", help="Reopen a dataset or container (only for privileged users)")
@click.option("--close", "operation", flag_value="close", help="Close a dataset or container.")
@click.pass_context
def update(ctx: click.Context, dids: tuple[str, ...], rse: Optional[str], operation: Literal['touch', 'open', 'close']) -> None:
    """Touch one or more DIDs and set the last accessed date to the current date, or mark them as open or closed."""

    if operation == "touch":
        for did in dids:
            # TODO check that RSE is present
            scope, name = get_scope(did, ctx.obj.client)
            ctx.obj.client.touch(scope, name, rse)
    elif operation == "open":
        for did in dids:
            scope, name = get_scope(did, ctx.obj.client)
            ctx.obj.client.set_status(scope=scope, name=name, open=True)
            print(f'{scope}:{name} has been reopened.')
    elif operation == "close":
        for did in dids:
            scope, name = get_scope(did, ctx.obj.client)
            ctx.obj.client.set_status(scope=scope, name=name, open=False)
            print(f'{scope}:{name} has been closed.')
    else:
        raise ValueError("No operation specified, please use `--help` to see possibilities")  # Should not be possible, but better safe than sorry


@did.command("remove")
@click.option("--undo", is_flag=True, default=False, help="Undo erase DIDs. Only works if has been less than 24 hours since erase operation.")
@click.argument("dids", nargs=-1)
@click.pass_context
def remove(ctx: click.Context, dids: tuple[str, ...], undo: bool) -> None:
    """
    This command sets the lifetime of the DID in order to expire in the next 24 hours.
    Expired DIDs are force-deleted (and their replicas purged).
    The deletion is not reversible after 24 hours grace time period expired
    """
    for did in dids:
        if '*' in did:
            ctx.obj.logger.warning("This command doesn't support wildcards! Skipping DID: %s" % did)
            continue
        try:
            scope, name = get_scope(did, ctx.obj.client)
        except RucioException as error:
            ctx.obj.logger.warning('DID is in wrong format: %s' % did)
            ctx.obj.logger.debug('Error: %s' % error)
            continue

        if undo:
            try:
                ctx.obj.client.set_metadata(scope=scope, name=name, key='lifetime', value=None)
                ctx.obj.logger.info('Erase undo for DID: {0}:{1}'.format(scope, name))
            except Exception:
                ctx.obj.logger.warning('Cannot undo erase operation on DID. DID not existent or grace period of 24 hours already expired.')
                ctx.obj.logger.warning('    DID: {0}:{1}'.format(scope, name))
        else:
            try:
                # set lifetime to expire in 24 hours (value is in seconds).
                ctx.obj.client.set_metadata(scope=scope, name=name, key='lifetime', value=86400)
                ctx.obj.logger.info('CAUTION! erase operation is irreversible after 24 hours. To cancel this operation you can run the following command:')
                print("rucio erase --undo {0}:{1}".format(scope, name))  # TODO: replace with f-strings
            except RucioException as error:
                ctx.obj.logger.warning('Failed to erase DID: %s' % did)
                ctx.obj.logger.debug('Error: %s' % error)


@did.group()
def content() -> None:
    """Manage contents of collection type DIDs"""


@content.command("history")
@click.argument("dids", nargs=-1, required=True)
@click.pass_context
def content_history(ctx: click.Context, dids: tuple[str, ...]) -> None:
    """List the content history of a collection-type DID"""
    table_data = []
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching content history')
        ctx.obj.spinner.start()

    for did in dids:
        scope, name = get_scope(did, ctx.obj.client)
        for content in ctx.obj.client.list_content_history(scope=scope, name=name):
            if ctx.obj.use_rich:
                table_data.append([f"{content['scope']}:{content['name']}", Text(content['type'].upper(), style=CLITheme.DID_TYPE.get(content['type'].upper(), 'default'))])
            else:
                table_data.append([f"{content['scope']}:{content['name']}", content['type'].upper()])

    if ctx.obj.use_rich:
        table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
        ctx.obj.spinner.stop()
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))


@content.command("add")
@click.option("-to", "--to-did", required=True, help="Collection-type DID to which attach [DIDs]")
@click.option("-f", "--from-file", is_flag=True, default=False, help="[DIDs] is a file instead of a list of did names. The file should contain one did per line.")
@click.argument("dids", nargs=-1)
@click.pass_context
def content_add_(ctx: click.Context, to_did: str, from_file: bool, dids: tuple[str, ...]) -> None:
    """Attach a list [dids] of data identifiers (file or collection-type) to another data identifier (collection-type)"""
    scope, name = get_scope(to_did, ctx.obj.client)
    limit = 499

    if from_file:
        if len(dids) != 1:
            raise ValueError('If --from-file option is active, only one file is supported. The file should contain a list of dids, one per line.')
        try:
            f = open(dids[0], 'r')
            dids_list = [did.rstrip() for did in f.readlines()]
        except OSError as error:
            ctx.obj.logger.error("Can't open file '" + dids[0] + "'.")
            raise OSError from error
    else:
        dids_list = list(dids)

    did_objs = [{'scope': get_scope(did, ctx.obj.client)[0], 'name': get_scope(did, ctx.obj.client)[1]} for did in dids_list]
    if len(did_objs) <= limit:
        ctx.obj.client.attach_dids(scope=scope, name=name, dids=did_objs)
    else:
        ctx.obj.logger.warning("You are trying to attach too much DIDs. Therefore they will be chunked and attached in multiple commands.")
        missing_dids = []
        for i, chunk in enumerate(chunks(did_objs, limit)):
            ctx.obj.logger.info("Try to attach chunk {0}/{1}".format(i, int(math.ceil(float(len(did_objs)) / float(limit)))))
            try:
                ctx.obj.client.attach_dids(scope=scope, name=name, dids=chunk)
            except Exception:
                content = [{'scope': did['scope'], 'name': did['name']} for did in ctx.obj. client.list_content(scope=scope, name=name)]
                missing_dids += [did for did in chunk if did not in content]

        if missing_dids:
            for chunk in chunks(missing_dids, limit):
                ctx.obj.client.attach_dids(scope=scope, name=name, dids=chunk)

    print(f'DIDs successfully attached to {scope}:{name}')


@content.command("remove")
@click.option("-f", "--from-did", help="Collection-type DID to remove DIDs from", required=True)
@click.argument("dids", nargs=-1)
@click.pass_context
def content_remove(ctx: click.Context, dids: tuple[str, ...], from_did: str) -> None:
    """Detach [dids], a list of DIDs (file or collection-type) from another Data Identifier (collection type)"""
    scope, name = get_scope(from_did, ctx.obj.client)
    did_objs = []
    for did in dids:
        cscope, cname = get_scope(did, ctx.obj.client)
        did_objs.append({'scope': cscope, 'name': cname})
    ctx.obj.client.detach_dids(scope=scope, name=name, dids=did_objs)
    print(f'DIDs successfully detached from {scope}:{name}')


@content.command("list")
@click.argument("dids", nargs=-1, required=True)
@click.option("--short", is_flag=True, default=False, help="Just dump the list of DIDs.")
@click.pass_context
def content_list_(ctx: click.Context, dids: list[str], short: bool) -> None:
    """List the content of a collection-type DID"""
    table_data = []
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching dataset contents')
        ctx.obj.spinner.start()

    for did in dids:
        scope, name = get_scope(did, ctx.obj.client)
        for content in ctx.obj.client.list_content(scope=scope, name=name):
            if ctx.obj.use_rich:
                table_data.append([f"{content['scope']}:{content['name']}", Text(content['type'].upper(), style=CLITheme.DID_TYPE.get(content['type'].upper(), 'default'))])
            else:
                table_data.append([f"{content['scope']}:{content['name']}", content['type'].upper()])

    if short:
        for did, _ in table_data:
            print(did)
    else:
        if ctx.obj.use_rich:
            table = generate_table(table_data, headers=['SCOPE:NAME', '[DID TYPE]'], col_alignments=['left', 'left'])
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['SCOPE:NAME', '[DID TYPE]']))


@did.group()
def metadata() -> None:
    """Manage metadata for DIDs"""


@metadata.command("add")
@click.argument("did")
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def metadata_add_(ctx: click.Context, did: str, key: str, value: Union[str, float]) -> None:
    """Add metadata to a DID"""
    if key == 'lifetime':
        value = None if value.lower() == 'none' else float(value)  # type: ignore
    scope, name = get_scope(did, ctx.obj.client)
    ctx.obj.client.set_metadata(scope=scope, name=name, key=key, value=value)


@metadata.command("remove")
@click.argument("did")
@click.option("--key", help="Key to remove from a DID's metadata.", required=True)
@click.pass_context
def metadata_remove(ctx: click.Context, did: str, key: str) -> None:
    """Remove metadata from a DID"""
    scope, name = get_scope(did, ctx.obj.client)
    ctx.obj.client.delete_metadata(scope=scope, name=name, key=key)


@metadata.command("list")
@click.argument("dids", nargs=-1)
@click.option("--plugin", help="Filter down to metadata from specific metadata plugin")
@click.pass_context
def metadata_list_(ctx: click.Context, dids: tuple[str, ...], plugin: Optional[str]) -> None:
    """List metadata for a list of DIDs"""
    if plugin is None:
        plugin = config_get('client', 'metadata_default_plugin', default='DID_COLUMN')

    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching metadata')
        ctx.obj.spinner.start()
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE, **CLITheme.AVAILABILITY}

    output = []
    for i, did in enumerate(dids):
        scope, name = get_scope(did, ctx.obj.client)
        meta = ctx.obj.client.get_metadata(scope=scope, name=name, plugin=plugin)
        if ctx.obj.use_rich:
            if i > 0:
                output.append(Text(f'\nDID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            elif len(dids) > 1:
                output.append(Text(f'DID: {did}', style=CLITheme.TEXT_HIGHLIGHT))
            table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for (k, v) in sorted(meta.items())]
            table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
            output.append(table)
        else:
            if i > 0:
                print('------')
            table = [(k + ':', str(v)) for (k, v) in sorted(meta.items())]
            print(tabulate(table, tablefmt='plain', disable_numparse=True))

    if ctx.obj.use_rich:
        ctx.obj.spinner.stop()
        print_output(*output, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
