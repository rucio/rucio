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
import datetime
import itertools
import math
import os
from typing import TYPE_CHECKING, Optional

import click
import tabulate
from rich.text import Text

from rucio.cli.utils import CommaSeparatedList, get_scope
from rucio.client.richclient import CLITheme, generate_table, print_output
from rucio.common.client import detect_client_location
from rucio.common.constants import ReplicaState
from rucio.common.exception import InputValidationError, InvalidObject
from rucio.common.utils import chunks, clean_pfns, sizefmt

if TYPE_CHECKING:
    from collections.abc import Sequence


@click.group()
def replica():
    """Manage replicas - DIDs with locations on RSEs"""


@replica.group("list")
def replica_list():
    """List replicas (file or collection-types)"""


@replica_list.command("file")
@click.argument("dids", nargs=-1)
@click.option("--protocols", help="Protocol used to access a replicas (i.e. https, root, srm)", type=CommaSeparatedList())
@click.option(
    "--all-states",
    help="To select all replicas (including unavailable ones).\
                Also gets information about the current state of a DID in each RSE",
    is_flag=True,
    default=False,
)
@click.option("--pfns", is_flag=True, help="Show only the PFNs", default=False)
@click.option("--domain", default=None, type=click.Choice(["wan", "lan", "all"]), help="Force the networking domain. If None, the server will choose based on the client's location.")
@click.option(
    "--link",
    help="Symlink PFNs with directory substitution.\
                For example: rucio list-file-replicas --rse RSE_TEST --link /eos/:/eos/ scope:datasetname",
)
@click.option("--missing", is_flag=True, default=False, help="To list missing replicas at a RSE-Expression. Must be used with --rses option")
@click.option("--metalink", is_flag=True, default=False, help="Output available replicas as metalink")
@click.option("--no-resolve-archives", is_flag=True, default=False, help="Do not resolve archives which may contain the files", required=False)
@click.option("--sort", help="Replica sort algorithm. Available options: geoip (default), random")
@click.option("--rses", "--rse-exp", "rses", help="The RSE filter expression")
@click.option("--human", default=True, hidden=True)
@click.pass_context
def list_(ctx, dids, protocols, all_states, pfns, domain, link, missing, metalink, no_resolve_archives, sort, rses, human):
    """List the replicas of a DID and its PFNs. By default, only available replicas are shown."""
    if missing:
        all_states = True
        ctx.obj.logger.debug("Specified missing - looking at all replica states.")

    table_data = []
    did_list = []
    if missing and not rses:
        raise InputValidationError('Cannot use --missing without specifying a RSE')
    if link and ':' not in link:
        raise ValueError('The substitution parameter must equal --link="/pfn/dir:/dst/dir"')

    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching file replicas')
        ctx.obj.spinner.start()

    for did in dids:
        scope, name = get_scope(did, ctx.obj.client)
        ctx.obj.client.get_metadata(scope=scope, name=name)  # Break with Exception before streaming replicas if DID does not exist.
        did_list.append({'scope': scope, 'name': name})

    replicas = ctx.obj.client.list_replicas(did_list, schemes=protocols,
                                    ignore_availability=True,
                                    all_states=all_states,
                                    rse_expression=rses,
                                    metalink=metalink,
                                    client_location=detect_client_location(),
                                    sort=sort, domain=domain,
                                    resolve_archives=not no_resolve_archives)
    rses = [rse["rse"] for rse in ctx.obj.client.list_rses(rse_expression=rses)]

    if metalink:
        print(replicas[:-1])  # Last character is newline, no need to print that.
        return

    if missing:
        for replica, rse in itertools.product(replicas, rses):
            if 'states' in replica and rse in replica['states'] and replica['states'].get(rse) != 'AVAILABLE':
                if ctx.obj.use_rich:
                    replica_state = f"[{CLITheme.REPLICA_STATE.get(ReplicaState[replica['states'].get(rse)].value, 'default')}]{ReplicaState[replica['states'].get(rse)].value}[/]"
                    table_data.append([replica['scope'], replica['name'], '({0}) {1}'.format(replica_state, rse)])
                else:
                    table_data.append([replica['scope'], replica['name'], "({0}) {1}".format(ReplicaState[replica['states'].get(rse)].value, rse)])
        if ctx.obj.use_rich:
            table = generate_table(table_data, headers=['SCOPE', 'NAME', '(STATE) RSE'], col_alignments=['left', 'left', 'left'])
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate.tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['SCOPE', 'NAME', '(STATE) RSE']))

    elif link:
        pfn_dir, dst_dir = link.split(':')
        if rses:
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
    elif pfns:
        if rses:
            for replica in replicas:
                for pfn in replica['pfns']:
                    rse = replica['pfns'][pfn]['rse']
                    if replica['rses'].get(rse):
                        if ctx.obj.use_rich:
                            table_data.append([pfn])
                        else:
                            print(pfn)
        else:  # TODO remove this extra branch
            for replica in replicas:
                for pfn in replica['pfns']:
                    rse = replica['pfns'][pfn]['rse']
                    if replica['rses'][rse]:
                        if ctx.obj.use_rich:
                            table_data.append([pfn])
                        else:
                            print(pfn)
        if ctx.obj.use_rich:
            table = generate_table(table_data, headers=['PFN'], col_alignments=['left'])
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        if all_states:
            header = ['SCOPE', 'NAME', 'FILESIZE', 'ADLER32', '(STATE) RSE: REPLICA']
        else:
            header = ['SCOPE', 'NAME', 'FILESIZE', 'ADLER32', 'RSE: REPLICA']
        for replica in replicas:
            if 'bytes' in replica:
                for pfn in replica['pfns']:
                    rse = replica['pfns'][pfn]['rse']
                    if all_states:
                        if ctx.obj.use_rich:
                            replica_state = f"[{CLITheme.REPLICA_STATE.get(ReplicaState[replica['states'][rse]].value, 'default')}]{ReplicaState[replica['states'][rse]].value}[/]"
                            # Less does not display hyperlinks well if the table is very wide.
                            if ctx.obj.no_pager:
                                rse_string = f'({replica_state}) {rse}: [u bright_blue link={pfn}]{pfn}[/]'
                            else:
                                rse_string = f'({replica_state}) {rse}: [u bright_blue]{pfn}[/]'
                        else:
                            rse_string = '({2}) {0}: {1}'.format(rse, pfn, ReplicaState[replica['states'][rse]].value)
                    else:
                        if ctx.obj.use_rich:
                            # Less does not display hyperlinks well if the table is very wide.
                            if ctx.obj.no_pager:
                                rse_string = f'{rse}: [u bright_blue link={pfn}]{pfn}[/]'
                            else:
                                rse_string = f'{rse}: [u bright_blue]{pfn}[/]'
                        else:
                            rse_string = '{0}: {1}'.format(rse, pfn)
                    if rses:
                        for selected_rse in rses:
                            if rse == selected_rse:
                                table_data.append([replica['scope'], replica['name'], sizefmt(replica['bytes'], human), replica['adler32'], rse_string])
                    else:
                        table_data.append([replica['scope'], replica['name'], sizefmt(replica['bytes'], human), replica['adler32'], rse_string])

        if ctx.obj.use_rich:
            table = generate_table(table_data, headers=header, col_alignments=['left', 'left', 'right', 'left', 'left'])
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate.tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=header, disable_numparse=True))


@replica_list.command("dataset")
@click.argument("dids", nargs=-1)
@click.option("--rse", default=None, help="RSE name to use a filter")
@click.option("--deep", default=False, is_flag=True, help="Make a deep check, checking the contents of datasets in datasets")
@click.option("--csv", help="Write output to comma separated values", is_flag=True, default=False)
@click.option("--long", is_flag=True, default=False, help="Display extra details")
@click.pass_context
def list_dataset(ctx, dids: Sequence[str], rse: Optional[str], deep: bool, csv: bool, long: bool):  # TODO Correct typing
    """List dataset replicas, or view all datasets at a RSE"""
    if rse is None:
        result = {}
        datasets = []

        def _append_to_datasets(scope, name):
            filedid = {'scope': scope, 'name': name}
            if filedid not in datasets:
                datasets.append(filedid)

        def _fetch_datasets_for_meta(meta):
            """Internal function to fetch datasets and recurse into files."""
            if meta['did_type'] != 'DATASET':
                dids = ctx.obj.client.scope_list(scope=meta['scope'], name=meta['name'], recursive=True)
                for did in dids:
                    if did['type'] == 'FILE':
                        _append_to_datasets(did['parent']['scope'], did['parent']['name'])
            else:
                _append_to_datasets(meta['scope'], meta['name'])

        def _append_result(dsn, replica):
            if dsn not in result:
                result[dsn] = {}
            result[dsn][replica['rse']] = [replica['rse'], replica['available_length'], replica['length']]

        if ctx.obj.use_rich:
            ctx.obj.spinner.update(status='Fetching dataset replicas')
            ctx.obj.spinner.start()

        if len(dids) == 1:
            scope, name = get_scope(dids[0], ctx.obj.client)
            dmeta = ctx.obj.client.get_metadata(scope, name)
            _fetch_datasets_for_meta(meta=dmeta)
        else:
            extractdids = (get_scope(did, ctx.obj.client) for did in dids)
            splitdids = [{'scope': scope, 'name': name} for scope, name in extractdids]
            for dmeta in ctx.obj.client.get_metadata_bulk(dids=splitdids):
                _fetch_datasets_for_meta(meta=dmeta)

        if deep or len(datasets) < 2:
            for did in datasets:
                dsn = f"{did['scope']}:{did['name']}"
                for rep in ctx.obj.client.list_dataset_replicas(scope=did['scope'], name=did['name'], deep=deep):
                    _append_result(dsn=dsn, replica=rep)
        else:
            for rep in ctx.obj.client.list_dataset_replicas_bulk(dids=datasets):
                dsn = f"{rep['scope']}:{rep['name']}"
                _append_result(dsn=dsn, replica=rep)

        if csv:
            for dsn in result:
                for rse in list(result[dsn].values()):
                    print(rse[0], rse[1], rse[2], sep=',')  # TODO change name to avoid typing overshadow

            if ctx.obj.use_rich:
                ctx.obj.spinner.stop()
        else:
            output = []
            for i, dsn in enumerate(result):
                if ctx.obj.use_rich:
                    if i > 0:
                        output.append(Text(f'\nDATASET: {dsn}', style=CLITheme.TEXT_HIGHLIGHT))
                    elif len(result) > 1:
                        output.append(Text(f'DATASET: {dsn}', style=CLITheme.TEXT_HIGHLIGHT))

                    table = generate_table(list(result[dsn].values()), headers=['RSE', 'FOUND', 'TOTAL'], col_alignments=['left', 'right', 'right'])
                    output.append(table)
                else:
                    print(f'\nDATASET: {dsn}')
                    print(tabulate.tabulate(list(result[dsn].values()), tablefmt=ctx.obj.tablefmt, headers=['RSE', 'FOUND', 'TOTAL']))

            if ctx.obj.use_rich:
                ctx.obj.spinner.stop()
                print_output(*output, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        if ctx.obj.use_rich:
            ctx.obj.spinner.update(status='Fetching datasets at RSE')
            ctx.obj.spinner.start()

        if long:  # TODO make consistent with the other branch - give that a long option too.
            table_data = []
            for dsn in ctx.obj.client.list_datasets_per_rse(rse):
                table_data.append([f"{dsn['scope']}:{dsn['name']}"
                                f"{str(dsn['available_length'])}/{str(dsn['length'])}",
                                f"{str(dsn['available_bytes'])}/{str(dsn['bytes'])}"])

            if ctx.obj.use_rich:
                table_data.sort()
                table = generate_table(table_data, headers=['SCOPE:NAME', 'LOCAL FILES/TOTAL FILES', 'LOCAL BYTES/TOTAL BYTES'], col_alignments=['left', 'right', 'right'])
                ctx.obj.spinner.stop()
                print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
            else:
                print(tabulate.tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['DID', 'LOCAL FILES/TOTAL FILES', 'LOCAL BYTES/TOTAL BYTES']))
        else:
            dsns = list(set([f"{dsn['scope']}:{dsn['name']}" for dsn in ctx.obj.client.list_datasets_per_rse(rse)]))
            dsns.sort()
            if ctx.obj.use_rich:
                table = generate_table([[dsn] for dsn in dsns], headers=['SCOPE:NAME'])
                ctx.obj.spinner.stop()
                print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
            else:
                print("SCOPE:NAME")
                print('----------')
                for dsn in dsns:
                    print(dsn)


@replica.command("remove")
@click.argument("dids", nargs=-1)
@click.option("--rse", "--rse-name", "rse", required=True)
@click.pass_context
def remove(ctx, dids, rse):
    "Set a replica for removal by adding a tombstone which will mark the replica as ready for deletion by a reaper daemon"
    # TODO: Fix set_tombstone to not expect a comma separated DID str
    dids = ",".join(dids)
    dids = [dids] if ',' not in dids else dids.split(',')
    replicas = []
    for did in dids:
        scope, name = get_scope(did, ctx.obj.client)
        replicas.append({'scope': scope, 'name': name, 'rse': rse})
    ctx.obj.client.set_tombstone(replicas)
    msg = f'Set tombstone successfully on: {dids}'
    ctx.obj.logger.info(msg)


@replica.group()
@click.help_option("-h", "--help")
def state():
    """Manage the state of replicas"""


@state.command("list")
@click.argument("state-type", type=click.Choice(["suspicious"]))
@click.option("--rses", "--rse-exp", help="RSE name or expression")  # TODO remap rse_expression to rses (for consistency)
@click.option("--younger-than", help='List files that have been marked suspicious since the date "younger_than", e.g. 2021-11-29T00:00:00')  # NOQA: E501
@click.option("--n-attempts", help="Minimum number of failed attempts to access a suspicious file")
@click.pass_context
def state_list(ctx, state_type, rses, younger_than, n_attempts):
    """List replicas by state. WARNING: Only implemented for 'suspicious'"""

    if state_type != "suspicious":
        msg = f"Cannot list state by {state_type}, please choose from ('suspicious')"
        raise ValueError(msg)

    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching suspicious replicas')
        ctx.obj.spinner.start()

    # Generator is a list with one entry, which itself is a list of lists.
    replicas_gen = ctx.obj.client.list_suspicious_replicas(rses, younger_than, n_attempts)
    for i in replicas_gen:
        replicas = i
    table = []
    table_data = []
    for rep in replicas:
        table_data.append([rep['rse'], rep['scope'], rep['created_at'], rep['cnt'], rep['name']])

    if ctx.obj.use_rich:
        table = generate_table(table_data, headers=['RSE EXPRESSION', 'SCOPE', 'CREATED AT', 'N-ATTEMPTS', 'FILE NAME'], col_alignments=['left', 'left', 'left', 'right', 'left'])
        ctx.obj.spinner.stop()
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        print(tabulate.tabulate(table_data, headers=(['RSE Expression:', 'Scope:', 'Created at:', 'Nattempts:', 'File Name:'])))


@state.group("update")
@click.help_option("-h", "--help")
def state_update():
    "Change the state of replicas"


def __declare_bad_file_replicas_by_lfns(scope, rse, reason, lfns, client, logger) -> object:
    """
    Declare a list of bad replicas using RSE name, scope and list of LFNs.
    """
    if not scope or not rse:
        raise InputValidationError("--lfn requires using --rse and --scope")
    replicas = []

    # send requests in chunks
    chunk_size = 10000

    def do_declare(client, lst, reason):
        non_declared = client.declare_bad_file_replicas(lst, reason)
        for rse, undeclared in non_declared.items():
            for r in undeclared:
                msg = f'{rse} : replica cannot be declared: {r}'
                logger.warning(msg)

    for line in open(lfns, "r"):
        lfn = line.strip()
        if lfn:
            replicas.append({"scope": scope, "rse": rse, "name": lfn})
            if len(replicas) >= chunk_size:
                do_declare(client, replicas, reason)
                replicas = []
    if replicas:
        do_declare(client, replicas, reason)


@state_update.command("bad")
@click.argument("replicas", nargs=-1)
@click.option("--reason", required=True, help="Reason")
@click.option("--as-file", is_flag=True, default=False, help="[REPLICAS] arg is a path to a file of replicas to update")
@click.option("--collection", is_flag=True, default=False, help="Items in the collection DID are also marked as bad")
@click.option("--lfn", is_flag=True, default=False, help="[REPLICAS] arg is a path to a file of LFNs. Requires --rse and --scope")
@click.option("--scope", help="Common scope for bad replicas specified with LFN list, ignored without --lfn")
@click.option("--rse", "--rse-name", help="Common RSE for bad replicas specified with LFN list, ignored without --lfn")
@click.pass_context
def update_bad(ctx, replicas, reason, as_file, collection, lfn, scope, rse):
    """Mark a replica bad"""
    if as_file:
        if len(replicas) != 1:
            raise ValueError("Exactly one positional argument expected in case as-file")

    elif lfn:
        if (scope is None) or (rse is None):
            raise ValueError("Scope and RSE are required when using LFNs")
        if len(replicas) != 1:
            raise ValueError("Exactly one positional argument expected in case of LFN list")

    if lfn:
        return __declare_bad_file_replicas_by_lfns(scope, rse, reason, replicas[0], ctx.obj.client, ctx.obj.logger)

    if as_file:
        with open(replicas[0]) as infile:
            bad_files = list(filter(None, [line.strip() for line in infile]))
    else:
        bad_files = replicas

    # Interpret filenames not in scheme://* format as LFNs and convert them to PFNs
    bad_files_pfns = []
    for bad_file in bad_files:
        if bad_file.find('://') == -1:
            scope, name = get_scope(bad_file, ctx.obj.client)
            did_info = ctx.obj.client.get_did(scope, name)
            if did_info['type'].upper() != 'FILE' and not collection:
                msg = f'DID {scope}:{name} is a collection and --allow-collection was not specified.'
                raise InputValidationError(msg)
            replicas = [replica for rep in ctx.obj.client.list_replicas([{'scope': scope, 'name': name}])
                        for replica in list(rep['pfns'].keys())]
            bad_files_pfns.extend(replicas)
        else:
            bad_files_pfns.append(bad_file)
    if ctx.obj.verbose:
        print("PFNs that will be declared bad:")
        for pfn in bad_files_pfns:
            print(pfn)

    if len(bad_files_pfns) < 100:
        # Using the old API to declare
        non_declared = ctx.obj.client.declare_bad_file_replicas(bad_files_pfns, reason)
        for rse in non_declared:
            for pfn in non_declared[rse]:
                msg = f'{rse} : PFN {pfn} cannot be declared.'
                ctx.obj.logger.warning(msg)
    else:
        ctx.obj.logger.debug('Getting the information about RSE protocols. It can take several seconds')
        dict_rse = ctx.obj.client.export_data(distance=False)
        prot_dict = {}
        for rse, dict_attr in dict_rse['rses'].items():
            protocols = dict_attr['protocols']
            for prot in protocols:
                prot_dict[f'{prot["scheme"]}://{prot["hostname"]}{prot["prefix"]}'] = rse
                prot_dict[f'{prot["scheme"]}://{prot["hostname"]}:{prot["port"]}{prot["prefix"]}'] = rse
        ctx.obj.logger.debug('Protocol information retrieved')

        chunk_size = 10000
        msg = f'Starting the declaration by chunks of {chunk_size}'
        ctx.obj.logger.debug(msg)

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
                    msg = f'Cannot find any RSE associated to {pfn}'
                    ctx.obj.logger.warning(msg)
            ctx.obj.client.add_bad_pfns(pfns=list_bad_pfns, reason=reason, state='BAD', expires_at=None)
            ndeclared = len(list_bad_pfns)
            tot_file_declared += ndeclared
            print(f'Chunk {int(cnt)}/{int(nchunk)} : {ndeclared} replicas successfully declared')
        print(f'Summary: {tot_file_declared}/{tot_files} replicas successfully declared')


@state_update.command("unavailable")
@click.argument("replicas", nargs=-1)
@click.option("--reason", required=True, help="Reason")
@click.option("--as-file", is_flag=True, default=False, help="[REPLICAS] arg is a path to a file of names to update")
@click.option("--duration", required=True, type=int, help="Timeout (in seconds) after which the replicas will become available again")
@click.pass_context
def update_unavailable(ctx, replicas, reason, as_file, duration):
    """Declare a replica unavailable"""
    bad_files = []
    if as_file:
        with open(replicas[0]) as infile:
            for line in infile:
                bad_file = line.rstrip('\n')
                if '://' not in bad_file:
                    msg = f'{bad_file} is not a valid PFN. Aborting'
                    raise InvalidObject(msg)
                if bad_file != '':
                    bad_files.append(bad_file)
    else:
        bad_files = replicas

    expiration_date = (datetime.datetime.utcnow() + datetime.timedelta(seconds=duration)).isoformat()

    chunk_size = 10000
    tot_files = len(bad_files)
    cnt = 0
    nchunk = math.ceil(tot_files / chunk_size)
    for chunk in chunks(bad_files, chunk_size):
        cnt += 1
        ctx.obj.client.add_bad_pfns(pfns=chunk, reason=reason, state='TEMPORARY_UNAVAILABLE', expires_at=expiration_date)
        ndeclared = len(chunk)
        print(f'Chunk {int(cnt)}/{int(nchunk)} : {ndeclared} replicas successfully declared')
    print(f'Summary: {tot_files} replicas successfully declared' % tot_files)


@state_update.command("quarantine")
@click.argument("replicas", nargs=-1)
@click.option("--as-file", is_flag=True, default=False, help="[REPLICAS] arg is a path to a file of names to update")
@click.option("--rse", "--rse-name", help="Name of RSE")
@click.pass_context
def update_quarantine(ctx, replicas, as_file, rse):
    """Quarantine a replica"""

    chunk = []

    # send requests in chunks
    chunk_size = 1000

    if as_file:
        replicas_list = open(replicas[0], "r")     # will iterate over file lines
    else:
        replicas_list = replicas

    for line in replicas_list:
        path = line.strip()
        if path:                                        # skip blank lines
            chunk.append(dict(path=path))
            if len(chunk) >= chunk_size:
                ctx.obj.client.quarantine_replicas(chunk, rse=rse)
                chunk = []
    if chunk:
        ctx.obj.client.quarantine_replicas(chunk, rse=rse)
