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
import click

from rucio.client.commands.bin_legacy.rucio import list_dataset_replicas, list_file_replicas, list_suspicious_replicas
from rucio.client.commands.bin_legacy.rucio_admin import declare_bad_file_replicas, declare_temporary_unavailable_replicas, quarantine_replicas, set_tombstone
from rucio.client.commands.utils import Arguments, click_decorator


@click.group()
@click.help_option("-h", "--help")
def replica():
    """Manage replicas - DIDs with locations on RSEs"""


@replica.group("list")
@click.help_option("-h", "--help")
def replica_list():
    """List replicas (file or collection-types)"""


@replica_list.command("file")
@click.argument("dids", nargs=-1)
@click.option("--protocols", help="Protocol used to access a replicas (i.e. https, root, srm)")
@click.option(
    "--all-states/--not-all-states",
    help="To select all replicas (including unavailable ones).\
                Also gets information about the current state of a DID in each RSE",
    default=False,
)
@click.option("--pfns/--no-pfns", help="Show only the PFNs", default=False)
@click.option("--domain", default="all", type=click.Choice(["wan", "lan", "all"]), help="Force the networking domain")
@click.option(
    "--link",
    help="Symlink PFNs with directory substitution.\
                For example: rucio list-file-replicas --rse RSE_TEST --link /eos/:/eos/ scope:datasetname",
)
@click.option("--missing/--no-missing", default=False, help="To list missing replicas at a RSE-Expression. Must be used with --rses option")
@click.option("--metalink/--no-metalink", default=False, help="Output available replicas as metalink")
@click.option("--no-resolve-archives/--resolve-archives", default=False, help="Do not resolve archives which may contain the files", required=False)
@click.option("--sort", help="Replica sort algorithm. Available options: geoip (default), random")
@click.option("--rses", "--rse-exp", "rses", help="The RSE filter expression")
@click.option("--human", default=True, hidden=True)
@click_decorator
def list_(ctx, dids, protocols, all_states, pfns, domain, link, missing, metalink, no_resolve_archives, sort, rses, human):
    """List the replicas of a DID and its PFNs. By default all states, even unavailable, are shown"""
    args = {"dids": dids, "protocols": protocols, "all_states": all_states, "pfns": pfns, "domain": domain, "link": link, "missing": missing, "metalink": metalink, "no_resolve_archives": no_resolve_archives, "sort": sort, "rses": rses, "human": human}
    list_file_replicas(Arguments(args), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@replica_list.command("dataset")
@click.argument("dids", nargs=-1)
@click.option("--deep/--no-deep", default=False, help="Make a deep check, checking the contents of datasets in datasets")
@click.option("--csv/--no-csv", help="Write output to comma separated values", default=False)
@click_decorator
def list_dataset(ctx, dids, deep, csv):
    """List dataset replicas"""
    args = Arguments({"dids": dids, "deep": deep, "csv": csv})
    list_dataset_replicas(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@replica.command("remove")
@click.argument("dids", nargs=-1)
@click.option("--rse", "--rse-name", "rse", required=True)
@click_decorator
def remove(ctx, dids, rse):
    "Set a replica for removal by adding a tombstone which will mark the replica as ready for deletion by a reaper daemon"
    # TODO: Fix set_tombstone to not expect a comma separated DID str
    dids = ",".join(dids)
    set_tombstone(Arguments({"dids": dids, "rse": rse}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@replica.group()
@click.help_option("-h", "--help")
def state():
    """Manage the state of replicas"""


@state.command("list")
@click.argument("state-type", type=click.Choice(["suspicious"]))
@click.option("--rses", "--rse-exp", help="RSE name or expression")  # TODO remap rse_expression to rses (for consistency)
@click.option("--younger-than", help='List files that have been marked suspicious since the date "younger_than", e.g. 2021-11-29T00:00:00')  # NOQA: E501
@click.option("--n-attempts", help="Minimum number of failed attempts to access a suspicious file")
@click_decorator
def state_list(ctx, state_type, rses, younger_than, n_attempts):
    """List replicas by state. WARNING: Only implemented for 'suspicious'"""

    if state_type != "suspicious":
        raise ValueError(f"Cannot list state by {state_type}, please choose from ('suspicious')")
    list_suspicious_replicas(Arguments({"rse_expression": rses, "younger_than": younger_than, "nattempts": n_attempts}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@state.group("update")
@click.help_option("-h", "--help")
def state_update():
    "Change the state of replicas"


@state_update.command("bad")
@click.argument("replicas", nargs=-1)
@click.option("--reason", required=True, help="Reason")
@click.option("--as-file/--not-as-file", default=False, help="[REPLICAS] arg is a path to a file of replicas to update")
@click.option("--collection/--no-collection", default=False, help="Items in the collection DID are also marked as bad")
@click.option("--lfn/--no-lfn", default=False, help="[REPLICAS] arg is a path to a file of LFNs. Requires --rse and --scope")
@click.option("--scope", help="Common scope for bad replicas specified with LFN list, ignored without --lfn")
@click.option("--rse", "--rse-name", help="Common RSE for bad replicas specified with LFN list, ignored without --lfn")
@click_decorator
def update_bad(ctx, replicas, reason, as_file, collection, lfn, scope, rse):
    """Mark a replica bad"""
    args = {"reason": reason, "allow_collection": collection, "scope": scope, "rse": rse}
    if as_file:
        args["inputfile"] = replicas
    elif lfn:
        if (scope is None) or (rse is None):
            raise ValueError("Scope and RSE are required when using LFNs")
        args["lfns"] = replicas
    else:
        args["listbadfiles"] = replicas
    declare_bad_file_replicas(Arguments(args), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@state_update.command("unavailable")
@click.argument("replicas", nargs=-1)
@click.option("--reason", required=True, help="Reason")
@click.option("--as-file/--not-as-file", default=False, help="[REPLICAS] arg is a path to a file of names to update")
@click.option("--duration", required=True, type=int, help="Timeout (in seconds) after which the replicas will become available again")
@click_decorator
def update_unavailable(ctx, replicas, reason, as_file, duration):
    """Declare a replica unavailable"""
    args = {"reason": reason, "duration": duration}
    if as_file:
        args["inputfile"] = replicas
    else:
        args["listbadfiles"] = replicas
    declare_temporary_unavailable_replicas(Arguments(args), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@state_update.command("quarantine")
@click.argument("replicas", nargs=-1)
@click.option("--as-file/--not-as-file", default=False, help="[REPLICAS] arg is a path to a file of names to update")
@click.option("--rse", "--rse-name")  # TODO What does this do?
@click_decorator
def update_quarantine(ctx, replicas, as_file, rse):
    """Quarantine a replica"""
    args = {"rse": rse}
    if as_file:
        args["paths_file"] = replicas
    else:
        args["paths_list"] = replicas

    # TODO Add a reason option
    quarantine_replicas(Arguments(args), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
