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

from rucio.client.commands.bin_legacy.rucio import add_container, add_dataset, attach, close, delete_metadata, detach, erase, get_metadata, list_content, list_content_history, list_dids, list_parent_dids, reopen, set_metadata, stat, touch
from rucio.client.commands.utils import Arguments, click_decorator


@click.group()
@click.help_option("-h", "--help")
def did():
    """Manage Data Identifiers - the source data objects"""


@did.command("list")
@click.option("-r", "--recursive/--no-recursive", default=False, help="List data identifiers recursively.")
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
@click.option("--short/--no-short", default=False, help="Dump the list of DIDs")
@click.argument("did-pattern", nargs=-1)
@click_decorator
def list_(ctx, did_pattern, recursive, filter_, short):
    """
    List the Data IDentifiers matching certain pattern.
    Only the collections (i.e. dataset or container) are returned by default.
    With the filter option, you can specify a list of metadata that the Data IDentifier should match
    """
    args = Arguments({"did": did_pattern, "recursive": recursive, "filter": filter_, "short": short})
    list_dids(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@did.command("show")
@click.argument("dids", nargs=-1)
@click.option("--parent/--no-parent", help="List the parents of the DID")
@click.option("--pfn", hidden=True)
@click.option("--guid", hidden=True)
@click_decorator
def show(ctx, dids, parent, pfn, guid):
    """List attributes, statuses, or parents for data identifiers"""
    if parent:
        for did in dids:
            list_parent_dids(Arguments({"did": did}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
    else:
        stat(Arguments({"dids": dids}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@did.command("add")
@click.argument("did-name")
@click.option("--type", "dtype", type=click.Choice(["container", "dataset"]))
@click.option("--monotonic/--no-monotonic", default=False, help="Monotonic status to True.")
@click.option("--lifetime", type=int, help="Lifetime in seconds.")
@click_decorator
def add_(ctx, did_name, dtype, monotonic, lifetime):
    """Create a new collection-type DID"""
    args = Arguments({"did": did_name, "monotonic": monotonic, "lifetime": lifetime})
    if dtype == "container":
        add_container(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
    else:
        add_dataset(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@did.command("update")
@click.argument("dids", nargs=-1)
@click.option("--rse", "--rse-name", help="The RSE of the DIDs")
@click.option("--touch", "operation", flag_value="touch", default=True, help="Touch one or more DIDs and set the last accessed date to the current date")
@click.option("--open", "operation", flag_value="open", help="Reopen a dataset or container (only for privileged users)")
@click.option("--close", "operation", flag_value="close", help="Close a dataset or container.")
@click_decorator
def update(ctx, dids, rse, operation):
    """Touch one or more DIDs and set the last accessed date to the current date, or mark them as open or closed."""
    args = Arguments({"dids": dids, "rse": rse})
    if operation == "touch":
        touch(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
    elif operation == "open":
        reopen(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
    elif operation == "close":
        close(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
    else:
        raise ValueError("No operation specified, please use `--help` to see possibilities")  # Should not be possible, but better safe than sorry


@did.command("remove")
@click.option("--undo", is_flag=True, default=False, help="Undo erase DIDs. Only works if has been less than 24 hours since erase operation.")
@click.argument("dids", nargs=-1)
@click_decorator
def remove(ctx, dids, undo):
    """
    This command sets the lifetime of the DID in order to expire in the next 24 hours.
    After this time, the dataset is eligible for deletion.
    The deletion is not reversible after 24 hours grace time period expired
    """
    erase(Arguments({"dids": dids, "undo": undo}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@did.group()
@click.help_option("-h", "--help")
def content():
    """Manage contents of collection type DIDs"""


@content.command("history")
@click.argument("dids", nargs=-1)
@click_decorator
def content_history(ctx, dids):
    """List the content history of a collection-type DID"""
    list_content_history(Arguments({"dids": dids}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@content.command("add")
@click.option("-to", "--to-did", required=True, help="Collection-type DID to which attach [DIDs]")
@click.option("-f", "--from-file", is_flag=True, default=False, help="[DIDs] is a file instead of a list of did names. The file should contain one did per line.")
@click.argument("dids", nargs=-1)
@click_decorator
def content_add_(ctx, to_did, from_file, dids):
    """Attach a list [dids] of Data IDentifiers (file or collection-type) to an other Data IDentifier (collection-type)"""
    args = Arguments({"dids": dids, "todid": to_did, "fromfile": from_file})
    attach(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@content.command("remove")
@click.option("-f", "--from-did", help="Collection-type DID to remove DIDs from")
@click.argument("dids", nargs=-1)
@click_decorator
def content_remove(ctx, dids, from_did):
    """Detach [dids], a list of DIDs (file or collection-type) from an other Data Identifier (collection type)"""
    args = Arguments({"dids": dids, "fromdid": from_did})
    detach(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@content.command("list")
@click.argument("dids", nargs=-1)
@click.option("--short", is_flag=True, default=False, help="Just dump the list of DIDs.")
@click_decorator
def content_list_(ctx, dids, short):
    """List the content of a collection-type DID"""
    args = Arguments({"dids": dids, "short": short})
    list_content(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@did.group()
@click.help_option("-h", "--help")
def metadata():
    """Manage metadata for DIDs"""


@metadata.command("add")
@click.argument("did")
@click.option("-o", "--option", type=(str, str), help="Key/Value pair to add to the DID.")
@click_decorator
def meta_add_(ctx, did, option):
    """Add metadata to a DID"""
    args = Arguments({"did": did, "key": option[0], "value": option[1]})
    set_metadata(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@metadata.command("remove")
@click.argument("did")
@click.option("--key", help="Key to remove from a DID's metadata.")
@click_decorator
def meta_remove(ctx, did, key):
    """Remove metadata from a DID"""
    args = Arguments({"did": did, "key": key})
    delete_metadata(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@metadata.command("list")
@click.argument("dids", nargs=-1)
@click.option("--plugin", help="Filter down to metadata from specific metadata plugin")
@click_decorator
def meta_list_(ctx, dids, plugin):
    """List metadata for a list of DIDs"""
    args = Arguments({"dids": dids, "plugin": plugin})
    get_metadata(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
