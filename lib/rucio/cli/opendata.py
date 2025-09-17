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
from typing import TYPE_CHECKING, Optional

import click
from rich.text import Text
from tabulate import tabulate

from rucio.cli.utils import JSONType
from rucio.client.richclient import CLITheme, generate_table, get_cli_config, print_output
from rucio.common.constants import OPENDATA_DID_STATE_LITERAL_LIST
from rucio.common.utils import extract_scope

if TYPE_CHECKING:
    from click import Context

    from rucio.common.constants import OPENDATA_DID_STATE_LITERAL

cli_config = get_cli_config()


def is_valid_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except json.JSONDecodeError:
        return False


@click.group()
def opendata() -> None:
    """Manage Opendata resources"""


@opendata.group(name="did")
def opendata_did() -> None:
    """Manage Opendata DIDs"""


@opendata_did.command("list")
@click.option("--state", type=click.Choice(OPENDATA_DID_STATE_LITERAL_LIST, case_sensitive=False), required=False,
              help="Filter on Opendata state")
@click.option("--public", required=False, is_flag=True, default=False,
              help="Perform request against the public endpoint")
@click.option("--short", is_flag=True, default=False, help="Dump the list of Opendata DIDs")
@click.pass_context
def list_opendata_dids(ctx: "Context", state: Optional["OPENDATA_DID_STATE_LITERAL"], public: bool,
                       short: bool) -> None:
    """
    List Opendata DIDs, optionally filtered by state and public/private access
    """

    client = ctx.obj.client
    spinner = ctx.obj.spinner

    dids_list = client.list_opendata_dids(state=state, public=public)

    table_data = []

    if cli_config == 'rich':
        spinner.update(status='Fetching Opendata DIDs')
        spinner.start()

    for did in dids_list["dids"]:
        if cli_config == 'rich':
            table_data.append([f"{did['scope']}:{did['name']}",
                               Text(did['state'], style=CLITheme.OPENDATA_DID_STATE.get(did['state'], 'default'))])
        else:
            table_data.append([f"{did['scope']}:{did['name']}", did['state']])

    if short:
        for did, _ in table_data:
            print(did)
    else:
        if cli_config == 'rich':
            table = generate_table(table_data, headers=['SCOPE:NAME', '[STATE]'], col_alignments=['left', 'left'])
            spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate(table_data, tablefmt="psql", headers=['SCOPE:NAME', '[STATE]']))


@opendata_did.command("add")
@click.argument("did")
@click.pass_context
def add_opendata_did(ctx: "Context", did: str) -> None:
    """
    Adds an existing DID to the Opendata catalog
    """

    client = ctx.obj.client
    scope, name = extract_scope(did)
    client.add_opendata_did(scope=scope, name=name)


@opendata_did.command("remove")
@click.argument("did")
@click.pass_context
def remove_opendata_did(ctx: "Context", did: str) -> None:
    """
    Removes an existing Opendata DID from the Opendata catalog
    """

    client = ctx.obj.client
    scope, name = extract_scope(did)
    client.remove_opendata_did(scope=scope, name=name)


@opendata_did.command("show")
@click.argument("did")
@click.option("--meta", required=False, is_flag=True, default=False, help="Print only the opendata metadata")
@click.option("--files", required=False, is_flag=True, default=False,
              help="Print the files associated with the opendata DID")
@click.option("--public", required=False, is_flag=True, default=False,
              help="Perform request against the public endpoint")
@click.pass_context
def get_opendata_did(ctx: "Context", did: str, files: bool, meta: bool, public: bool) -> None:
    """
    Get information about an Opendata DID, optionally including files and metadata.
    """

    client = ctx.obj.client
    spinner = ctx.obj.spinner
    console = ctx.obj.console

    scope, name = extract_scope(did)
    info = client.get_opendata_did(scope=scope, name=name, public=public,
                                   include_files=files, include_metadata=meta,
                                   include_doi=True)

    output = []
    if cli_config == 'rich':
        spinner.update(status='Fetching Opendata DID stats')
        spinner.start()
        keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.OPENDATA_DID_STATE}

        table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for (k, v) in
                      sorted(info.items())]
        table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
        output.append(table)
    else:
        table = [(k + ':', str(v)) for (k, v) in sorted(info.items())]
        print(tabulate(table, tablefmt='plain', disable_numparse=True))

    if cli_config == 'rich':
        spinner.stop()
        print_output(*output, console=console, no_pager=ctx.obj.no_pager)


@opendata_did.command("update")
@click.argument("did")
@click.option("--meta", type=JSONType(), required=False, help="Opendata JSON")
@click.option("--state", type=click.Choice(OPENDATA_DID_STATE_LITERAL_LIST, case_sensitive=False), required=False,
              help="State of the Opendata DID")
@click.option("--doi", required=False,
              help="Digital Object Identifier (DOI) for the Opendata DID (e.g., 10.1234/foo.bar)")
@click.pass_context
def update_opendata_did(ctx: "Context", did: str, meta: Optional[str],
                        state: Optional["OPENDATA_DID_STATE_LITERAL"],
                        doi: Optional[str]) -> None:
    """
    Update an existing Opendata DID in the Opendata catalog.
    """

    client = ctx.obj.client
    if not any([meta, state, doi]):
        raise ValueError("At least one of --meta, --state, or --doi must be provided.")

    scope, name = extract_scope(did)
    client.update_opendata_did(scope=scope, name=name, meta=meta, state=state, doi=doi)
