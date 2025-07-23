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

from rucio.cli.utils import JSONType
from rucio.common.constants import OPENDATA_DID_STATE_LITERAL_LIST
from rucio.common.utils import extract_scope

if TYPE_CHECKING:
    from click import Context

    from rucio.common.constants import OPENDATA_DID_STATE_LITERAL


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
@click.pass_context
def list_opendata_dids(ctx: "Context", state: Optional["OPENDATA_DID_STATE_LITERAL"], public: bool) -> None:
    """
    List Opendata DIDs, optionally filtered by state and public/private access
    """

    client = ctx.obj.client
    result = client.list_opendata_dids(state=state, public=public)
    print(json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False))


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
def get_opendata_did(ctx: "Context", did: str, include_files: bool, include_metadata: bool, public: bool) -> None:
    """
    Get information about an Opendata DID, optionally including files and metadata.
    """

    client = ctx.obj.client
    scope, name = extract_scope(did)
    result = client.get_opendata_did(scope=scope, name=name, public=public,
                                     include_files=include_files, include_metadata=include_metadata,
                                     include_doi=True)
    # TODO: pretty print using tables, etc
    print(json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False))


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
