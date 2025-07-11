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
from rucio.common.utils import extract_scope

if TYPE_CHECKING:
    from click import Context


def is_valid_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except json.JSONDecodeError:
        return False


# TODO: import this from somewhere else
valid_opendata_states = ['draft', 'public', 'suspended']


@click.group()
def opendata() -> None:
    """Manage Open Data DIDs"""


@opendata.command("list")
# TODO instead of state, maybe use a flag for each valid state?
@click.option("--state", type=click.Choice(valid_opendata_states, case_sensitive=False), required=False,
              help="Filter on opendata state")
@click.option("--public", required=False, is_flag=True, default=False,
              help="Perform request against the public endpoint")
@click.pass_context
def list_opendata_dids(ctx: "Context", state: str, public: bool) -> None:
    client = ctx.obj.client
    result = client.list_opendata_dids(state=state, public=public)
    print(json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False))


@opendata.command("add")
@click.argument("did")
@click.pass_context
def add_opendata_did(ctx: "Context", did: str) -> None:
    client = ctx.obj.client
    scope, name = extract_scope(did)
    client.add_opendata_did(scope=scope, name=name)


@opendata.command("remove")
@click.argument("did")
@click.pass_context
def remove_opendata_did(ctx: "Context", did: str) -> None:
    client = ctx.obj.client
    scope, name = extract_scope(did)
    client.remove_opendata_did(scope=scope, name=name)


@opendata.command("show")
@click.argument("did")
@click.option("--meta", required=False, is_flag=True, default=False, help="Print only the opendata metadata")
@click.option("--files", required=False, is_flag=True, default=False,
              help="Print the files associated with the opendata DID")
@click.option("--public", required=False, is_flag=True, default=False,
              help="Perform request against the public endpoint")
@click.pass_context
def get_opendata_did(ctx: "Context", did: str, files: bool, meta: bool, public: bool) -> None:
    client = ctx.obj.client
    scope, name = extract_scope(did)
    result = client.get_opendata_did(scope=scope, name=name, public=public, files=files, meta=meta, doi=True)
    # TODO: pretty print using tables, etc
    print(json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False))


@opendata.command("update")
@click.argument("did")
@click.option("--meta", type=JSONType(), required=False, help="OpenData JSON")
# TODO: do not hardcode the list of valid states but import them
@click.option("--state", type=click.Choice(valid_opendata_states, case_sensitive=False), required=False, help="State")
@click.option("--doi", required=False, help="DOI")
@click.pass_context
def update_opendata_did(ctx: "Context", did: str, meta: Optional[str], state: Optional[str],
                        doi: Optional[str]) -> None:
    client = ctx.obj.client
    if not any([meta, state, doi]):
        raise click.UsageError("At least one of --meta, --state, or --doi must be provided.")

    scope, name = extract_scope(did)
    client.update_opendata_did(scope=scope, name=name, meta=meta, state=state, doi=doi)
