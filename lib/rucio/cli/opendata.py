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

from rucio.common.exception import RucioException

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from click import Context


def extract_scope_name(did: str) -> tuple[str, str]:
    # TODO: move this somewhere else

    parts = did.split(':')
    if len(parts) != 2:
        msg = f"Cannot extract scope and name from DID {did}. The DID should have exactly one colon but found {len(parts)} colons."
        raise RucioException(msg)
    scope, name = parts
    if not scope or not name:
        msg = f"Cannot extract scope and name from DID {did}. Found empty scope or name."
        raise RucioException(msg)
    return scope, name


def is_valid_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except json.JSONDecodeError:
        return False


@click.group()
def opendata() -> None:
    """Manage Open Data DIDs"""


@opendata.command("list")
# TODO instead of state, maybe use a flag for each valid state?
@click.option("--state", required=False, help="Filter on opendata state")
@click.option("--public", required=False, is_flag=True, default=False,
              help="Perform request against the public endpoint")
@click.pass_context
def list_opendata_dids(ctx: "Context", state: str, public: bool) -> None:
    # TODO: check state is valid
    client = ctx.obj.client
    print(f"DEBUG: Listing Open Data DIDs with state '{state}' and public flag '{public}'")
    result = client.list_opendata_dids(state=state, public=public)
    for i, entry in enumerate(result):
        print(f"OpenData entry {i}: {entry}")
        print(entry)


@opendata.command("add")
@click.argument("did")
@click.pass_context
def add_opendata_did(ctx: "Context", did: str) -> None:
    client = ctx.obj.client
    print(f"DEBUG: Adding Open Data DID with '{did}'")
    scope, name = extract_scope_name(did)
    client.add_opendata_did(scope=scope, name=name)


@opendata.command("remove")
@click.argument("did")
@click.pass_context
def remove_opendata_did(ctx: "Context", did: str) -> None:
    client = ctx.obj.client
    print(f"DEBUG: Removing Open Data DID with '{did}'")
    scope, name = extract_scope_name(did)
    client.remove_opendata_did(scope=scope, name=name)


@opendata.command("show")
@click.argument("did")
@click.option("--json", "json_flag", required=False, is_flag=True, default=False, help="Print only the metadata JSON")
@click.option("--public", required=False, is_flag=True, default=False,
              help="Perform request against the public endpoint")
@click.pass_context
def get_opendata_did(ctx: "Context", did: str, json_flag: bool, public: bool) -> None:
    client = ctx.obj.client
    scope, name = extract_scope_name(did)
    result = client.get_opendata_did(scope=scope, name=name, public=public)

    if json_flag:
        result = result["opendata_json"]

    # TODO: pretty print using tables, etc
    print(json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False))


@opendata.command("update")
@click.argument("did")
@click.option("--json", "opendata_json", required=False, help="OpenData JSON")
# TODO: once the list of states is defined, restrict choices to those states
@click.option("--state", required=False, help="State")
@click.pass_context
def update_opendata_did(ctx: "Context", did: str, opendata_json: str, state: str) -> None:
    client = ctx.obj.client
    if not opendata_json and not state:
        raise ValueError("At least one of --json or --state must be provided.")

    scope, name = extract_scope_name(did)

    if opendata_json is not None:
        if not is_valid_json(opendata_json):
            raise ValueError("Invalid JSON provided.")

        opendata_json = json.loads(opendata_json)

    client.update_opendata_did(scope=scope, name=name, opendata_json=opendata_json, state=state)
