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
import json

from rucio.common.exception import RucioException


def extract_scope_name(did: str):
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


def minify_json(data):
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


@click.group()
def opendata():
    """Manage Open Data DIDs"""


@opendata.command("list")
@click.pass_context
def list_opendata_dids(ctx):
    client = ctx.obj.client
    print("DEBUG: Listing Open Data DIDs")
    client.list_opendata_dids()


@opendata.command("add")
@click.argument("did-name")
@click.pass_context
def add_opendata_did(ctx, did_name):
    client = ctx.obj.client
    print(f"DEBUG: Adding Open Data DID with '{did_name}'")
    scope, name = extract_scope_name(did_name)
    client.add_opendata_did(scope=scope, name=name)


@opendata.command("remove")
@click.argument("did-name")
@click.pass_context
def remove_opendata_did(ctx, did_name):
    client = ctx.obj.client
    print(f"DEBUG: Removing Open Data DID with '{did_name}'")
    scope, name = extract_scope_name(did_name)
    client.remove_opendata_did(scope=scope, name=name)


# Add --json option to get only the metadata
@opendata.command("show")
@click.argument("did-name")
@click.option("--json", required=False, is_flag=True, default=False, help="Print only the metadata JSON")
@click.pass_context
def get_opendata_did(ctx, did_name: str, json: bool):
    client = ctx.obj.client
    print(f"DEBUG: Getting Open Data DID with '{did_name}'")
    scope, name = extract_scope_name(did_name)
    result = client.get_opendata_did(scope=scope, name=name)
    # TODO: switch on json flag
    if json:
        ...  # print only the metadata JSON
    print(result)


@opendata.command("update")
@click.argument("did-name")
# How to change the name of this `--json` to (metadata_json) while keeping the flag as `--json`?
# TODO: change name to avoid shadowing the json module
@click.option("--json", required=False, help="Metadata JSON")
# TODO: once the list of states is defined, restrict choices to those states
@click.option("--state", required=False, help="State")
@click.pass_context
def update_opendata_did(ctx, did_name: str, json: str, state: str):
    client = ctx.obj.client
    print(f"DEBUG: Updating Open Data DID with '{did_name}', metadata: {json}, state: {state}")
    if not json and not state:
        raise ValueError("At least one of --json or --state must be provided.")

    scope, name = extract_scope_name(did_name)

    if state:
        raise NotImplementedError("State update is not implemented yet.")

    if json:
        if not is_valid_json(json):
            raise ValueError("Invalid JSON provided.")

        json = minify_json(json)

        client.update_opendata_did(scope=scope, name=name, metadata_json=json)
