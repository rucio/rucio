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
    client.add_opendata_did(did_name, scope=scope, name=name)


@opendata.command("remove")
@click.argument("did-name")
@click.pass_context
def remove_opendata_did(ctx, did_name):
    client = ctx.obj.client
    print(f"DEBUG: Removing Open Data DID with '{did_name}'")
    scope, name = extract_scope_name(did_name)
    client.remove_opendata_did(did_name, scope=scope, name=name)


@opendata.command("show")
@click.argument("did-name")
@click.pass_context
def get_opendata_did(ctx, did_name):
    client = ctx.obj.client
    print(f"DEBUG: Getting Open Data DID with '{did_name}'")
    scope, name = extract_scope_name(did_name)
    client.get_opendata_did(did_name, scope=scope, name=name)


@opendata.command("update")
@click.argument("did-name")
@click.argument("metadata-json")
@click.pass_context
def update_opendata_did(ctx, did_name, metadata_json):
    client = ctx.obj.client
    print(f"DEBUG: Updating Open Data DID with '{did_name}'")
    scope, name = extract_scope_name(did_name)
    client.update_opendata_did(did_name, scope=scope, name=name, metadata_json=metadata_json)
