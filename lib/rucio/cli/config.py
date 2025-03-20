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

from rucio.cli.bin_legacy.rucio_admin import delete_config_option, get_config, set_config_option
from rucio.cli.utils import Arguments


@click.group()
def config():
    "Modify the configuration table"


# TODO Limit to just the section names
@config.command("list")
@click.option("-s", "--section", help="Filter by sections")
@click.option("-k", "--key", help="Show key's value, section required.")
@click.pass_context
def list_(ctx, section, key):
    """List the sections or content of sections in the rucio.cfg"""
    get_config(Arguments({"section": section, "key": key}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# TODO Change to only add new fields and cannot modify an existing field
@config.command("add")
@click.option("-s", "--section", help="Section name", required=True)
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def add_(ctx, section, key, value):
    """
    Add a new key/value to a section.

    \b
    Example, Add a key to an existing section:
        $ rucio config add --section my-section --key key --value value
    """
    args = Arguments({"section": section, "option": key, "value": value})
    set_config_option(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@config.command("remove")
@click.option("-s", "--section", help="Section", required=True)
@click.option("-k", "--key", help="Key in section", required=True)
@click.pass_context
def remove(ctx, section, key):
    """Remove the section.key from the config."""
    args = Arguments({"section": section, "option": key})
    delete_config_option(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# @config.command("show")
# @click.pass_context
def show(ctx):
    """Show a single sections options"""


# TODO Change this so that it only modifies existing fields
def update():
    """Modify an existing command"""
    pass
