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

from rucio.client.commands.bin_legacy.rucio_admin import delete_config_option, get_config, set_config_option
from rucio.client.commands.utils import Arguments, click_decorator


def abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


@click.group(help="Modify the rucio.cfg")
@click.help_option("-h", "--help")
def config():
    pass


# TODO Limit to just the section names
@config.command("list")
@click.option("-s", "--section", help="Filter by sections")
@click.option("-k", "--key", help="Show key's value, section required.")
@click_decorator
def list_(ctx, section, key):
    # """List all sections"""
    get_config(Arguments({"section": section, "key": key}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# TODO Change to only add new fields and cannot modify an existing field
# TODO Swap so that it can be accessed via [-s section] --key value
@config.command("add")
@click.option("-s", "--section", help="Section name", required=True)
@click.option("-o", "--option", type=(str, str))
@click_decorator
def add_(ctx, section, option):
    """
    Add a new key/value to a section.

    |b
    Example, Add a key to an existing section:
        $ rucio config add --section my-section -o key value
    """
    args = Arguments({"section": section, "key": option[0], "value": option[1]})
    set_config_option(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@config.command("remove")
@click.option("-s", "--section", help="Section", required=True)
@click.option("-k", "--key", help="Key in section", required=True)
@click.confirmation_option(prompt="Are you sure you want to delete this value?")
@click_decorator
def remove(ctx, section, key):
    """Remove the section.key from the config."""
    args = Arguments({"section": section, "key": key})
    delete_config_option(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# @config.command("show")
# @click_decorator
def show(ctx):
    """Show a single sections options"""


# TODO Change this so that it only modifies existing fields
def update():
    """Modify an existing command"""
    pass
