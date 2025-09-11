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
def list_(ctx: click.Context, section: str, key: str):
    """List the sections or content of sections in the rucio.cfg"""
    get_config(Arguments({"no_pager": ctx.obj.no_pager, "section": section, "key": key}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@config.command("add")
@click.option("-s", "--section", help="Section name", required=True)
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def add_(ctx: click.Context, section: str, key: str, value: str):
    """
    Add a new key/value to a section.

    \b
    Example, Add a key to an existing section:
        $ rucio config add --section my-section --key key --value value
    """
    has_option = ctx.obj.client.get_config().get(section, {}).get(key) is not None
    if has_option:
        msg = f"Config already has field {section}: {key}, please use \n\
            rucio config update --section {section} --key {key} --value {value}"
        raise ValueError(msg)

    args = Arguments({"no_pager": ctx.obj.no_pager, "section": section, "option": key, "value": value})
    set_config_option(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@config.command("remove")
@click.option("-s", "--section", help="Section", required=True)
@click.option("-k", "--key", help="Key in section", required=True)
@click.pass_context
def remove(ctx: click.Context, section: str, key: str):
    """Remove the section.key from the config."""
    args = Arguments({"no_pager": ctx.obj.no_pager, "section": section, "option": key})
    delete_config_option(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


# @config.command("show")
# @click.pass_context
def show(ctx):
    """Show a single sections options"""


@config.command("update")
@click.option("-s", "--section", required=True)
@click.option("-k", "--key", help='Attribute key', required=True)
@click.option("-v", "--value", help='Attribute value', required=True)
@click.pass_context
def update(ctx: click.Context, section: str, key: str, value: str):
    """Modify an existing command"""
    has_option = ctx.obj.client.get_config().get(section, {}).get(key) is not None
    if has_option:
        ctx.obj.client.set_config_option(section, key, value)
    else:
        msg = f"{section} {key} not present. Please use \n\
            rucio config add --section {section} --key {key} --value {value}"
        raise ValueError(msg)
