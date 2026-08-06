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
from typing import Optional

import click
from rich.text import Text
from rich.tree import Tree
from tabulate import tabulate

from rucio.cli.utils import RichUtils


@click.group()
def config():
    "Modify the configuration table"


# TODO Limit to just the section names
@config.command("list")
@click.option("-s", "--section", help="Filter by sections")
@click.option("-k", "--key", help="Show key's value, section required.")
@click.pass_context
def list_(ctx: click.Context, section: Optional[str], key: Optional[str]):
    """List the sections or content of sections in the rucio.cfg"""
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching Config')
        ctx.obj.spinner.start()

    result = ctx.obj.client.get_config(section=section, option=key)
    if not isinstance(result, dict):
        print(f'[{section}]\n{key}={result}')

    else:
        if ctx.obj.use_rich:
            table_data = []
            if section is None:
                for result_section, option in result.items():
                    tree = Tree(str(result_section))
                    for k, v in option.items():
                        branch = tree.add(k)
                        if isinstance(v, int):
                            v = str(v)
                        branch.add(Text(v))
                    table_data.append(tree)
            else:
                tree = Tree(str(section))
                for option, value in result.items():
                    branch = tree.add(option)
                    if isinstance(value, int):
                        value = str(value)
                    branch.add(Text(value))
                table_data.append(tree)

        else:
            table_data = []
            if section is None:
                headers = ["SECTION", "OPTION", "KEY"]
                for result_section, option in result.items():
                    for i, (k, v) in enumerate(option.items()):
                        if i == 0:
                            table_data.append([result_section, k, v])
                        else:
                            table_data.append(["", k, v])

            else:
                headers = ["OPTION", "KEY"]
                table_data = [(o, v) for o, v in result.items()]

        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
            RichUtils.print_output(*table_data, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=headers))


@config.command("set")
@click.option("-s", "--section", help="Section name", required=True)
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def set(ctx: click.Context, section: str, key: str, value: str):
    """
    Modify the section.key/value of the config. Overwrites if option already exists.

    \b
        $ rucio config set --section my-section --key key --value value
    """
    if ctx.obj.client.get_config().get(section, {}).get(key, None) is not None:
        ctx.obj.logger.debug("%s.%s already exists. Overwriting..." % (section, key))

    ctx.obj.client.set_config_option(section=section, option=key, value=value)
    print(f'Set configuration: {section}.{key}={value}')


@config.command("unset")
@click.option("-s", "--section", help="Section", required=True)
@click.option("-k", "--key", help="Key in section", required=True)
@click.pass_context
def unset(ctx: click.Context, section: str, key: str):
    """Remove the section.key from the config."""
    if ctx.obj.client.delete_config_option(section=section, option=key):
        print(f"Deleted section '{section}' option '{key}'")
    else:
        msg = f"Section '{section}' option '{key}' not found"
        raise ValueError(msg)


# @config.command("show")
# @click.pass_context
def show(ctx):
    """Show a single sections options"""
