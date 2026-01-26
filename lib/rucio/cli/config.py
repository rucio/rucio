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
    result = ctx.obj.client.get_config(section=section, option=key)
    if not isinstance(result, dict):
        print(f'[{section}]\n{key}={result}')
    else:
        print_header = True
        for i in list(result.keys()):
            if print_header:
                if section is not None:
                    print(f'[{section}]')
                else:
                    print(f'[{i}]')
            if not isinstance(result[i], dict):
                print(f'{i}={result[i]}')
                print_header = False
            else:
                for j in list(result[i].keys()):
                    print(f'{j}={result[i][j]}')


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

    ctx.obj.client.set_config_option(section=section, option=key, value=value)
    print(f'Set configuration: {section}.{key}={value}')


@config.command("remove")
@click.option("-s", "--section", help="Section", required=True)
@click.option("-k", "--key", help="Key in section", required=True)
@click.pass_context
def remove(ctx: click.Context, section: str, key: str):
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
