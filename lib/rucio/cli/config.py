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
from rucio.cli.bin_legacy.rucio_admin import get_config, set_config_option, delete_config_option
from rucio.cli.utils import Arguments

@click.group()
def config():
    """
    Configuration management.
    """
    pass

@config.command()
@click.argument('section')
@click.argument('option', required=False)
@click.pass_context
def get(ctx, section, option):
    """
    Get a configuration value.
    """
    # The legacy function expects an object with .section and .option attributes
    args = Arguments(section=section, option=option)
    get_config(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])

@config.command()
@click.argument('section')
@click.argument('option')
@click.argument('value')
@click.pass_context
def set(ctx, section, option, value):
    """
    Set a configuration value.
    """
    # The legacy function expects .section, .option, and .value
    args = Arguments(section=section, option=option, value=value)
    set_config_option(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])

@config.command()
@click.argument('section')
@click.argument('option')
@click.pass_context
def delete(ctx, section, option):
    """
    Delete a configuration value.
    """
    # The legacy function expects .section and .option
    args = Arguments(section=section, option=option)
    delete_config_option(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])
