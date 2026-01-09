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
@click.option('--section', dest='section', help='Section name')
@click.option('--option', dest='option', help='Option name')
@click.pass_context
def get(ctx, **kwargs):
    """
    Get matching configuration.
    """
    args = Arguments(**kwargs)
    get_config(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])


@config.command()
@click.option('--section', dest='section', required=True, help='Section name')
@click.option('--option', dest='option', required=True, help='Option name')
@click.option('--value', dest='value', required=True, help='Value')
@click.pass_context
def set(ctx, **kwargs):
    """
    Set matching configuration.
    """
    args = Arguments(**kwargs)
    set_config_option(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])


@config.command()
@click.option('--section', dest='section', required=True, help='Section name')
@click.option('--option', dest='option', required=True, help='Option name')
@click.pass_context
def delete(ctx, **kwargs):
    """
    Delete matching configuration.
    """
    args = Arguments(**kwargs)
    delete_config_option(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])
