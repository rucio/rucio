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

from rucio.client.commands.bin_legacy.rucio_admin import add_scope, list_scopes
from rucio.client.commands.utils import Arguments, click_decorator


@click.group()
@click.help_option("-h", "--help")
def scope():
    pass


@scope.command("add")
@click.argument("scope-name")
@click.option("-a", "--account", help="Associated account", required=True)
@click_decorator
def add_(ctx, account, scope_name):
    """Add a new scope with name [SCOPE-NAME]"""
    args = Arguments({"scope": scope_name, "account": account})
    add_scope(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@scope.command("list")
@click.option("-a", "--account", help="Filter by associated account", default=False)
@click_decorator
def list_(ctx, account):
    """List existing scopes"""
    list_scopes(Arguments({"account": account}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
