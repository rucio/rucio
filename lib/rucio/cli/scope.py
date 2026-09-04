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
from tabulate import tabulate

from rucio.cli.utils import RichUtils


@click.group()
def scope():
    """Interact with scopes - a logical grouping of DIDs"""


@scope.command("add")
@click.argument("scope-name")
@click.option("-a", "--account", help="Associated account", required=True)
@click.pass_context
def add_(ctx: click.Context, account: str, scope_name: str) -> None:
    """Add a new scope with name [SCOPE-NAME]"""
    ctx.obj.client.add_scope(account=account, scope=scope_name)
    print(f'Added new scope to {account}: {scope_name}')


@scope.command("list")
@click.option("-a", "--account", help="Filter by associated account", required=False)
@click.option("--csv", is_flag=True, help="Output in CSV format", default=False)
@click.pass_context
def list_(ctx: click.Context, account: str, csv: bool) -> None:
    """List existing scopes"""
    if (ctx.obj.use_rich) and (not csv):
        ctx.obj.spinner.update(status='Fetching scopes')
        ctx.obj.spinner.start()

    if account:
        scopes = ctx.obj.client.list_scopes_for_account(account)
        with_owner = False
    else:
        scopes = ctx.obj.client.list_scope_owners()
        with_owner = True

    if (ctx.obj.use_rich) and (not csv):
        if len(scopes) == 0:
            ctx.obj.spinner.stop()
        elif not with_owner:
            scopes = [[scope] for scope in sorted(scopes)]
            table = RichUtils.generate_table(scopes, headers=['SCOPE'], col_alignments=['left'])
            ctx.obj.spinner.stop()
            RichUtils.print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            scopes = [[s['scope'], s['account']] for s in scopes]
            table = RichUtils.generate_table(scopes, headers=['SCOPE', "ACCOUNT"], col_alignments=['left'])
            ctx.obj.spinner.stop()
            RichUtils.print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        if len(scopes) == 0:
            pass
        elif csv:
            for scope in scopes:
                if not with_owner:
                    print(scope)
                else:
                    print(f"{scope['scope']},{scope['account']}")
        elif not with_owner:
            for scope in scopes:
                print(scope)
        else:
            scopes = [[s['scope'], s['account']] for s in scopes]
            print(tabulate(scopes, tablefmt=ctx.obj.tablefmt, headers=['SCOPE', 'ACCOUNT'], disable_numparse=True))


@scope.command("update")
@click.argument("scope-name")
@click.option("--account", help="New account to associate with scope", required=True)
@click.pass_context
def update(ctx: click.Context, scope_name: str, account: str) -> None:
    """Update the owner of the scope [SCOPE-NAME]"""
    ctx.obj.client.update_scope(account=account, scope=scope_name)
