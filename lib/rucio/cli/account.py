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
from typing import Literal, Optional

import click
from rich.text import Text
from tabulate import tabulate

from rucio.client.richclient import CLITheme, generate_table, print_output
from rucio.common.exception import InputValidationError
from rucio.common.utils import get_bytes_value_from_string, sizefmt


@click.group()
def account():
    """Methods to add or change accounts for users, groups, and services. Used to assign privileges"""


@account.command("add")
@click.argument("account-name")
@click.argument("account-type", type=click.Choice(["USER", "GROUP", "SERVICE"]))
@click.option("--email", type=str, help="Email address associated with the account")
@click.pass_context
def add_(ctx: click.Context, account_type: Literal['USER', 'GROUP', 'SERVICE'], account_name: str, email: str):
    """Add an account of type [ACCOUNT-TYPE] with the name [ACCOUNT-NAME]

    \b
    Example:
        $ rucio account add
    """
    ctx.obj.client.add_account(
        account=account_name,
        type_=account_type,
        email=email
    )
    print('Added new account: %s' % account)


@account.command("list")
@click.option("--type", "type_", type=click.Choice(["USER", "GROUP", "SERVICE"]))
@click.option("--id", help="Filter by identity (e.g. DN)")
@click.option("--filter", help="Filter arguments in form `key=value,another_key=next_value`")  # TODO Explicit numeration of these possible keys
@click.option('--csv', help="Output result as a CSV", is_flag=True)
@click.pass_context
def list_(ctx: click.Context, type_: Optional[Literal['USER', 'GROUP', 'SERVICE']], id: Optional[str], filter: Optional[str], csv: bool):
    """List all accounts that match given filters"""
    filters = {}
    if filter:
        for key, value in [(s.split('=')[0], s.split('=')[1]) for s in filter.split(',')]:
            filters[key] = value
    accounts = ctx.obj.client.list_accounts(identity=id, account_type=type_, filters=filters)
    if csv:
        print(*(account['account'] for account in accounts), sep=',')
    elif ctx.obj.use_rich:
        table = generate_table([
            [account['account']] for account in accounts],
            headers=['ACCOUNT'],
            col_alignments=['left']
        )
        ctx.obj.spinner.stop()
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        for account in accounts:
            print(account['account'])


@account.command("show")
@click.argument("account-name")
@click.pass_context
def show(ctx: click.Context, account_name: str):
    """
    Show info about a single account
    """
    info = ctx.obj.client.get_account(account=account_name)
    if ctx.obj.use_rich:
        keyword_style = {**CLITheme.ACCOUNT_STATUS, **CLITheme.ACCOUNT_TYPE}
        table_data = [(k, Text(str(v), style=keyword_style.get(str(v), 'default'))) for k, v in sorted(info.items())]
        table = generate_table(
            table_data,
            row_styles=['none'],
            col_alignments=['left', 'left']
        )
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        for k in info:
            print(k.ljust(10) + ' : ' + str(info[k]))


@account.command("remove")
@click.argument("account-name")
@click.pass_context
def remove(ctx: click.Context, account_name: str):
    """
    Remove an account
    (WARNING: Permanently disables the account. If you want to temporarily disable, use `account update [account-name] --ban`)
    """
    ctx.obj.client.delete_account(account_name)
    print('Deleted account: %s' % account_name)


@account.command("update")
@click.argument("account-name")
@click.option("--email", help="Email address associated with the account")
@click.option("--ban/--unban", default=None, help="Temporarily disable/enable an account")
@click.pass_context
def update(ctx: click.Context, ban: Optional[bool], account_name: str, email: Optional[str]):
    """Update account settings"""
    if ban is not None:
        if ban:
            ctx.obj.client.update_account(
                account=account_name, key='status', value='SUSPENDED'
            )
            print('Account %s banned' % account_name)
        else:
            ctx.obj.client.update_account(account=account_name, key='status', value='ACTIVE')
            print('Account %s unbanned' % account_name)
    else:
        ctx.obj.client.update_account(account=account_name, key='email', value=email)
        print('email of account %s changed to %s' % (account_name, email))


@account.group()
def attribute():
    """View or modify account attributes"""


@attribute.command("list")
@click.argument("account-name")
@click.pass_context
def attribute_list(ctx: click.Context, account_name: str):
    "List the attributes for a given account"
    attributes = next(ctx.obj.client.list_account_attributes(account_name))
    table_data = []
    for attr in attributes:
        table_data.append([attr['key'], attr['value']])

    if ctx.obj.use_rich:
        table = generate_table(table_data, headers=['Key', 'Value'], col_alignments=['left', 'left'])
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['Key', 'Value']))


@attribute.command("add")
@click.argument("account-name")
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def attribute_add(ctx: click.Context, account_name: str, key: str, value: str):
    """Add a new attribute [key] to an account"""
    ctx.obj.client.add_account_attribute(account=account_name, key=key, value=value)


@attribute.command("remove")
@click.argument("account-name")
@click.option("--key", help="Attribute key", required=True)
@click.pass_context
def attribute_remove(ctx: click.Context, account_name: str, key: str):
    """Remove an attribute from an account without reassigning it"""
    ctx.obj.client.delete_account_attribute(account=account_name, key=key)


@account.group("limit")
def limit():
    """View or modify account limits - limit how much data an account can store on an RSE"""


@limit.command("list")
@click.argument("account-name")
@click.option("--rse", "--rse-name", help="Show usage for only for this RSE.")
@click.option(
    "--unique",
    is_flag=True,
    default=False,
    help="Count unique replicas to avoid double-counting when multiple locks exist. "
        "Warning: This is computationally expensive as it queries replicas directly "
        "rather than using cached counters. Use sparingly, especially for accounts "
        "with many replicas.")
@click.pass_context
def limit_list(ctx: click.Context, account_name: str, rse: Optional[str], unique: bool) -> None:
    """
    Shows the space used, the quota limit and the quota left
    for an account for every RSE where the user have quota.
    """
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching account usage')
        ctx.obj.spinner.start()

    usage = ctx.obj.client.get_local_account_usage(account=account_name, rse=rse, unique=unique)
    table_data = []
    for item in usage:
        remaining = 0 if float(item['bytes_remaining']) < 0 else float(item['bytes_remaining'])
        table_data.append([item['rse'], sizefmt(item['bytes'], ctx.obj.human), sizefmt(item['bytes_limit'], ctx.obj.human), sizefmt(remaining, ctx.obj.human)])
    table_data.sort()

    if ctx.obj.use_rich:
        table1 = generate_table(table_data, headers=['RSE', 'USAGE', 'LIMIT', 'QUOTA LEFT'], col_alignments=['left', 'right', 'right', 'right'])
    else:
        print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['RSE', 'USAGE', 'LIMIT', 'QUOTA LEFT']))

    table_data = []
    usage = ctx.obj.client.get_global_account_usage(account=account_name)
    for item in usage:
        if (rse and rse in item['rse_expression']) or not rse:
            remaining = 0 if float(item['bytes_remaining']) < 0 else float(item['bytes_remaining'])
            table_data.append([item['rse_expression'], sizefmt(item['bytes'], ctx.obj.human), sizefmt(item['bytes_limit'], ctx.obj.human), sizefmt(remaining, ctx.obj.human)])
    table_data.sort()

    if ctx.obj.use_rich:
        table2 = generate_table(table_data, headers=['RSE EXPRESSION', 'USAGE', 'LIMIT', 'QUOTA LEFT'], col_alignments=['left', 'right', 'right', 'right'])
    else:
        print(tabulate(table_data, tablefmt=ctx.obj.tablefmt, headers=['RSE EXPRESSION', 'USAGE', 'LIMIT', 'QUOTA LEFT']))

    if ctx.obj.use_rich:
        ctx.obj.spinner.stop()
        print_output(table1, table2, console=ctx.obj.console, no_pager=ctx.obj.no_pager)

@limit.command("add")
@click.argument(
    "account-name",
)
@click.option("--rse", "--rse-name", help="Full RSE name", required=True)  # TODO Separate RSE (local) and RSE Expression (global)
@click.option("--bytes", "bytes_", help='Value of the limit; can be specified in bytes ("10000"), with a storage unit ("10GB"), or "infinity"', required=True)
@click.option("--locality", type=click.Choice(["local", "global"]), help="Global or local limit scope", default="local")
@click.pass_context
def limit_add(ctx: click.Context, account_name: str, rse: str, bytes_: str, locality: str):
    """Add a new limit for an account on an RSE. An account can have both local and global limits on the same RSE."""
    byte_limit = None
    limit_input = bytes_.lower()

    if limit_input == 'inf' or limit_input == 'infinity':
        byte_limit = -1
    else:
        byte_limit = get_bytes_value_from_string(limit_input)
        if not byte_limit:
            try:
                byte_limit = int(limit_input)
            except ValueError:
                msg = f'\
                    The limit could not be set. Either you misspelled infinity or your input ({bytes_.lower()}) could not be converted to integer or you used a wrong pattern. \
                    Please use a format like 10GB with B,KB,MB,GB,TB,PB as units (not case sensitive)'
                raise InputValidationError(msg)

    ctx.obj.client.set_account_limit(account=account_name, rse=rse, bytes_=byte_limit, locality=locality.lower())
    print('Set account limit for account %s on RSE %s: %s' % (account_name, rse, sizefmt(byte_limit, True)))


@limit.command("remove")
@click.argument("account-name")
@click.option("--rse", "--rse-name", help="Full RSE name", required=True)
@click.option("--locality", type=click.Choice(["local", "global"]), help="Global or local limit scope", default="local")
@click.pass_context
def limit_remove(ctx: click.Context, account_name: str, rse: str, locality: str):
    """Remove existing limits for an account on an RSE"""
    ctx.obj.client.delete_account_limit(account=account_name, rse=rse, locality=locality)
    print('Deleted account limit for account %s and RSE %s' % (account_name, rse))


@account.group("identity")
def identity():
    """Manage identities for an account - used to login"""


@identity.command("list")
@click.argument("account-name", required=True)
@click.pass_context
def identity_list(ctx: click.Context, account_name: str):
    """See all the IDs for [account-name]"""
    table_data = []
    identities = ctx.obj.client.list_identities(account=account_name)
    for identity in identities:
        if ctx.obj.use_rich:
            table_data.append([identity['identity'], identity['type']])
        else:
            print('Identity: %(identity)s,\ttype: %(type)s' % identity)
    if ctx.obj.use_rich:
        table = generate_table(table_data, headers=['IDENTITY', 'TYPE'], col_alignments=['left', 'left'])
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)


@identity.command("add")
@click.argument("account-name", required=True)
@click.option("--type", "type_", type=click.Choice(["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"]), help="Authentication type", required=True)
@click.option("--id", help="Identity", required=True)
@click.option("--email", help="Email address associated with the identity", required=True)
@click.option("--password", help="Password if authtype is USERPASS")
@click.pass_context
def identity_add(ctx: click.Context, account_name: str, type_: str, id: str, email: str, password: Optional[str]):
    """Add a new identity for [account-name]"""
    if email == "":
        raise InputValidationError('Error: --email argument can\'t be an empty string. Failed to grant an identity access to an account')

    if type_ == 'USERPASS' and not password:
        raise InputValidationError('Missing --password argument')

    ctx.obj.client.add_identity(account=account_name, identity=id, authtype=type_, email=email, password=password)
    print('Added new identity to account: %s-%s' % (id, account_name))


@identity.command("remove")
@click.argument("account-name", required=True)
@click.option("--type", "type_", type=click.Choice(["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"]), help="Authentication type", required=True)
@click.option("--id", help="Identity", required=True)
@click.pass_context
def identity_remove(ctx: click.Context, account_name: str, type_: str, id: str):
    """Revoke a given ID's access from an account"""
    ctx.obj.client.del_identity(account_name, id, authtype=type_)
    print('Deleted identity: %s' % id)
