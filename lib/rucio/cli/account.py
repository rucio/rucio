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

from rucio.cli.bin_legacy.rucio import list_account_usage
from rucio.cli.bin_legacy.rucio_admin import (
    add_account,
    add_account_attribute,
    ban_account,
    delete_account,
    delete_account_attribute,
    delete_limits,
    identity_delete,
    info_account,
    list_account_attributes,
    list_accounts,
    list_identities,
    set_limits,
    unban_account,
    update_account,
)
from rucio.cli.bin_legacy.rucio_admin import identity_add as legacy_identity_add
from rucio.cli.utils import Arguments


@click.group()
def account():
    """Methods to add or change accounts for users, groups, and services. Used to assign privileges"""


@account.command("add")
@click.argument("account-name")
@click.argument("account-type", type=click.Choice(["USER", "GROUP", "SERVICE"]))
@click.option("--email", type=str, help="Email address associated with the account")
@click.pass_context
def add_(ctx, account_type, account_name, email):
    """Add an account of type [ACCOUNT-TYPE] with the name [ACCOUNT-NAME]

    \b
    Example:
        $ rucio account add
    """
    args = Arguments({"no_pager": ctx.obj.no_pager, "account_type": account_type, "account": account_name, "email": email})
    add_account(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.command("list")
@click.option("--type", "type_", type=click.Choice(["USER", "GROUP", "SERVICE"]))
@click.option("--id", help="Filter by identity (e.g. DN)")
@click.option("--filter", help="Filter arguments in form `key=value,another_key=next_value`")  # TODO Explicit numeration of these possible keys
@click.pass_context
def list_(ctx, type_, id, filter):
    """List all accounts that match given filters"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account_type": type_, "identity": id, "filters": filter})
    list_accounts(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.command("show")
@click.argument("account-name")
@click.pass_context
def show(ctx, account_name):
    """
    Show info about a single account
    """
    info_account(Arguments({"no_pager": ctx.obj.no_pager, "account": account_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.command("remove")
@click.argument("account-name")
@click.pass_context
def remove(ctx, account_name):
    """
    Remove an account
    (WARNING: Permanently disables the account. If you want to temporarily disable, use `account update [account-name] --ban`)
    """
    delete_account(Arguments({"no_pager": ctx.obj.no_pager, "account": account_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.command("update")
@click.argument("account-name")
@click.option("--email", help="Email address associated with the account")
@click.option("--ban/--unban", default=None, help="Temporarily disable/enable an account")
@click.pass_context
def update(ctx, ban, account_name, email):
    """Update account settings"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "key": "email", "value": email})
    if ban is not None:
        if ban:
            ban_account(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
        else:
            unban_account(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
    else:
        update_account(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.group()
def attribute():
    """View or modify account attributes"""


@attribute.command("list")
@click.argument("account-name")
@click.pass_context
def attribute_list(ctx, account_name):
    "List the attributes for a given account"
    list_account_attributes(Arguments({"no_pager": ctx.obj.no_pager, "account": account_name}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@attribute.command("add")
@click.argument("account-name")
@click.option('--key', help='Attribute key', required=True)
@click.option('--value', help='Attribute value', required=True)
@click.pass_context
def attribute_add(ctx, account_name, key, value):
    """Add a new attribute [key] to an account"""
    add_account_attribute(Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "key": key, "value": value}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@attribute.command("remove")
@click.argument("account-name")
@click.option("--key", help="Attribute key", required=True)
@click.pass_context
def attribute_remove(ctx, account_name, key):
    """Remove an attribute from an account without reassigning it"""
    delete_account_attribute(Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "key": key}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.group("limit")
def limit():
    """View or modify account limits - limit how much data an account can store on an RSE"""


@limit.command("list", help="Shows the space used, the quota limit and the quota left for an account for every RSE where the user have quota.")
@click.argument("account-name")
@click.option("--rse", "--rse-name", help="Show usage for only for this RSE.")
@click.pass_context
def limit_list(ctx, account_name, rse):
    """List the limits and current usage for an account"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "usage_account": account_name, "rse": rse})
    list_account_usage(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@limit.command("add")
@click.argument(
    "account-name",
)
@click.option("--rse", "--rse-name", help="Full RSE name", required=True)  # TODO Separate RSE (local) and RSE Expression (global)
@click.option("--bytes", "bytes_", help='Value of the limit; can be specified in bytes ("10000"), with a storage unit ("10GB"), or "infinity"', required=True)
@click.option("--locality", type=click.Choice(["local", "global"]), help="Global or local limit scope", default="local")
@click.pass_context
def limit_add(ctx, account_name, rse, bytes_, locality):
    """Add a new limit for an account on an RSE. An account can have both local and global limits on the same RSE."""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "rse": rse, "bytes": bytes_, "locality": locality})
    set_limits(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@limit.command("remove")
@click.argument(
    "account-name",
)
@click.option("--rse", "--rse-name", help="Full RSE name", required=True)
@click.option("--locality", type=click.Choice(["local", "global"]), help="Global or local limit scope", default="local")
@click.pass_context
def limit_remove(ctx, account_name, rse, locality):
    """Remove existing limits for an account on an RSE"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "rse": rse, "locality": locality})
    delete_limits(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@account.group("identity")
def identity():
    """Manage identities for an account - used to login"""


@identity.command("list")
@click.argument("account-name", required=True)
@click.pass_context
def identity_list(ctx, account_name):
    """See all the IDs for [account-name]"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account": account_name})
    list_identities(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@identity.command("add")
@click.argument("account-name", required=True)
@click.option("--type", "type_", type=click.Choice(["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"]), help="Authentication type", required=True)
@click.option("--id", help="Identity", required=True)
@click.option("--email", help="Email address associated with the identity", required=True)
@click.option("--password", help="Password if authtype is USERPASS")
@click.pass_context
def identity_add(ctx, account_name, type_, id, email, password):
    """Add a new identity for [account-name]"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "authtype": type_, "identity": id, "email": email, "password": password})
    legacy_identity_add(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@identity.command("remove")
@click.argument("account-name", required=True)
@click.option("--type", "type_", type=click.Choice(["X509", "GSS", "USERPASS", "SSH", "SAML", "OIDC"]), help="Authentication type", required=True)
@click.option("--id", help="Identity", required=True)
@click.pass_context
def identity_remove(ctx, account_name, type_, id):
    """Revoke a given ID's access from an account"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "account": account_name, "authtype": type_, "identity": id})
    identity_delete(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
