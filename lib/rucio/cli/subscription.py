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

from rucio.cli.bin_legacy.rucio_admin import add_subscription, list_subscriptions, reevaluate_did_for_subscription, update_subscription
from rucio.cli.utils import Arguments


@click.group()
def subscription():
    "The methods for automated and regular processing of some specific rules"


@subscription.command("show")
@click.option("-a", "--account", help="Account associated with the subscription")
@click.option("--long", default=False, is_flag=True, help="Show extended information about the subscription")
@click.argument("subscription-name")
@click.pass_context
def list_(ctx, subscription_name, account, long):
    """Show the attributes of a subscription [SUBSCRIPTION-NAME]"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "subs_account": account, "name": subscription_name, "long": long})
    list_subscriptions(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@subscription.command("update")
@click.argument("subscription-name")
@click.option("--filter", "did_filter", help='Json serializable DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')', required=True)
@click.option("--rule", help='List of replication rules (eg \'[{"activity": "Functional Tests", "copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "weight": "mou"}]\')', required=True)
@click.option("--comment", help="Comments on subscription")
@click.option("--lifetime", type=int, help="Subscription lifetime (in days)")
@click.option("--account", help="Account name")
@click.option("--priority", help="The priority of the subscription")
@click.pass_context
def update(ctx, subscription_name, did_filter, rule, comment, lifetime, account, priority):
    """Update a subscription [SUBSCRIPTION-NAME] to have new properties"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "name": subscription_name, "filter": did_filter, "replication_rules": rule, "comments": comment, "lifetime": lifetime, "subs_account": account, "priority": priority})
    update_subscription(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@subscription.command("add")
@click.argument("subscription-name")
@click.option("--filter", "did_filter", help='Json serializable DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')', required=True)
@click.option("--rule", help='List of replication rules (eg \'[{"activity": "Functional Tests", "copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "weight": "mou"}]\')', required=True)
@click.option("--comment", help="Comments on subscription")
@click.option("--lifetime", type=int, help="Subscription lifetime (in days)")
@click.option("--account", help="Account name")
@click.option("--priority", help="The priority of the subscription")
@click.pass_context
def add_(ctx, subscription_name, did_filter, rule, comment, lifetime, account, priority):
    """Create a new subscription with the name [SUBSCRIPTION-NAME]"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "name": subscription_name, "filter": did_filter, "replication_rules": rule, "comments": comment, "lifetime": lifetime, "subs_account": account, "priority": priority})
    add_subscription(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@subscription.command("touch")
@click.argument("dids", nargs=-1)
@click.pass_context
def touch(ctx, dids):
    """Reevaluate list of DIDs against all active subscriptions"""
    # TODO make reeval accept DIDs as a list
    dids = ",".join(dids)
    reevaluate_did_for_subscription(Arguments({"no_pager": ctx.obj.no_pager, "dids": dids}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
