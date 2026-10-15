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
import json
from typing import TYPE_CHECKING, Optional

import click
from rich.text import Text
from rich.tree import Tree

from rucio.cli.utils import DSVType, RichCLITheme, RichUtils, get_scope

if TYPE_CHECKING:
    from collections.abc import Iterable


@click.group()
def subscription():
    "The methods for automated and regular processing of some specific rules"


def __format_filter_values(values: object) -> str:
    if isinstance(values, (list, tuple)):
        return ', '.join(map(str, values))
    return str(values)


@subscription.command("show")
@click.option("-a", "--account", help="Account associated with the subscription")
@click.option("--long", default=False, is_flag=True, help="Show extended information about the subscription")
@click.argument("subscription-name")
@click.pass_context
def show(ctx: click.Context, subscription_name: str, account: Optional[str], long: bool) -> None:
    """Show the attributes of a subscription [SUBSCRIPTION-NAME]"""
    if account is None:
        account = ctx.obj.client.account

    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching subscriptions')
        ctx.obj.spinner.start()
        keyword_styles = {**RichCLITheme.SUBSCRIPTION_STATE, **RichCLITheme.BOOLEAN}

    subs = ctx.obj.client.list_subscriptions(name=subscription_name, account=account)
    for sub in subs:
        table_data = []
        if long:
            if ctx.obj.use_rich:
                for k, v in sorted(sub.items()):
                    if k == 'filter':
                        filter_tree = Tree('')
                        for filter, values in json.loads(sub['filter']).items():
                            values_str = __format_filter_values(values)
                            filter_tree.add(f'[{RichCLITheme.JSON_STR}]{filter}[/]: {values_str}')
                        table_data.append(['filter', filter_tree])
                    elif k == 'replication_rules':
                        rule_tree = Tree('')
                        for i, rule in enumerate(json.loads(sub['replication_rules'])):
                            branch = rule_tree.add(Text('rule:', style='default'))
                            for k, v in rule.items():
                                branch.add(f'[{RichCLITheme.JSON_STR}]{k}[/]: {v}')
                        table_data.append(['replication_rules', rule_tree])
                    else:
                        table_data.append([str(k), Text(str(v), style=keyword_styles.get(str(v), 'default'))])
            else:
                print('\n'.join('%s: %s' % (str(k), str(v)) for (k, v) in list(sub.items())))
                print()
        else:
            if ctx.obj.use_rich:
                table_data.append(['account', sub['account']])
                table_data.append(['comments', sub.get('comments', '')])
                filter_tree = Tree('')
                for filter, values in json.loads(sub['filter']).items():
                    values_str = __format_filter_values(values)
                    filter_tree.add(f'[green]{filter}[/]: {values_str}')
                table_data.append(['filter', filter_tree])
                table_data.append(['name', sub['name']])
                table_data.append(['policyid', str(sub['policyid'])])
                rule_tree = Tree('')
                for i, rule in enumerate(json.loads(sub['replication_rules'])):
                    branch = rule_tree.add(Text('rule:', style='default'))
                    for k, v in rule.items():
                        branch.add(f'[{RichCLITheme.JSON_STR}]{k}[/]: {v}')
                table_data.append(['replication_rules', rule_tree])
                table_data.append(['state', Text(str(sub['state']), keyword_styles.get(str(sub['state']), 'default'))])
            else:
                print("%s: %s %s\n  priority: %s\n  filter: %s\n  rules: %s\n  comments: %s" % (sub['account'], sub['name'], sub['state'], sub['policyid'], sub['filter'], sub['replication_rules'], sub.get('comments', '')))

        if ctx.obj.use_rich:
            table = RichUtils.generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
            ctx.obj.spinner.stop()
            RichUtils.print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)


@subscription.command("update")
@click.argument("subscription-name")
@click.option("--filter", "did_filter", help='Json serializable DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')', required=True)
@click.option("--rule", help='List of replication rules (eg \'[{"activity": "Functional Tests", "copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "weight": "mou"}]\')', required=True)
@click.option("--comment", help="Comments on subscription")
@click.option("--lifetime", type=int, help="Subscription lifetime (in days)")
@click.option("--account", help="Account name")
@click.option("--priority", help="The priority of the subscription")
@click.pass_context
def update(
    ctx: click.Context,
    subscription_name: str,
    did_filter: str,
    rule: str,
    comment: Optional[str],
    lifetime: Optional[int],
    account: Optional[str],
    priority: Optional[str]
) -> None:
    """Update a subscription [SUBSCRIPTION-NAME] to have new properties"""
    if account is None:
        account = ctx.obj.client.account

    ctx.obj.client.update_subscription(
        name=subscription_name,
        account=account,
        filter_=json.loads(did_filter),
        replication_rules=json.loads(rule),
        comments=comment,
        lifetime=lifetime,
        retroactive=False,
        dry_run=False,
        priority=priority
    )


@subscription.command("add")
@click.argument("subscription-name")
@click.option("--filter", "did_filter", help='Json serializable DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')', required=True)
@click.option("--rule", help='List of replication rules (eg \'[{"activity": "Functional Tests", "copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "weight": "mou"}]\')', required=True)
@click.option("--comment", help="Comments on subscription")
@click.option("--lifetime", type=int, help="Subscription lifetime (in days)")
@click.option("--account", help="Account name")
@click.option("--priority", help="The priority of the subscription")
@click.pass_context
def add_(
    ctx: click.Context,
    subscription_name: str,
    did_filter: str,
    rule: str,
    comment: Optional[str],
    lifetime: Optional[int],
    account: Optional[str],
    priority: Optional[str]
) -> None:
    """Create a new subscription with the name [SUBSCRIPTION-NAME]"""
    if account is None:
        account = ctx.obj.client.account

    subscription_id = ctx.obj.client.add_subscription(
        name=subscription_name,
        account=account,
        filter_=json.loads(did_filter),
        replication_rules=json.loads(rule),
        comments=comment,
        lifetime=lifetime,
        retroactive=False,
        dry_run=False,
        priority=priority
    )
    print(f'Subscription added {subscription_id}')


@subscription.command("touch")
@click.argument("dids", nargs=-1, type=DSVType())
@click.pass_context
def touch(ctx: click.Context, dids: "Iterable[list]") -> None:
    """Reevaluate list of DIDs against all active subscriptions"""
    flattened_dids = [did for items in dids for did in items]
    for did in flattened_dids:
        scope, name = get_scope(did, ctx.obj.client)
        ctx.obj.client.set_metadata(scope, name, 'is_new', True)


@subscription.command("list")
@click.option("--account", help="Filter by account associated with the subscription. If not supplied, the client account will be used.")
@click.option("--long", is_flag=True, default=False, help='Show extended attributes for each subscription')
@click.pass_context
def list_(ctx: click.Context, account: Optional[str], long: str) -> None:
    """List all subscriptions"""
    if account is None:
        account = ctx.obj.client.account

    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching subscriptions')
        ctx.obj.spinner.start()
        keyword_styles = {**RichCLITheme.SUBSCRIPTION_STATE, **RichCLITheme.BOOLEAN}

    subs = ctx.obj.client.list_subscriptions(name=None, account=account)
    for sub in subs:
        table_data = []
        if long:
            if ctx.obj.use_rich:
                for k, v in sorted(sub.items()):
                    if k == 'filter':
                        filter_tree = Tree('')
                        for filter, values in json.loads(sub['filter']).items():
                            values_str = __format_filter_values(values)
                            filter_tree.add(f'[{RichCLITheme.JSON_STR}]{filter}[/]: {values_str}')
                        table_data.append(['filter', filter_tree])
                    elif k == 'replication_rules':
                        rule_tree = Tree('')
                        for i, rule in enumerate(json.loads(sub['replication_rules'])):
                            branch = rule_tree.add(Text('rule:', style='default'))
                            for k, v in rule.items():
                                branch.add(f'[{RichCLITheme.JSON_STR}]{k}[/]: {v}')
                        table_data.append(['replication_rules', rule_tree])
                    else:
                        table_data.append([str(k), Text(str(v), style=keyword_styles.get(str(v), 'default'))])
            else:
                print('\n'.join('%s: %s' % (str(k), str(v)) for (k, v) in list(sub.items())))
                print()
        else:
            if ctx.obj.use_rich:
                table_data.append(['account', sub['account']])
                table_data.append(['comments', sub.get('comments', '')])
                filter_tree = Tree('')
                for filter, values in json.loads(sub['filter']).items():
                    values_str = __format_filter_values(values)
                    filter_tree.add(f'[green]{filter}[/]: {values_str}')
                table_data.append(['filter', filter_tree])
                table_data.append(['name', sub['name']])
                table_data.append(['policyid', str(sub['policyid'])])
                rule_tree = Tree('')
                for i, rule in enumerate(json.loads(sub['replication_rules'])):
                    branch = rule_tree.add(Text('rule:', style='default'))
                    for k, v in rule.items():
                        branch.add(f'[{RichCLITheme.JSON_STR}]{k}[/]: {v}')
                table_data.append(['replication_rules', rule_tree])
                table_data.append(['state', Text(str(sub['state']), keyword_styles.get(str(sub['state']), 'default'))])
            else:
                print("%s: %s %s\n  priority: %s\n  filter: %s\n  rules: %s\n  comments: %s" % (sub['account'], sub['name'], sub['state'], sub['policyid'], sub['filter'], sub['replication_rules'], sub.get('comments', '')))

        if ctx.obj.use_rich:
            table = RichUtils.generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
            ctx.obj.spinner.stop()
            RichUtils.print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
