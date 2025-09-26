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
from tabulate import tabulate

from rucio.cli.bin_legacy.rucio import add_rule, delete_rule, info_rule, list_rules_history, move_rule, update_rule
from rucio.cli.utils import Arguments
from rucio.client.richclient import CLITheme, generate_table, print_output
from rucio.common.exception import InputValidationError
from rucio.common.utils import extract_scope, sizefmt


@click.group()
def rule():
    """View and define rules for creating replicas of DIDs"""


@rule.command("add")
@click.argument("dids", nargs=-1)
@click.option("--copies", type=int, help="Number of copies", required=True)
@click.option("--rses", "--rse-exp", help="Rule RSE expression", required=True)
@click.option("--weight", help="RSE Weight")
@click.option("--lifetime", type=int, help="Rule lifetime (in seconds)")
@click.option("--grouping", type=click.Choice(["DATASET", "ALL", "NONE"]), help="Rule grouping")
@click.option("--locked", default=False, type=bool, is_flag=False, help="Rule locking")
@click.option("--source-rses", help="RSE Expression for RSEs to be considered for source replicas")
@click.option("--notify", type=click.Choice(["Y", "N", "C"]), help="Notification strategy : Y (Yes), N (No), C (Close)")
@click.option("--activity", help="Activity to be used (e.g. User, Data Consolidation)")
@click.option("--comment", help="Comment about the replication rule")
@click.option("--ask-approval", is_flag=True, default=False, help="Ask for rule approval")
@click.option("--asynchronous", is_flag=True, default=False, help="Create rule asynchronously")
@click.option("--delay-injection", type=int, help="Delay (in seconds) to wait before starting applying the rule. This option implies --asynchronous.")
@click.option("--account", help="The account owning the rule")
@click.option("--skip-duplicates", is_flag=True, default=False, help="Skip duplicate rules")
@click.pass_context
def add_(ctx, dids, copies, rses, weight, asynchronous, lifetime, grouping, locked, source_rses, notify, activity, comment, ask_approval, delay_injection, account, skip_duplicates):
    """Add replication rule to define how replicas of a list of DIDs are created on RSEs."""
    args = Arguments(
        {
            "dids": dids,
            "copies": copies,
            "rse_expression": rses,
            "weight": weight,
            "lifetime": lifetime,
            "grouping": grouping,
            "locked": locked,
            "notify": notify,
            "activity": activity,
            "comment": comment,
            "ask_approval": ask_approval,
            "delay_injection": delay_injection,
            "rule_account": account,
            "source_replica_expression": source_rses,
            "ignore_duplicate": skip_duplicates,
            "asynchronous": asynchronous,
        }
    )
    add_rule(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("remove")
@click.argument("rule-id-dids")
@click.option("--purge-replicas", is_flag=True, default=False, help="Purge rule replicas")
@click.option("--all", "_all", is_flag=True, default=False, help="Delete all the rules, even the ones that are not owned by the account")
@click.option("--rses", "--rse-exp", help="The RSE expression. Must be specified if a DID is provided.")  # TODO mutual inclusive group
@click.option("--account", help="The account of the rule that must be deleted")
@click.pass_context
def remove(ctx, rule_id_dids, _all, rses, account, purge_replicas):
    """Remove an existing rule. Supply [rule-id] if know, or use [DID] and --rses to remove all rules for DIDs on RSEs matching the expression"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "purge_replicas": purge_replicas, "delete_all": _all, "rule_account": account, "rule_id": rule_id_dids, "rses": rses})
    delete_rule(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("show")
@click.argument("rule-id")
@click.option("--examine", is_flag=True, default=False, help="Detailed analysis of transfer errors")
@click.pass_context
def show(ctx, rule_id, examine):
    """Retrieve information about a rule"""
    info_rule(Arguments({"no_pager": ctx.obj.no_pager, "rule_id": rule_id, "examine": examine}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("history")
@click.argument("did", nargs=1)
@click.pass_context
def history(ctx, did):
    """Display the history of rules acting on a DID"""
    list_rules_history(Arguments({"no_pager": ctx.obj.no_pager, "did": did}), ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("move")
@click.argument("rule_id")
@click.option("--rses", "--rse-exp", help="RSE expression of new rule", required=True)
@click.option("--activity", help="Update activity for moved rule", hidden=True)  # Should only do this using `update`
@click.option("--source-rses", help="Update how replicas are sourced for the rule")
@click.pass_context
def move(ctx, rule_id, rses, activity, source_rses):
    """Create a child rule on a different RSE. The parent rule is deleted once the new rule reaches `OK` status"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "rule_id": rule_id, "rse_expression": rses, "source_replica_expression": source_rses, "activity": activity})
    move_rule(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("update")
@click.argument("rule-id", nargs=1)
@click.option("--lifetime", type=str, help="Rule lifetime (in seconds). Use 'None' for no set lifetime")
@click.option("--locked", default=False, type=bool, is_flag=False, help="Rule locking")
@click.option("--source-rses", help="RSE Expression for RSEs to be considered for source replicas")
@click.option("--activity", help="Activity to be used (e.g. User, Data Consolidation)")
@click.option("--comment", help="Comment about the replication rule")
@click.option("--account", help="The account owning the rule")
@click.option("--stuck", is_flag=True, default=False, help="Set state to STUCK.")
@click.option('--suspend', is_flag=True, default=None, help='Set state to SUSPENDED.')
@click.option("--activity", help="Activity of the rule.")
@click.option("--cancel-requests", is_flag=True, default=False, help="Cancel requests when setting rules to stuck.")
@click.option("--priority", help="Priority of the requests of the rule.")
@click.option("--child-rule-id", help='Child rule id of the rule. Use "None" to remove an existing parent/child relationship.')
@click.option("--boost-rule", is_flag=True, default=False, help="Quickens the transition of a rule from STUCK to REPLICATING.")
@click.pass_context
def update(
    ctx, rule_id: str, lifetime: str, locked: bool, source_rses: str, activity: str, comment: str,
    account: str, stuck: bool, suspend: bool, cancel_requests: bool, priority: str, child_rule_id: str, boost_rule: bool
):
    """Update an existing rule"""
    args = Arguments(
        {
            "rule_id": rule_id,
            "lifetime": lifetime,
            "locked": str(locked),  # update-rule wants to be able to uppercase arg
            "rule_activity": activity,
            "comment": comment,
            "rule_account": account,
            "source_replica_expression": source_rses,
            "state_stuck": stuck,
            "state_suspended": suspend,
            "cancel_requests": cancel_requests,
            "priority": priority,
            "child_rule_id": child_rule_id,
            "boost_rule": boost_rule,
        }
    )
    update_rule(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("list")
@click.option("--did", help="Filter by DID")
@click.option("--traverse", is_flag=True, default=False, help="Traverse the did tree and search for rules affecting this did. Must supply a DID.")
@click.option("--csv", is_flag=True, default=False, help="Comma Separated Value output")
@click.option("--lock", is_flag=True, default=False, help="See all rules locking a DID")
@click.option("--account", help="Filter by account")
@click.option("--subscription", help="Filter by subscription name")
@click.option("--rses", "--rse-exp", help="Filter by RSE")
@click.pass_context
def list_(ctx: click.Context, did: Optional[str], traverse: bool, csv: bool, lock: bool, account: Optional[str], subscription: Optional[str], rses: Optional[str]) -> None:
    """List all rules impacting a given DID"""

    if (traverse and (did is None)) or (lock and (did is None)):
        raise InputValidationError("To use the `--traverse` or `--lock` option a DID must be supplied")

    cli_config = ctx.obj.cli_config
    spinner = ctx.obj.spinner
    client = ctx.obj.client

    if cli_config == 'rich':
        spinner.update(status='Fetching rules')
        spinner.start()

    rules = None
    filters = {}
    if did is not None:
        scope, name = extract_scope(did)
        filters["scope"] = scope
        filters["name"] = name
        if traverse:
            locks = client.get_dataset_locks(scope=scope, name=name)
            rules = []
            for rule_id in list(set([lock['rule_id'] for lock in locks])):
                rules.append(client.get_replication_rule(rule_id))
        if lock:
            rules = client.list_associated_rules_for_file(scope, name)

    if account is not None:
        filters['account'] = account
    if subscription is not None:
        subscription_info = client.list_subscriptions(name=subscription)['subscription_id']
        filters["subscription_id"] = subscription_info
    if rses is not None:
        filters['rse_expression'] = rses

    if rules is None:
        rules = client.list_replication_rules(filters=filters)

    if csv:
        for rule in rules:
            print(
                rule['id'],
                rule['account'],
                f"{rule['scope']}:{rule['name']}",
                f"{rule['state']}[{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}]",
                rule['rse_expression'],
                rule['copies'],
                sizefmt(rule['bytes'], ctx.obj.human) if rule['bytes'] is not None else 'N/A',
                rule['expires_at'],
                rule['created_at'],
                sep=','
            )

        if cli_config == 'rich':
            spinner.stop()
    else:
        table_data = []
        for rule in rules:
            if cli_config == 'rich':
                table_data.append([
                    rule['id'],
                    rule['account'],
                    f"{rule['scope']}:{rule['name']}",
                    f"[{CLITheme.RULE_STATE.get(rule['state'], 'default')}]{rule['state']}[/][{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}]",
                    rule['rse_expression'],
                    rule['copies'],
                    sizefmt(rule['bytes'], ctx.obj.human) if rule['bytes'] is not None else 'N/A',
                    rule['expires_at'],
                    rule['created_at']
                ])
            else:
                table_data.append([
                    rule['id'],
                    rule['account'],
                    f"{rule['scope']}:{rule['name']}",
                    f"{rule['state']}[{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}]",
                    rule['rse_expression'],
                    rule['copies'],
                    sizefmt(rule['bytes'], ctx.obj.human) if rule['bytes'] is not None else 'N/A',
                    rule['expires_at'],
                    rule['created_at']
                ])

        if cli_config == 'rich':
            table = generate_table(
                table_data,
                headers=['ID', 'ACCOUNT', 'SCOPE:NAME', 'STATE[OK/REPL/STUCK]', 'RSE EXPRESSION', 'COPIES', 'SIZE', 'EXPIRES (UTC)', 'CREATED (UTC)'],
                col_alignments=['left', 'left', 'left', 'right', 'left', 'right', 'right', 'left', 'left']
            )
            spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            print(tabulate(
                table_data,
                tablefmt='simple',
                headers=['ID', 'ACCOUNT', 'SCOPE:NAME', 'STATE[OK/REPL/STUCK]', 'RSE_EXPRESSION', 'COPIES', 'SIZE', 'EXPIRES (UTC)', 'CREATED (UTC)'],
                disable_numparse=True)
            )
