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

from rucio.cli.bin_legacy.rucio import add_rule, delete_rule, info_rule, list_rules, list_rules_history, move_rule, update_rule
from rucio.cli.utils import Arguments


@click.group()
def rule():
    """View and define rules for creating replicas of DIDs"""


@rule.command("add")
@click.argument("dids", nargs=-1)
@click.option("--copies", type=int, help="Number of copies", required=True)
@click.option("--rses", "--rse-exp", help="Rule RSE expression", required=True)
@click.option("--weight", help="RSE Weight")
@click.option("--lifetime", type=str, help="Rule lifetime (in seconds). Use 'None' for no set lifetime")
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
@click.option("--activity", help="Activity of the rule.")
@click.option("--cancel-requests", is_flag=True, default=False, help="Cancel requests when setting rules to stuck.")
@click.option("--priority", help="Priority of the requests of the rule.")
@click.option("--child-rule-id", help='Child rule id of the rule. Use "None" to remove an existing parent/child relationship.')
@click.option("--boost-rule", is_flag=True, default=False, help="Quickens the transition of a rule from STUCK to REPLICATING.")
@click.pass_context
def update(ctx, rule_id, lifetime, locked, source_rses, activity, comment, account, stuck, cancel_requests, priority, child_rule_id, boost_rule):
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
            "cancel_requests": cancel_requests,
            "priority": priority,
            "child_rule_id": child_rule_id,
            "boost_rule": boost_rule,
        }
    )
    update_rule(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@rule.command("list")
@click.option("--did")
@click.option("--id", "rule_id", help="List by rule id", hidden=True)  # TODO: Remove. This doesn't work and does the same thing as show
@click.option("--traverse", is_flag=True, default=False, help="Traverse the did tree and search for rules affecting this did")
@click.option("--csv", is_flag=True, default=False, help="Comma Separated Value output")
@click.option("--file", help="Filter by file")
@click.option("--account", help="Filter by account")
@click.option("--subscription", help="Filter by subscription name")
@click.pass_context
def list_(ctx, did, rule_id, traverse, csv, file, account, subscription):
    """List all rules impacting a given DID"""
    args = Arguments({"no_pager": ctx.obj.no_pager, "did": did, "rule_id": rule_id, "traverse": traverse, "csv": csv, "file": file, "subscription": (account if account is not None else ctx.obj.client.account, subscription)})
    list_rules(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
