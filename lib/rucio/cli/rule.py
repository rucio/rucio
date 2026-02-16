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
import uuid

import click
from rich.padding import Padding
from rich.text import Text
from tabulate import tabulate

from rucio.cli.utils import get_scope
from rucio.client.richclient import CLITheme, generate_table, print_output
from rucio.common.exception import DuplicateRule, InputValidationError, RucioException
from rucio.common.utils import sizefmt


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
    did_list = []
    rule_ids = []
    for did in dids:
        scope, name = get_scope(did, ctx.obj.client)
        did_list.append({'scope': scope, 'name': name})
    try:
        rule_ids = ctx.obj.client.add_replication_rule(
            dids=did_list,
            copies=copies,
            rse_expression=rses,
            weight=weight,
            lifetime=lifetime,
            grouping=grouping,
            account=account,
            locked=locked,
            source_replica_expression=source_rses,
            notify=notify,
            activity=activity,
            comment=comment,
            ask_approval=ask_approval,
            asynchronous=asynchronous,
            delay_injection=delay_injection
    )
    except DuplicateRule as error:
        if skip_duplicates:
            for did in did_list:
                try:
                    rule_id = ctx.obj.client.add_replication_rule(
                        dids=[did],
                        copies=copies,
                        rse_expression=rses,
                        weight=weight,
                        lifetime=lifetime,
                        grouping=grouping,
                        account=account,
                        locked=locked,
                        source_replica_expression=source_rses,
                        notify=notify,
                        activity=activity,
                        comment=comment,
                        ask_approval=ask_approval,
                        asynchronous=asynchronous,
                        delay_injection=delay_injection
                    )
                    rule_ids.extend(rule_id)
                except DuplicateRule:
                    print(f'Duplicate rule for {did["scope"]}:{did["name"]} found; Skipping.')
        else:
            raise error

    for rule in rule_ids:
        print(rule)


@rule.command("remove")
@click.argument("rule-id-dids")
@click.option("--purge-replicas", is_flag=True, default=False, help="Purge rule replicas")
@click.option("--all", "_all", is_flag=True, default=False, help="Delete all the rules, even the ones that are not owned by the account")
@click.option("--rses", "--rse-exp", help="The RSE expression. Must be specified if a DID is provided.")  # TODO mutual inclusive group
@click.option("--account", help="The account of the rule that must be deleted")
@click.pass_context
def remove(ctx, rule_id_dids, _all, rses, account, purge_replicas):
    """Remove an existing rule. Supply [rule-id] if know, or use [DID] and --rses to remove all rules for DIDs on RSEs matching the expression"""
    try:
        # Test if the rule_id is a real rule_id
        uuid.UUID(rule_id_dids)
        ctx.obj.client.delete_replication_rule(rule_id=rule_id_dids, purge_replicas=purge_replicas)
    except ValueError:
        # Otherwise, trying to extract the scope, name from args.rule_id
        if not rses:
            raise InputValidationError('A RSE expression must be specified if you do not provide a rule_id but a DID')
        scope, name = get_scope(rule_id_dids, ctx.obj.client)
        rules = ctx.obj.client.list_did_rules(scope=scope, name=name)
        if account is None:
            account = ctx.obj.client.account

        deletion_success = False
        for rule in rules:
            if _all:
                account_checked = True
            else:
                account_checked = rule['account'] == account
            if rule['rse_expression'] == rses and account_checked:
                ctx.obj.client.delete_replication_rule(rule_id=rule['id'], purge_replicas=purge_replicas)
                deletion_success = True
        if not deletion_success:
            raise RucioException('No replication rule was deleted from the DID')


@rule.command("show")
@click.argument("rule-id")
@click.option("--examine", is_flag=True, default=False, help="Detailed analysis of transfer errors")
@click.pass_context
def show(ctx, rule_id, examine):
    """Retrieve information about a rule"""
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching rule info')
        ctx.obj.spinner.start()

    if examine:
        output = []
        analysis = ctx.obj.client.examine_replication_rule(rule_id=rule_id)
        if ctx.obj.use_rich:
            keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE, **CLITheme.RULE_STATE}
            rule_status = " ".join([f'[{keyword_styles.get(word, "default")}]{word}[/]' for word in analysis['rule_error'].split()])
            output.append(f'Status of the replication rule: {rule_status}')
            if analysis['transfers']:
                output.append('[b]STUCK Requests:[/]')
                for transfer in analysis['transfers']:
                    output.append(Padding.indent(Text(f"{transfer['scope']}:{transfer['name']}", style=CLITheme.SUBHEADER_HIGHLIGHT), 2))
                    table_data = [
                        ['RSE:', str(transfer['rse'])],
                        ['Attempts:', str(transfer['attempts'])],
                        ['Last retry:', str(transfer['last_time'])],
                        ['Last error:', str(transfer['last_error'])],
                        ['Last source:', str(transfer['last_source'])],
                        ['Available sources:', ', '.join([source[0] for source in transfer['sources'] if source[1]])],
                        ['Blocklisted sources:', ', '.join([source[0] for source in transfer['sources'] if not source[1]])]
                    ]
                    table = generate_table(table_data, row_styles=['none'], col_alignments=['left', 'left'])
                    output.append(Padding.indent(table, 2))

            ctx.obj.spinner.stop()
            print_output(*output, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            analysis = ctx.obj.client.examine_replication_rule(rule_id=rule_id)
            print(f'Status of the replication rule: {analysis["rule_error"]}')
            if analysis['transfers']:
                print('STUCK Requests:')
                lpad = ' ' * 5

                def _format_print(name, value):
                    name += ":"
                    print(f"{lpad}{name.ljust(20)}{value}")
                for transfer in analysis['transfers']:
                    print(f'  {transfer["scope"]}:{transfer["name"]}')
                    _format_print('RSE', transfer['rse'])
                    _format_print('Attempts', transfer['attempts'])
                    _format_print('Last Retry', transfer['last_time'])
                    _format_print('Last error', transfer['last_error'])
                    _format_print('Last source', transfer['last_source'])
                    _format_print('Available sources', ', '.join([source[0] for source in transfer['sources'] if source[1]]))
                    _format_print('Blocklisted sources', ', '.join([source[0] for source in transfer['sources'] if not source[1]]))

    else:
        rule = ctx.obj.client.get_replication_rule(rule_id=rule_id)
        if ctx.obj.use_rich:
            keyword_styles = {**CLITheme.BOOLEAN, **CLITheme.DID_TYPE, **CLITheme.RULE_STATE}
            table_data = [(k, Text(str(v), style=keyword_styles.get(str(v), 'default'))) for k, v in sorted(rule.items())]
            table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            def _format_print(name, value):
                name += ":"
                print(f'{name.ljust(28)}{value}')

            _format_print('Id', rule['id'])
            _format_print('Account', rule['account'])
            _format_print('Scope', rule['scope'])
            _format_print('Name', rule['name'])
            _format_print('RSE Expression', rule['rse_expression'])
            _format_print('Copies', rule['copies'])
            _format_print('State', rule['state'])
            _format_print('Locks OK/REPLICATING/STUCK', f"{rule['locks_ok_cnt']}/{rule['locks_replicating_cnt']}/{rule['locks_stuck_cnt']}")
            _format_print('Grouping', rule['grouping'])
            _format_print('Expires at', rule['expires_at'])
            _format_print('Locked', rule['locked'])
            _format_print('Weight', rule['weight'])
            _format_print('Created at', rule['created_at'])
            _format_print('Updated at', rule['updated_at'])
            _format_print('Error', rule['error'])
            _format_print('Subscription Id', rule['subscription_id'])
            _format_print('Source replica expression', rule['source_replica_expression'])
            _format_print('Activity', rule['activity'])
            _format_print('Comment', rule['comments'])
            _format_print('Ignore Quota', rule['ignore_account_limit'])
            _format_print('Ignore Availability', rule['ignore_availability'])
            _format_print('Purge replicas', rule['purge_replicas'])
            _format_print('Notification', rule['notification'])
            _format_print('End of life', rule['eol_at'])
            _format_print('Child Rule Id', rule['child_rule_id'])


@rule.command("history")
@click.argument("did", nargs=1)
@click.pass_context
def history(ctx, did):
    """Display the history of rules acting on a DID"""
    rule_dict = []
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching rules history')
        ctx.obj.spinner.start()

    scope, name = get_scope(did, ctx.obj.client)
    table_data = []
    for rule in ctx.obj.client.list_replication_rule_full_history(scope, name):
        if rule['rule_id'] not in rule_dict:
            rule_dict.append(rule['rule_id'])
            if ctx.obj.use_rich:
                table_data.append(['Insertion', rule['account'], rule['rse_expression'], rule['created_at']])
            else:
                print('-' * 40)
                print('Rule insertion')
                print(f'Account : {rule["account"]}')
                print(f'RSE expression : {rule["rse_expression"]}')
                print(f'Time : {rule["created_at"]}')
        else:
            rule_dict.remove(rule['rule_id'])
            if ctx.obj.use_rich:
                table_data.append(['Deletion', rule['account'], rule['rse_expression'], rule['updated_at']])
            else:
                print('-' * 40)
                print('Rule deletion')
                print(f'Account : {rule["account"]}')
                print(f'RSE expression : {rule["rse_expression"]}')
                print(f'Time : {rule["updated_at"]}')

    if ctx.obj.use_rich:
        table_data = sorted(table_data, key=lambda entry: entry[-1], reverse=True)
        table = generate_table(table_data, headers=['ACTION', 'ACCOUNT', 'RSE EXPRESSION', 'TIME'])
        ctx.obj.spinner.stop()
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)


@rule.command("move")
@click.argument("rule_id")
@click.option("--rses", "--rse-exp", help="RSE expression of new rule", required=True)
@click.option("--activity", help="Update activity for moved rule", hidden=True)  # Should only do this using `update`
@click.option("--source-rses", help="Update how replicas are sourced for the rule")
@click.pass_context
def move(ctx, rule_id, rses, activity, source_rses):
    """Create a child rule on a different RSE. The parent rule is deleted once the new rule reaches `OK` status"""
    override = {}
    if activity:
        override['activity'] = activity
    if source_rses:
        override['source_replica_expression'] = None if source_rses.lower() == "none" else source_rses

    new_rule_id = ctx.obj.client.move_replication_rule(rule_id=rule_id, rse_expression=rses, override=override)
    print(new_rule_id)


@rule.command("update")
@click.argument("rule-id", nargs=1)
@click.option("--lifetime", type=str, help="Rule lifetime (in seconds). Use 'None' for no set lifetime")
@click.option("--locked", type=bool, is_flag=False, help="Rule locking")
@click.option("--source-rses", help="RSE Expression for RSEs to be considered for source replicas")
@click.option("--activity", help="Activity to be used (e.g. User, Data Consolidation)")
@click.option("--comment", help="Comment about the replication rule")
@click.option("--account", help="The account owning the rule")
@click.option("--stuck", is_flag=True, default=False, help="Set state to STUCK.")
@click.option('--suspend', is_flag=True, default=None, help='Set state to SUSPENDED.')
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
    options = {}
    if lifetime:
        options['lifetime'] = None if lifetime.lower() == "none" else int(lifetime)
    if locked:
        options['locked'] = locked
    if comment:
        options['comment'] = comment
    if account:
        options['account'] = account
    if stuck:  # TODO Error when both are selected
        options['state'] = 'STUCK'
    if suspend:
        options['state'] = 'SUSPENDED'
    if activity:
        options['activity'] = activity
    if source_rses:
        options['source_replica_expression'] = None if source_rses.lower() == 'none' else source_rses
    if cancel_requests:
        if 'state' not in options:
            raise InputValidationError('--stuck or --suspend must be specified when running --cancel-requests')
        options['cancel_requests'] = True
    if priority:
        options['priority'] = int(priority)
    if child_rule_id:
        if child_rule_id.lower() == 'none':
            options['child_rule_id'] = None
        else:
            options['child_rule_id'] = child_rule_id
    if boost_rule:
        options['boost_rule'] = boost_rule
    ctx.obj.client.update_replication_rule(rule_id=rule_id, options=options)
    print('Updated Rule')


@rule.command("list")
@click.option("--did", help="Filter by DID")
@click.option("--traverse", is_flag=True, default=False, help="Traverse the did tree and search for rules affecting this did")
@click.option("--csv", is_flag=True, default=False, help="Comma Separated Value output")
@click.option("--file", help="Filter by file")
@click.option("--account", help="Filter by account")
@click.option("--subscription", help="Filter by subscription name")
@click.pass_context
def list_(ctx, did, traverse, csv, file, account, subscription):
    """List all rules impacting a given DID"""
    # Done here to raise error==2
    if not (did or file or account or subscription):
        raise InputValidationError("At least one option has to be given. Use -h to list the options.")
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Fetching rules')
        ctx.obj.spinner.start()

    if file:
        scope, name = get_scope(file, ctx.obj.client)
        rules = ctx.obj.client.list_associated_rules_for_file(scope=scope, name=name)
    elif traverse:
        scope, name = get_scope(did, ctx.obj.client)
        locks = ctx.obj.client.get_dataset_locks(scope=scope, name=name)
        rules = []
        for rule_id in list(set([lock['rule_id'] for lock in locks])):
            rules.append(ctx.obj.client.get_replication_rule(rule_id))
    elif did:
        scope, name = get_scope(did, ctx.obj.client)
        meta = ctx.obj.client.get_metadata(scope=scope, name=name)
        rules = ctx.obj.client.list_did_rules(scope=scope, name=name)
        try:
            next(rules)
            rules = ctx.obj.client.list_did_rules(scope=scope, name=name)
        except StopIteration:
            rules = []
            # looking for other rules
            if meta['did_type'] == 'CONTAINER':
                for dsn in ctx.obj.client.list_content(scope, name):
                    rules.extend(ctx.obj.client.list_did_rules(scope=dsn['scope'], name=dsn['name']))
                if rules:
                    print('No rules found, listing rules for content')
            if meta['did_type'] == 'DATASET':
                for container in ctx.obj.client.list_parent_dids(scope, name):
                    rules.extend(ctx.obj.client.list_did_rules(scope=container['scope'], name=container['name']))
                if rules:
                    print('No rules found, listing rules for parents')
    elif account:
        rules = ctx.obj.client.list_account_rules(account=account)
    elif subscription:
        if account is None:
            account = ctx.obj.client.account
        name = subscription
        rules = ctx.obj.client.list_subscription_rules(account=account, name=name)

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

        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
    else:
        table_data = []
        for rule in rules:
            if ctx.obj.use_rich:
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

        if ctx.obj.use_rich:
            table = generate_table(
                table_data,
                headers=['ID', 'ACCOUNT', 'SCOPE:NAME', 'STATE[OK/REPL/STUCK]', 'RSE EXPRESSION', 'COPIES', 'SIZE', 'EXPIRES (UTC)', 'CREATED (UTC)'],
                col_alignments=['left', 'left', 'left', 'right', 'left', 'right', 'right', 'left', 'left']
            )
            ctx.obj.spinner.stop()
            print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
        else:
            table = tabulate(table_data, tablefmt='simple', headers=['ID', 'ACCOUNT', 'SCOPE:NAME', 'STATE[OK/REPL/STUCK]', 'RSE_EXPRESSION', 'COPIES', 'SIZE', 'EXPIRES (UTC)', 'CREATED (UTC)'], disable_numparse=True)
            print(table)
