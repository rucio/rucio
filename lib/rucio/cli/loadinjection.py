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

import csv
import json
from datetime import datetime, timedelta
from typing import Optional

import click
from tabulate import tabulate

from rucio.client.richclient import get_cli_config, generate_table, print_output
from rucio.common.exception import NoLoadInjectionPlanFound

cli_config = get_cli_config()

# Common options reused across subcommands
_SRC_RSE_OPTION = click.option(
    "--src-rse", "--src", "src_rse",
    type=str, required=True, help="Source RSE name.",
)
_DEST_RSE_OPTION = click.option(
    "--dest-rse", "--dest", "--des", "--dst", "dest_rse",
    type=str, required=True, help="Destination RSE name.",
)
_SRC_RSE_OPTION_OPT = click.option(
    "--src-rse", "--src", "src_rse",
    type=str, required=False, help="Source RSE name.",
)
_DEST_RSE_OPTION_OPT = click.option(
    "--dest-rse", "--dest", "--des", "--dst", "dest_rse",
    type=str, required=False, help="Destination RSE name.",
)
_INJECT_RATE_OPTION = click.option(
    "--inject-rate", "--rate", "--mbps",
    type=int, default=200, help="Injection rate in Mbps (default: 200).",
)
_START_TIME_OPTION = click.option(
    "--start-time", "--start",
    type=str, default=None,
    help="Start time (UTC) YYYY-MM-DD HH:MM:SS (default: now).",
)
_END_TIME_OPTION = click.option(
    "--end-time", "--end",
    type=str, default=None,
    help="End time (UTC) YYYY-MM-DD HH:MM:SS (default: now + 2h).",
)
_INTERVAL_OPTION = click.option(
    "--interval", "--time-interval",
    type=int, default=900, help="Injection interval in seconds (default: 900).",
)
_FUDGE_OPTION = click.option(
    "--fudge", "--fudge-factor",
    type=float, default=0.0, help="Fudge factor (default: 0.0).",
)
_MAX_INJECTION_OPTION = click.option(
    "--max-injection", "--max",
    type=float, default=0.2, help="Max fraction beyond target rate (default: 0.2).",
)
_EXPIRATION_DELAY_OPTION = click.option(
    "--expiration-delay", "--delay",
    type=int, default=1800, help="Dataset reuse delay in seconds (default: 1800).",
)
_RULE_LIFETIME_OPTION = click.option(
    "--rule-lifetime", "--lifetime",
    type=int, default=3600, help="Rule lifetime in seconds (default: 3600).",
)
_BIG_FIRST_OPTION = click.option(
    "--big-first", is_flag=True, default=False, help="Inject larger datasets first.",
)
_DRY_RUN_OPTION = click.option(
    "--dry-run", "--dryrun", is_flag=True, default=False,
    help="Dry run: do not actually submit rules.",
)
_COMMENTS_OPTION = click.option(
    "--comments", "--comment",
    type=str, default="Data injection plans", help="Comments for the plan.",
)
_CSV_OPTION = click.option(
    "--csv-file", "--csv", "--file",
    type=click.Path(exists=True), help="CSV file for bulk plan import.",
)
_TEST_OPTION = click.option(
    "--test", is_flag=True, default=False,
    help="Test mode: print plans without submitting.",
)
_STATE_OPTION = click.option(
    "--state", type=str, default=None, help="Filter by plan state.",
)


def _normalize_csv(csv_path: str) -> list[dict]:
    """Read and normalize a CSV file into a list of plan dicts."""
    plans = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            plan = {}
            for key, value in row.items():
                key = key.strip().lower().replace("_", "-")
                if key in ("src-rse", "src"):
                    plan["src_rse"] = value
                elif key in ("dest-rse", "dest", "des", "dst"):
                    plan["dest_rse"] = value
                elif key in ("inject-rate", "rate", "mbps"):
                    plan["inject_rate"] = int(value) if value else 200
                elif key in ("start-time", "start"):
                    plan["start_time"] = value
                elif key in ("end-time", "end"):
                    plan["end_time"] = value
                elif key in ("interval", "time-interval"):
                    plan["interval"] = int(value) if value else 900
                elif key in ("fudge", "fudge-factor"):
                    plan["fudge"] = float(value) if value else 0.0
                elif key in ("max-injection", "max"):
                    plan["max_injection"] = float(value) if value else 0.2
                elif key in ("expiration-delay", "delay"):
                    plan["expiration_delay"] = int(value) if value else 1800
                elif key in ("rule-lifetime", "lifetime"):
                    plan["rule_lifetime"] = int(value) if value else 3600
                elif key in ("big-first"):
                    plan["big_first"] = value.lower() in ("true", "1", "yes")
                elif key in ("dry-run", "dryrun"):
                    plan["dry_run"] = value.lower() in ("true", "1", "yes")
                elif key in ("comments", "comment"):
                    plan["comments"] = value
                else:
                    raise ValueError(f"Unknown CSV column: {key}")
            plans.append(plan)
    return plans


def _build_plan(args: dict, src_rse: str, dest_rse: str) -> dict:
    """Build a plan dict from args."""
    return {
        "src_rse": src_rse,
        "dest_rse": dest_rse,
        "inject_rate": args.get("inject_rate", 200),
        "start_time": args.get("start_time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        "end_time": args.get("end_time", (datetime.utcnow() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")),
        "interval": args.get("interval", 900),
        "fudge": args.get("fudge", 0.0),
        "max_injection": args.get("max_injection", 0.2),
        "expiration_delay": args.get("expiration_delay", 1800),
        "rule_lifetime": args.get("rule_lifetime", 3600),
        "big_first": args.get("big_first", False),
        "dry_run": args.get("dry_run", False),
        "comments": args.get("comments", "Data injection plans"),
    }


@click.group()
def loadinjection() -> None:
    """Manage load injection plans for data challenges and stress testing."""


@loadinjection.command("add")
@_SRC_RSE_OPTION
@_DEST_RSE_OPTION
@_INJECT_RATE_OPTION
@_START_TIME_OPTION
@_END_TIME_OPTION
@_INTERVAL_OPTION
@_FUDGE_OPTION
@_MAX_INJECTION_OPTION
@_EXPIRATION_DELAY_OPTION
@_RULE_LIFETIME_OPTION
@_BIG_FIRST_OPTION
@_DRY_RUN_OPTION
@_COMMENTS_OPTION
@_CSV_OPTION
@_TEST_OPTION
@click.pass_context
def add_(
    ctx, src_rse, dest_rse, inject_rate, start_time, end_time,
    interval, fudge, max_injection, expiration_delay, rule_lifetime,
    big_first, dry_run, comments, csv_file, test,
):
    """Add load injection plan(s). Use --csv-file for bulk import."""
    if start_time is None:
        start_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    if end_time is None:
        end_time = (datetime.utcnow() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")

    if csv_file:
        plans = _normalize_csv(csv_file)
    else:
        plans = [_build_plan({
            "inject_rate": inject_rate, "start_time": start_time,
            "end_time": end_time, "interval": interval,
            "fudge": fudge, "max_injection": max_injection,
            "expiration_delay": expiration_delay,
            "rule_lifetime": rule_lifetime, "big_first": big_first,
            "dry_run": dry_run, "comments": comments,
        }, src_rse, dest_rse)]

    if test:
        click.echo("Test mode — plans to be submitted:\n")
        click.echo(json.dumps(plans, indent=2, default=str))
        return

    client = ctx.obj.client
    client.add_load_injection_plans(plans)
    click.echo(f"Added {len(plans)} load injection plan(s).")


@loadinjection.command("list")
@_STATE_OPTION
@_SRC_RSE_OPTION_OPT
@_DEST_RSE_OPTION_OPT
@click.pass_context
def list_(
    ctx, state, src_rse, dest_rse,
):
    """List load injection plans, optionally filtered by state or RSE."""
    client = ctx.obj.client
    plans = list(client.list_load_injection_plans())

    if state:
        plans = [p for p in plans if p.get("state") == state]
    if src_rse:
        plans = [p for p in plans if p.get("src_rse") == src_rse]
    if dest_rse:
        plans = [p for p in plans if p.get("dest_rse") == dest_rse]

    if not plans:
        click.echo("No load injection plans found.")
        return

    table_data = [
        [
            p.get("src_rse", ""), p.get("dest_rse", ""),
            str(p.get("inject_rate", "")), p.get("state", ""),
            p.get("start_time", ""), p.get("end_time", ""),
            p.get("comments", ""),
        ]
        for p in plans
    ]

    headers = ['SRC RSE', 'DEST RSE', 'RATE (Mbps)', 'STATE', 'START', 'END', 'COMMENTS']
    if cli_config == 'rich':
        table = generate_table(table_data, headers=headers)
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        print(tabulate(table_data, headers=headers, tablefmt='simple'))


@loadinjection.command("info")
@_SRC_RSE_OPTION_OPT
@_DEST_RSE_OPTION_OPT
@click.pass_context
def info(
    ctx, src_rse, dest_rse,
):
    """Show detailed information about a load injection plan."""
    if not src_rse or not dest_rse:
        raise click.UsageError("--src-rse and --dest-rse are required.")

    client = ctx.obj.client
    plan = client.info_load_injection_plan(src_rse, dest_rse)

    key_order = [
        "plan_id", "src_rse", "dest_rse", "inject_rate", "state",
        "start_time", "end_time", "interval", "fudge", "max_injection",
        "rule_lifetime", "expiration_delay", "big_first", "dry_run", "comments",
    ]
    table_data = [[k, str(plan[k])] for k in key_order if k in plan]

    if cli_config == 'rich':
        table = generate_table(table_data, col_alignments=['left', 'left'], row_styles=['none'])
        print_output(table, console=ctx.obj.console, no_pager=ctx.obj.no_pager)
    else:
        print(tabulate(table_data, tablefmt='psql'))


@loadinjection.command("remove")
@_SRC_RSE_OPTION
@_DEST_RSE_OPTION
@click.pass_context
def remove(ctx, src_rse, dest_rse):
    """Remove a load injection plan."""
    client = ctx.obj.client
    try:
        client.remove_load_injection_plan(src_rse, dest_rse)
        click.echo(f"Plan {src_rse} -> {dest_rse} removed.")
    except NoLoadInjectionPlanFound:
        raise SystemExit(f"No plan found for {src_rse} -> {dest_rse}.")


# Update-specific options with default=None so only explicit params are sent
_UPDATE_INJECT_RATE = click.option(
    "--inject-rate", "--rate", "--mbps", type=int, default=None,
    help="Injection rate in Mbps.",)
_UPDATE_START_TIME = click.option(
    "--start-time", "--start", type=str, default=None,
    help="Start time (UTC) YYYY-MM-DD HH:MM:SS.",)
_UPDATE_END_TIME = click.option(
    "--end-time", "--end", type=str, default=None,
    help="End time (UTC) YYYY-MM-DD HH:MM:SS.",)
_UPDATE_INTERVAL = click.option(
    "--interval", "--time-interval", type=int, default=None,
    help="Injection interval in seconds.",)
_UPDATE_FUDGE = click.option(
    "--fudge", "--fudge-factor", type=float, default=None,
    help="Fudge factor.",)
_UPDATE_MAX_INJ = click.option(
    "--max-injection", "--max", type=float, default=None,
    help="Max fraction beyond target rate.",)
_UPDATE_EXP_DELAY = click.option(
    "--expiration-delay", "--delay", type=int, default=None,
    help="Dataset reuse delay in seconds.",)
_UPDATE_RULE_LT = click.option(
    "--rule-lifetime", "--lifetime", type=int, default=None,
    help="Rule lifetime in seconds.",)
_UPDATE_BIG_FIRST = click.option(
    "--big-first", "big_first", flag_value=True, default=None,
    help="Inject larger datasets first.",)
_UPDATE_NO_BIG_FIRST = click.option(
    "--no-big-first", "big_first", flag_value=False,
    help="Do not inject larger datasets first.",)
_UPDATE_DRY_RUN = click.option(
    "--dry-run", "--dryrun", "dry_run", flag_value=True, default=None,
    help="Dry run: do not actually submit rules.",)
_UPDATE_NO_DRY_RUN = click.option(
    "--no-dry-run", "--no-dryrun", "dry_run", flag_value=False,
    help="Actually submit rules (disable dry run).",)
_UPDATE_COMMENTS = click.option(
    "--comments", "--comment", type=str, default=None,
    help="Comments for the plan.",)


@loadinjection.command("update")
@_SRC_RSE_OPTION
@_DEST_RSE_OPTION
@_UPDATE_INJECT_RATE
@_UPDATE_START_TIME
@_UPDATE_END_TIME
@_UPDATE_INTERVAL
@_UPDATE_FUDGE
@_UPDATE_MAX_INJ
@_UPDATE_EXP_DELAY
@_UPDATE_RULE_LT
@_UPDATE_BIG_FIRST
@_UPDATE_NO_BIG_FIRST
@_UPDATE_DRY_RUN
@_UPDATE_NO_DRY_RUN
@_UPDATE_COMMENTS
@click.pass_context
def update(
    ctx, src_rse, dest_rse, inject_rate, start_time, end_time,
    interval, fudge, max_injection, expiration_delay, rule_lifetime,
    big_first, dry_run, comments,
):
    """Update an existing load injection plan. Only specified options are sent."""
    client = ctx.obj.client
    # Collect only parameters the user explicitly set (non-None/non-default)
    updates = {}
    if inject_rate is not None:
        updates["inject_rate"] = inject_rate
    if start_time is not None:
        updates["start_time"] = start_time
    if end_time is not None:
        updates["end_time"] = end_time
    if interval is not None:
        updates["interval"] = interval
    if fudge is not None:
        updates["fudge"] = fudge
    if max_injection is not None:
        updates["max_injection"] = max_injection
    if expiration_delay is not None:
        updates["expiration_delay"] = expiration_delay
    if rule_lifetime is not None:
        updates["rule_lifetime"] = rule_lifetime
    if big_first is not None:
        updates["big_first"] = big_first
    if dry_run is not None:
        updates["dry_run"] = dry_run
    if comments is not None:
        updates["comments"] = comments

    if not updates:
        click.echo("No updates specified.")
        return

    try:
        client.update_load_injection_plan(src_rse, dest_rse, updates)
        click.echo(f"Plan {src_rse} -> {dest_rse} updated.")
    except NoLoadInjectionPlanFound:
        raise SystemExit(f"No plan found for {src_rse} -> {dest_rse}.")


@loadinjection.command("kill")
@_SRC_RSE_OPTION
@_DEST_RSE_OPTION
@click.pass_context
def kill(ctx, src_rse, dest_rse):
    """Kill a running plan — stop injecting and remove active rules."""
    client = ctx.obj.client
    try:
        client.kill_load_injection_plan(src_rse, dest_rse)
        click.echo(f"Kill signal sent to {src_rse} -> {dest_rse}.")
    except NoLoadInjectionPlanFound:
        raise SystemExit(f"No plan found for {src_rse} -> {dest_rse}.")
