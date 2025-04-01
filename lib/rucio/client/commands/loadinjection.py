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

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from rucio.client.richclient import get_cli_config
from rucio.client.commands.command import get_client
from rucio.client.commands.command_base import CommandBase
from rucio.common.exception import NoLoadInjectionPlanFound

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from rucio.client.commands.utils import OperationDict

cli_config = get_cli_config()

plan_parameters = [
    {
        "name_or_flags": ["--csv", "--csv-file", "--file"],
        "kwargs": {"type": str, "help": "Plans configuration file in a csv file."},
    },
    {
        "name_or_flags": ["--src-rse", "--src"],
        "kwargs": {"type": str, "help": "Source RSE name, default is None."},
    },
    {
        "name_or_flags": ["--dest-rse", "--dest", "--des", "--dst"],
        "kwargs": {"type": str, "help": "Destination RSE name, default in None."},
    },
    {
        "name_or_flags": ["--inject-rate", "--rate", "--mbps"],
        "kwargs": {
            "type": int,
            "default": 200,
            "help": "Rate of the injection in Mbps, default is 200.",
        },
    },
    {
        "name_or_flags": ["--start-time", "--start"],
        "kwargs": {
            "type": str,
            "default": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "help": "Start time (UTC) of the injection in format YYYY-MM-DD HH:MM:SS, default is now.",
        },
    },
    {
        "name_or_flags": ["--end-time", "--end"],
        "kwargs": {
            "type": str,
            "default": (datetime.utcnow() + timedelta(hours=2)).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "help": "End time (UTC) of the injection in format YYYY-MM-DD HH:MM:SS, default is now + 2 hours.",
        },
    },
    {
        "name_or_flags": ["--comments", "--comment"],
        "kwargs": {
            "type": str,
            "default": "Data injection plans",
            "help": 'Comments for the injection, default is "Data injection plans".',
        },
    },
    {
        "name_or_flags": ["--interval", "--time-interval"],
        "kwargs": {
            "type": int,
            "default": 900,
            "help": "Interval of each time injection in seconds, default is 900.",
        },
    },
    {
        "name_or_flags": ["--fudge", "--fudge-factor"],
        "kwargs": {
            "type": float,
            "default": 0.0,
            "help": "Fudge factor for the injection, default is 0.0.",
        },
    },
    {
        "name_or_flags": ["--max-injection", "--max"],
        "kwargs": {
            "type": float,
            "default": 0.2,
            "help": "Max injection rate, default is 0.2.",
        },
    },
    {
        "name_or_flags": ["--expiration-delay", "--delay"],
        "kwargs": {
            "type": int,
            "default": 1800,
            "help": "Expiration delay in seconds, default is 1800.",
        },
    },
    {
        "name_or_flags": ["--rule-lifetime", "--lifetime"],
        "kwargs": {
            "type": int,
            "default": 3600,
            "help": "Rule lifetime in seconds, default is 3600.",
        },
    },
    {
        "name_or_flags": ["--big-first"],
        "kwargs": {
            "action": "store_true",
            "help": "Big containers get injected in first.",
        },
    },
    {
        "name_or_flags": ["--dry-run", "--dryrun"],
        "kwargs": {
            "action": "store_true",
            "help": "Dry run, do not submit the injection.",
        },
    },
    {
        "name_or_flags": ["--test"],
        "kwargs": {
            "action": "store_true",
            "help": "Test your plans if they are correct.",
        },
    },
]


class LoadInjection(CommandBase):
    def module_help(self) -> str:
        return "Methods to add or update load injection plans."

    def usage_example(self) -> list[str]:
        return [
            "$ rucio loadinjection add --csv CSV_FILE",
            "$ rucio loadinjection list",
            "$ rucio loadinjection info --src-rse SRC_RSE --dest-rse DEST_RSE",
            "$ rucio loadinjection remove --src-rse SRC_RSE --dest-rse DEST_RSE",
        ]

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument(
            "--state",
            "--status",
            dest="state",
            action="store",
            type=str,
            help="State of the plan, default is None.",
            required=False,
        )
        parser.add_argument(
            "--src-rse",
            "--src",
            dest="src_rse",
            action="store",
            type=str,
            help="Source RSE name, default is None.",
            required=False,
        )
        parser.add_argument(
            "--dest-rse",
            "--dest",
            "--des",
            "--dst",
            dest="dest_rse",
            action="store",
            type=str,
            help="Destination RSE name, default in None.",
            required=False,
        )

    def add_namespace(self, parser: "ArgumentParser") -> None:
        for parameter in plan_parameters:
            parser.add_argument(*parameter["name_or_flags"], **parameter["kwargs"])

    def info_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument(
            "--src-rse",
            "--src",
            dest="src_rse",
            action="store",
            type=str,
            help="Source RSE name, default is None.",
            required=False,
        )
        parser.add_argument(
            "--dest-rse",
            "--dest",
            "--des",
            "--dst",
            dest="dest_rse",
            action="store",
            type=str,
            help="Destination RSE name, default in None.",
            required=False,
        )

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument(
            "--src-rse",
            "--src",
            dest="src_rse",
            action="store",
            type=str,
            help="Source RSE name, default is None.",
            required=False,
        )
        parser.add_argument(
            "--dest-rse",
            "--dest",
            "--des",
            "--dst",
            dest="dest_rse",
            action="store",
            type=str,
            help="Destination RSE name, default in None.",
            required=False,
        )

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {
                "call": self.list_,
                "docs": "List plans.",
                "namespace": self.list_namespace,
            },
            "add": {
                "call": self.add,
                "docs": "Add a new plan.",
                "namespace": self.add_namespace,
            },
            "info": {
                "call": self.info,
                "docs": "Get detailed information of a plan.",
                "namespace": self.info_namespace,
            },
            "remove": {
                "call": self.remove,
                "docs": "Remove a plan.",
                "namespace": self.remove_namespace,
            },
        }

    def add(self) -> None:
        client = get_client(self.args, self.logger)

        plans = list()
        if not self.args.csv:
            if not self.args.src_rse or not self.args.dest_rse:
                self.logger.error(
                    '"--src-rse" and "--dest-src" are mandatory if you don\'t use "--csv".'
                )
                return None
            plan = dict()
            for parameter in plan_parameters:
                key = parameter["name_or_flags"][0].strip("-").replace("-", "_")
                plan[key] = getattr(self.args, key)
            plans.append(plan)
        else:
            plans = self._normalize_csv(self.args.csv)
            for plan in plans:
                for parameter in plan_parameters:
                    key = parameter["name_or_flags"][0].strip("-").replace("-", "_")
                    if key not in plan:
                        plan[key] = getattr(self.args, key)

        if self.args.test:
            pass
        else:
            client.add_load_injection_plans(plans)

    def list_(self) -> None:
        client = get_client(self.args, self.logger)

        plans = client.list_load_injection_plans()
        filter = dict()
        if self.args.state:
            filter["state"] = self.args.state
        if self.args.src_rse:
            filter["src_rse"] = self.args.src_rse
        if self.args.dest_rse:
            filter["dest_rse"] = self.args.dest_rse

        result = list()
        for plan in plans:
            if filter:
                for key, value in filter.items():
                    if plan[key] != value:
                        break
                    else:
                        continue
                else:
                    result.append(plan)
            else:
                result.append(plan)

        if len(result) == 0:
            raise NoLoadInjectionPlanFound()
        print(result)

    def info(self) -> None:
        client = get_client(self.args, self.logger)

        result = client.info_load_injection_plan(self.args.src_rse, self.args.dest_rse)

        for i in result:
            print(i)

    def remove(self) -> None:
        client = get_client(self.args, self.logger)

        if not self.args.src_rse or not self.args.dest_rse:
            self.logger.error('"--src-rse" and "--dest-src" are mandatory.')
            return None
        else:
            client.remove_load_injection_plan(self.args.src_rse, self.args.dest_rse)

    def _normalize_csv(self, csvfile: str) -> list[dict[str, Any]]:
        """Normalize the csv file."""

        def get_normalized_key_value(key: str, value: str) -> tuple[str, Any]:
            key = key.strip(" -").lower().replace("_", "-")
            for parameter in plan_parameters:
                for p in parameter["name_or_flags"]:
                    if p.strip("-") == key:
                        return parameter["name_or_flags"][0].strip("-"), parameter[
                            "kwargs"
                        ]["type"](value)
            self.logger.error(f'key "{key}" is not supported.')
            return key, value

        plans = list()
        with open(csvfile, "r") as f:
            import csv

            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                plan = dict()
                for key, value in row.items():
                    key, value = get_normalized_key_value(key, value)
                    plan[key] = value
                plans.append(plan)

        return plans

    def _format_plan_list(self, plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Format plan list to user readable format."""
        return plans

    def _format_plan_info(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Format plan info to user readable format."""
        return plan
