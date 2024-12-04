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
from argparse import SUPPRESS
from typing import TYPE_CHECKING

from rucio.client.commands.bin_legacy.rucio import add_rule, delete_rule, info_rule, list_rules, list_rules_history, move_rule, update_rule
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Rule(CommandBase):
    def module_help(self) -> str:
        return "Create rules that require a number of replicas at a defined set of remote Rucio Storage Elements (RSEs). Rules will initialize transfers between sites."

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "add": {"call": self.add, "docs": "Add replication rule to define number of replicas at sites.", "namespace": self.add_namespace},
            "remove": {"call": self.remove, "docs": "Delete a replication rule. Replicas created by the rule will not be impacted unless specified to do so.", "namespace": self.remove_namespace},
            "show": {"call": self.show, "docs": "Retrieve information about a specific rule.", "namespace": self.show_namespace},
            "history": {"call": self.history, "docs": "List history of different replica rules impacting a DID", "namespace": self._common_namespace},
            "update": {"call": self.update, "docs": "Update replication rule, can be used to move a rule from one RSE to another.", "namespace": self.update_namespace},
            "list": {"call": self.list_, "docs": "List replication rules.", "namespace": self.list_namespace},
        }

    def default_operation(self):
        return self.list_

    def usage_example(self) -> list[str]:
        return [
            "$ rucio rule add -d user.jdoe:test_did --copies 2 --rse SPAINSITES  # Create a rule that requires two copies of a did limited to Spanish Cites.",
            "$ rucio rule list --did user.jdoe:test_did  # show rules impacting a DID",
            "$ rucio rule list --rule-id rule123456  # View a summary for an existing rule",
            "$ rucio rule show --rule-id rule123456  # View a detailed overview for an existing rule.",
            "$ rucio rule remove --rule-id rule123456  # Deactivate a rule",
            "$ rucio rule update --rule-id rule123456 --suspend  # Suspend the execution of a rule",
            "$ rucio rule update --rule-id rule123456 --move --rse NewRSE # Copy an existing rule to a new RSE",
        ]

    def _common_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-a", "--account", dest="rule_account", action="store", help="The account of the rule")
        parser.add_argument("--activity", action="store", help="Activity to be used (e.g. User, Data Consolidation)")  # TODO More info on this
        parser.add_argument("--rule-id", help="The rule ID, for accessing an existing rule.")
        parser.add_argument("--lifetime", dest="lifetime", action="store", type=int, help="Rule lifetime (in seconds)")
        parser.add_argument("--locked", action="store_true", help="Set the rule to locked - [WHAT IS THE CONSEQUENCE?]")  # TODO More info on this
        parser.add_argument("--source-replica-expression", help="RSE Expression for RSEs to be considered for source replicas")
        parser.add_argument("--comment", dest="comment", action="store", help="Comment about the replication rule")

    def add_namespace(self, parser: "ArgumentParser") -> None:
        self._common_namespace(parser)
        parser.add_argument("-r", "--rse", dest="rse_expression", action="store", help="The RSE expression. Must be specified if a DID is provided.")
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="DID(s) to apply the rule to")
        parser.add_argument("--copies", type=int, help="Number of copies")
        parser.add_argument("--weight", help="RSE Weight")  # TODO What does this do
        parser.add_argument("--grouping", choices=["DATASET", "ALL", "NONE"], help="Rule grouping")  # TODO What does this do
        parser.add_argument("--notify", action="store", help="Notification strategy : Y (Yes), N (No), C (Close)", choices={"Y", "N", "C"})
        parser.add_argument("--ask-approval", action="store_true", help="Ask for rule approval")
        parser.add_argument("--asynchronous", action="store_true", help="Create rule asynchronously")
        parser.add_argument("--delay-injection", type=int, help="Delay (in seconds) to wait before starting applying the rule. This option implies --asynchronous.")
        parser.add_argument("--skip-duplicates", action="store_true", help="Skip duplicate rules")

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        self._common_namespace(parser)
        parser.add_argument("--purge-replicas", action="store_true", help="Purge rule replicas")
        parser.add_argument("--all", dest="delete_all", action="store_true", default=False, help="Delete all the rules, even the ones that are not owned by the account")

    def show_namespace(self, parser: "ArgumentParser") -> None:
        self._common_namespace(parser)
        parser.add_argument("--examine", action="store_true", help="Detailed analysis of transfer errors")

    def list_namespace(self, parser: "ArgumentParser") -> None:
        self._common_namespace(parser)
        parser.add_argument("-d", "--did", help="DIDs to look for rules.")
        parser.add_argument("--traverse", action="store_true", help="Traverse the did tree and search for rules affecting this did")
        parser.add_argument("--csv", action="store_true", help="Write output to a CSV.")
        parser.add_argument("--file", help="List associated rules of an affected file")
        parser.add_argument("--subscription", help="List by account and subscription name", metavar=("ACCOUNT", "SUBSCRIPTION"), nargs=2)
        parser.add_argument("--human", default=True, help=SUPPRESS)

    def update_namespace(self, parser: "ArgumentParser") -> None:
        self._common_namespace(parser)
        parser.add_argument("-r", "--rse", dest="rse_expression", help="RSE to change for the rule.")
        parser.add_argument("--stuck", dest="state_stuck", action="store_true", help="Set state to STUCK.")
        parser.add_argument("--suspend", dest="state_suspended", action="store_true", help="Set state to SUSPENDED.")
        parser.add_argument("--cancel-requests", action="store_true", help="Cancel requests when setting rules to stuck.")
        parser.add_argument("--priority", help="Priority of the requests of the rule.")
        parser.add_argument("--child-rule-id", help='Child rule id of the rule. Use "None" to remove an existing parent/child relationship.')
        parser.add_argument("--boost-rule", action="store_true", help="Quickens the transition of a rule from STUCK to REPLICATING.")
        parser.add_argument("--move", action="store_true", help="Duplicate the existing replication rule to a different RSE.")

    def list_(self):
        list_rules(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        add_rule(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_rule(self.args, self.client, self.logger, self.console, self.spinner)

    def show(self):
        info_rule(self.args, self.client, self.logger, self.console, self.spinner)

    def history(self):
        list_rules_history(self.args, self.client, self.logger, self.console, self.spinner)

    def update(self):
        # typing issue is due to trying to map two argparser objects to one function
        # Claims you can't add new args
        self.args.rule_activity = self.args.activity
        if self.args.move:
            move_rule(self.args, self.client, self.logger, self.console, self.spinner)

        else:
            update_rule(self.args, self.client, self.logger, self.console, self.spinner)
