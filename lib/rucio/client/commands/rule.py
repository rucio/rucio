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

from typing import TYPE_CHECKING

from rucio.client.bin.rucio import add_rule, delete_rule, info_rule, list_rules, list_rules_history, move_rule, update_rule
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Rule(CLIClientBase):
    def parser(self, subparser: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparser)
        parser.add_argument("--did", nargs="+", help="DID(s) to apply the rule to")
        parser.add_argument("--copies", type=int, help="Number of copies", default=1)
        parser.add_argument("--rse", dest='rse_expression', help="RSE Expression")
        parser.add_argument("--rule-id", help="Rule to modify")

        # new rule
        parser.add_argument("--weight", help="RSE Weight")
        parser.add_argument("--lifetime", type=int, help="Rule lifetime (in seconds)")
        parser.add_argument("--grouping", choices=["DATASET", "ALL", "NONE"], help="Rule grouping")
        parser.add_argument("--locked", action="store_true", help="Rule locking")
        parser.add_argument("--unlocked", action="store_true", help="Set a rule as unlocked")
        parser.add_argument("--source-replica-expression", help="RSE Expression for RSEs to be considered for source replicas")
        parser.add_argument("--notify", help="Notification strategy : Y (Yes), N (No), C (Close)")
        parser.add_argument("--activity", help="Activity to be used (e.g. User, Data Consolidation)")
        parser.add_argument("--comment", help="Comment about the replication rule")
        parser.add_argument("--ask-approval", action="store_true", help="Ask for rule approval")
        parser.add_argument("--asynchronous", action="store_true", help="Create rule asynchronously")
        parser.add_argument("--delay-injection", type=int, help="Delay (in seconds) to wait before starting applying the rule. This option implies --asynchronous.")
        parser.add_argument("--account", dest='rule_account', help="The account owning the rule")
        parser.add_argument("--skip-duplicates", action="store_true", help="Skip duplicate rules")

        # remove
        parser.add_argument("--purge-replicas", action="store_true", help="Purge rule replicas")
        parser.add_argument("--delete-all", action="store_true", help="Delete all the rules, even the ones that are not owned by the account")

        # set
        parser.add_argument("--move", action="store_true", help="Duplicate a rule to a different RSE")
        parser.add_argument("--stuck", dest='state_stuck', action="store_true", help="Set state to STUCK.")
        parser.add_argument("--suspend", dest='state_suspended', action="store_true", help="Set state to SUSPENDED.")
        parser.add_argument("--cancel-requests", action="store_true", help="Cancel requests when setting rules to stuck.")
        parser.add_argument("--priority", help="Priority of the requests of the rule.", type=int)
        parser.add_argument("--child-rule-id", dest="child_rule_id", action="store", help='Child rule id of the rule. Use "None" to remove an existing parent/child relationship.')
        parser.add_argument("--boost-rule", action="store_true", help="Quickens the transition of a rule from STUCK to REPLICATING.")

        # list
        parser.add_argument("--file")
        parser.add_argument("--csv")
        parser.add_argument("--human", action='store_true')
        parser.add_argument("--transverse")
        parser.add_argument("--analyse-transfers", action="store_true")
        parser.add_argument("--traverse", action="store_true")
        parser.add_argument('--subscription', action='store_true', help='List by account and subscription name')

    def module_help(self) -> str:
        return "Interact with rules that define how replicas are distributed across RSEs"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rule --dids mock:did_1234 --rse_expression RSE-1  # Add a rule on RSE-1 that only applies to did_1234",
            f"$ {self.COMMAND_NAME} list rule --dids mock:did_1234 --rse_expression RSE-1 # List the rules that apply to did_1234",
            f"$ {self.COMMAND_NAME} set rule --rule_id rule_1234 --move --rse_expression RSE-2 # Duplicate a rule to a new RSE",
            f"$ {self.COMMAND_NAME} remove rule --rule_id rule_1234 --rse_expression RSE-2 # Delete the rule off RSE-2",
        ]

    def add(self) -> None:
        self.args.dids = self.args.did
        add_rule(self.args, self.logger)

    def remove(self):
        return delete_rule(self.args, self.logger)

    def set(self):
        if self.args.move:
            return move_rule(self.args, self.logger)
        else:
            self.args.rule_activity = self.args.activity
            return update_rule(self.args, self.logger)

    def list(self):
        if len(self.args.did) > 1:
            self.logger.debug("Using only the first did to add a tombstone - repeat this command with other DIDs to set other replica tombstones.")
        self.args.did = self.args.did[0]
        return {
            None: list_rules,
            "history": list_rules_history,
            "info": info_rule
        }[self.args.view](self.args, self.logger)
