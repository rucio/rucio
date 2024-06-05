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
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, Union

from rucio.client.rcom.base_command import CLIClientBase
from rucio.client.rcom.utils import get_dids, get_scope
from rucio.common.exception import DuplicateRule

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Rule(CLIClientBase):
    def parser(self, subparser: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparser)
        parser.add_argument("--dids", nargs="+", help="DID(s) to apply the rule to")
        parser.add_argument("--copies", type=int, help="Number of copies", default=1)
        parser.add_argument("--rse-expression", help="RSE Expression")
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
        parser.add_argument("--account", help="The account owning the rule")
        parser.add_argument("--skip-duplicates", action="store_true", help="Skip duplicate rules")

        # remove
        parser.add_argument("--purge-replicas", action="store_true", help="Purge rule replicas")
        parser.add_argument("--delete-all", action="store_true", help="Delete all the rules, even the ones that are not owned by the account")

        # set
        parser.add_argument("--move", action="store_true", help="Duplicate a rule to a different RSE")
        parser.add_argument("--stuck", action="store_true", help="Set state to STUCK.")
        parser.add_argument("--suspend", action="store_true", help="Set state to SUSPENDED.")
        parser.add_argument("--cancel-requests", action="store_true", help="Cancel requests when setting rules to stuck.")
        parser.add_argument("--priority", help="Priority of the requests of the rule.", type=int)
        parser.add_argument("--child-rule-id", dest="child_rule_id", action="store", help='Child rule id of the rule. Use "None" to remove an existing parent/child relationship.')
        parser.add_argument("--boost-rule", action="store_true", help="Quickens the transition of a rule from STUCK to REPLICATING.")

        # list
        parser.add_argument("--file")
        parser.add_argument("--transverse")
        parser.add_argument("--analyse-transfers", action="store_true")
        parser.add_argument("--info", action="store_true")
        parser.add_argument("--traverse", action="store_true")

    def module_help(self) -> str:
        return "Interact with rules that define how replicas are distributed across RSEs"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} add rule --dids mock:did_1234 --rse_expression RSE-1  # Add a rule on RSE-1 that only applies to did_1234",
            f"$ {self.COMMAND_NAME} list rule --dids mock:did_1234 --rse_expression RSE-1 # List the rules that apply to did_1234",
            f"$ {self.COMMAND_NAME} set rule --rule_id rule_1234 --move --rse_expression RSE-2 # Duplicate a rule to a new RSE",
            f"$ {self.COMMAND_NAME} remove rule --rule_id rule_1234 --rse_expression RSE-2 # Delete the rule off RSE-2",
        ]

    def _make_rule(self, dids: Sequence[dict[str, str]]) -> list:
        rule_ids = self.client.add_replication_rule(
            dids=dids,
            copies=self.args.copies,
            rse_expression=self.args.rse_expression,
            weight=self.args.weight,
            lifetime=self.args.lifetime,
            grouping=self.args.grouping,
            account=self.args.account,
            locked=self.args.locked,
            source_replica_expression=self.args.source_replica_expression,
            notify=self.args.notify,
            activity=self.args.activity,
            comment=self.args.comment,
            ask_approval=self.args.ask_approval,
            asynchronous=self.args.asynchronous,
            delay_injection=self.args.delay_injection,
        )
        return rule_ids

    def add(self) -> Optional[Union[list, dict]]:
        dids = get_dids(self.args.dids, self.client)
        try:
            rules = {"rule_id": self._make_rule(dids)}
        except DuplicateRule as error:
            rules = []
            if self.args.ignore_duplicate:
                self.logger.debug("Duplicate rules detected - trying again.")
                for did in dids:
                    try:
                        rule = self._make_rule([did])
                        rules.append(rule)
                    except DuplicateRule:
                        self.logger.info(f"Ignoring {did['scope']}:{did['name']}, duplicate rule found.")
            else:
                raise error
        return rules

    def remove(self) -> None:
        try:
            # Test if the rule_id is a real rule_id
            uuid.UUID(self.args.rule_id)
            self.client.delete_replication_rule(rule_id=self.args.rule_id, purge_replicas=self.args.purge_replicas)
        except ValueError:
            # Otherwise, trying to extract the scope, name from args.rule_id
            if (self.args.rse_expression is None) or (self.args.dids is None):
                raise ValueError("A RSE expression and DID must be specified if you do not provide a rule_id.")

            scope, name = get_scope(self.args.dids, self.client)
            rules = self.client.list_did_rules(scope=scope, name=name)

            account = self.args.account if self.args.account is not None else self.client.account
            deletion_success = False

            for rule in rules:
                account_checked = True if self.args.delete_all else rule["account"] == account
                if rule["rse_expression"] == self.args.rse_expression and account_checked:
                    self.client.delete_replication_rule(rule_id=rule["id"], purge_replicas=self.args.purge_replicas)
                    self.logger.info(f"Removed rule {rule['id']} from {self.args.rse_expression} with account {account}.")
                    deletion_success = True

            if not deletion_success:
                # TODO Rucio error instead
                raise RuntimeError("No replication rule was deleted from the DID")

    def set(self) -> None:
        if self.args.rule_id is None:
            raise ValueError("Can only modify rules by rule_id.")

        override_options = {}
        # Only options for moving
        if self.args.activity:
            override_options["activity"] = self.args.activity
        if self.args.source_replica_expression:
            override_options["source_replica_expression"] = None if self.args.source_replica_expression.lower() == "none" else self.args.source_replica_expression

        if self.args.move:
            self.client.move_replication_rule(rule_id=self.args.rule_id, rse_expression=self.args.rse_expression, override=override_options)
            self.logger.info(f"Successfully moved rule {self.args.rule_id} to {self.args.rse_expression}")
            return None  # TODO is it okay to continue to modify the rule after its been moved?

        args_dict = vars(self.args)

        # The ones that can have an explicit "None"
        for key in ["child_rule_id", "lifetime"]:
            if args_dict[key] is not None:
                override_options[key] = None if args_dict[key].lower() == "none" else args_dict[key]

        # The ones that are only set if they're not None
        for key in ["comment", "account", "priority", "boost_rule"]:
            if args_dict[key] is not None:
                override_options[key] = args_dict[key]

        # And the other ones (booleans)
        if self.args.locked or self.args.unlocked:
            override_options["locked"] = True if not self.args.unlocked else False

        if (self.args.stuck) or (self.args.suspended):
            override_options["state"] = "STUCK" if self.args.stuck else "SUSPENDED"

        if self.args.cancel_requests:
            if "state" not in override_options:
                raise ValueError("--cancel-requests can only be used when setting rules as stuck or suspended (with --stuck or --suspended)")
            override_options["cancel_requests"] = True

        self.client.update_replication_rule(rule_id=self.args.rule_id, options=override_options)

    def list(self) -> Optional[list[dict]]:
        if self.args.analyse_transfers:
            if self.args.rule_id is None:
                raise ValueError("Must supply a rule id to view transfers for that rule")
            analysis = self.client.examine_replication_rule(rule_id=self.args.rule_id)
            rules = []
            try:
                for transfer in analysis["transfers"]:
                    rules.append(transfer)
            except KeyError:
                self.logger.info(f"No transfers for {self.args.rule_id}")
                return None

        elif self.args.info or (self.args.rule_id is not None):
            rules = self.client.get_replication_rule(rule_id=self.args.rule_id)

        elif self.args.file is not None:
            scope, name = get_scope(self.args.file, self.client)
            rules = self.client.list_associated_rules_for_file(scope=scope, name=name)

        elif self.args.dids is not None:
            for did in self.args.dids:
                if self.args.traverse:
                    locks = self.client.get_dataset_locks(scope=scope, name=name)
                    rules = []
                    for rule_id in list(set([lock["rule_id"] for lock in locks])):
                        for rule in self.client.get_replication_rule(rule_id):
                            rules.append(rule)

                else:
                    scope, name = get_scope(did, self.client)
                    meta = self.client.get_metadata(scope=scope, name=name)
                    rules = self.client.list_did_rules(scope=scope, name=name)

                    try:
                        next(rules)
                        rules = self.client.list_did_rules(scope=scope, name=name)
                    except StopIteration:
                        rules = []
                        # looking for other rules
                        if meta["did_type"] == "CONTAINER":
                            for dsn in self.client.list_content(scope, name):
                                rules.extend(self.client.list_did_rules(scope=dsn["scope"], name=dsn["name"]))
                            if rules:
                                self.logger.info("No rules found, listing rules for content")
                        if meta["did_type"] == "DATASET":
                            for container in self.client.list_parent_dids(scope, name):
                                rules.extend(self.client.list_did_rules(scope=container["scope"], name=container["name"]))
                            if rules:
                                self.logger.info("No rules found, listing rules for parents")

        elif self.args.account is not None:
            rules = self.client.list_account_rules(account=self.args.account)

        elif self.args.subscription is not None:
            account = self.args.subscription[0]
            name = self.args.subscription[1]
            rules = self.client.list_subscription_rules(account=account, name=name)

        else:
            raise ValueError("Cannot get rules - provide one of the following arguments: (account, analyse_transfers, dids, file, info, subscription.)")

        return [rule for rule in rules]
