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

from rucio.client.commands.bin_legacy.rucio_admin import add_subscription, list_subscriptions, reevaluate_did_for_subscription, update_subscription
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Subscription(CommandBase):
    def module_help(self) -> str:
        return "Automate processing of specific rules, will create new rules on a schedule"

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "List all active subscriptions", "namespace": self.list_namespace},
            "update": {"call": self.update, "docs": "Update an existing subscription", "namespace": self._common_namespace},
            "add": {"call": self.add, "docs": "Create a new subscription", "namespace": self._common_namespace},
            "touch": {"call": self.touch, "docs": "Reevaluate did for subscription", "namespace": self.touch_namespace},
        }

    def usage_example(self) -> list[str]:
        return [
            "$ rucio subscription add --lifetime 2 --account jdoe --priority 1 --name jdoes_txt_files_on_datadisk  # Create a new subscription to create new rules",
            "$ rucio subscription list --account jdoe # List subscriptions for jdoe's account. Shows rules created by this subscription",
        ]

    def _common_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--name", help="Subscription name, used to identify the subscription in the place of an ID")
        parser.add_argument("--filter", help='DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')')
        parser.add_argument("--rules", dest="replication_rules", help='Replication rules (eg \'[{"copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "activity": "Functional Tests", "weight": "mou"}]\')')
        parser.add_argument("--comments", help="Comments on subscription")
        parser.add_argument("--lifetime", type=int, help="Subscription lifetime (in days)")
        parser.add_argument("-a", "--account", dest="subs_account", help="Account name")
        parser.add_argument("--priority", help="The priority of the subscription")

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--name", help="Subscription name, used to identify the subscription in the place of an ID")
        parser.add_argument("-a", "--account", dest="subs_account", help="Account name")
        parser.add_argument("--filter", help='DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')')
        parser.add_argument("--long", action="store_true", help="Show extra subscription information, including creation and expiration dates")

    def touch_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", help="List of DIDs (coma separated)", required=True)

    def list_(self):
        list_subscriptions(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        add_subscription(self.args, self.client, self.logger, self.console, self.spinner)

    def update(self):
        update_subscription(self.args, self.client, self.logger, self.console, self.spinner)

    def touch(self):
        reevaluate_did_for_subscription(self.args, self.client, self.logger, self.console, self.spinner)
