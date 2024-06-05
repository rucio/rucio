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
from typing import TYPE_CHECKING, Any

from rucio.client.rcom.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Subscription(CLIClientBase):
    PARSER_NAME = "subscription"

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]"):
        parser = super().parser(subparser)

        parser.add_argument("--name", help="Subscription name")
        parser.add_argument("--filter", help='DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')')
        parser.add_argument("--replication-rules", help='Replication rules (eg \'[{"copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "activity": "Functional Tests", "weight": "mou"}]\')', default="[]")
        parser.add_argument("--comments", help="Comments on subscription")
        parser.add_argument("--lifetime", type=int, help="Subscription lifetime (in days)")
        parser.add_argument("--account", action="store", help="Account name")
        parser.add_argument("--priority", help="The priority of the subscription. Note - priority can range from 1 to infinity. Internal share for given account.")

    def module_help(self) -> str:
        return "Subscription methods. The methods for automated and regular processing of some specific rules."

    def usage_example(self) -> list[str]:
        filter_ = json.dumps({"scope": ["user.jdoe"], "datatype": ["txt"]})
        rules = json.dumps([{"copies": 1, "rse_expression": "JDOE_DATADISK", "lifetime": 3600, "activity": "User Subscriptions"}])
        return [f'$ {self.COMMAND_NAME} subscription list --account jdoe --name jdoes_txt_files_on_datadisk --priority 1\n   --filter "{filter_}"\n   --rules "{rules}"\n   --comments "keeping replica on jdoes disk for 60 mins"']

    def _get_account(self) -> str:
        if self.args.account is not None:
            account = self.args.account
        else:
            account = str(self.client.account)  # Done to make typing stop complaining
        return account

    def list(self) -> list[dict[str, Any]]:
        account = self._get_account()
        subscriptions = self.client.list_subscriptions(name=self.args.name, account=account)
        all_subscriptions = [sub for sub in subscriptions]
        return all_subscriptions

    def add(self) -> None:
        account = self._get_account()
        subscription_id = self.client.add_subscription(
            name=self.args.name,
            account=account,
            filter_=json.loads(self.args.filter),
            replication_rules=json.loads(self.args.replication_rules),
            comments=self.args.comments,
            lifetime=self.args.lifetime,
            retroactive=False,
            dry_run=False,
            priority=self.args.priority,
        )
        self.logger.info(f"Subscription {self.args.name} added with ID: {subscription_id}.")

    def set(self) -> None:
        account = self._get_account()
        self.client.update_subscription(
            name=self.args.name,
            account=account,
            filter_=json.loads(self.args.filter),
            replication_rules=json.loads(self.args.replication_rules),
            comments=self.args.comments,
            lifetime=self.args.lifetime,
            retroactive=False,
            dry_run=False,
            priority=self.args.priority,
        )
        self.logger.info(f"Subscription {self.args.name} updated.")
