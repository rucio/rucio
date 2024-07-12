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
from typing import TYPE_CHECKING

from rucio.client.bin.rucio_admin import add_subscription, list_subscriptions, update_subscription
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Subscription(CLIClientBase):
    PARSER_NAME = "subscription"

    def parser(self, subparser: "_SubParsersAction[ArgumentParser]"):
        parser = super().parser(subparser)

        parser.add_argument("--name", help="Subscription name")
        parser.add_argument("--filter", help='DID filter (eg \'{"scope": ["tests"], "project": ["data12_8TeV"]}\')')
        parser.add_argument("--rules", dest='replication_rules', help='Replication rules (eg \'[{"copies": 2, "rse_expression": "tier=2", "lifetime": 3600, "activity": "Functional Tests", "weight": "mou"}]\')', default="[]")
        parser.add_argument("--comments", help="Comments on subscription")
        parser.add_argument("--lifetime", type=int, help="Subscription lifetime (in days)")
        parser.add_argument("--account", dest='subs_account', help="Account name")
        parser.add_argument("--priority", help="The priority of the subscription. Note - priority can range from 1 to infinity. Internal share for given account.")

    def module_help(self) -> str:
        return "Subscription methods. The methods for automated and regular processing of some specific rules."

    def usage_example(self) -> list[str]:
        filter_ = json.dumps({"scope": ["user.jdoe"], "datatype": ["txt"]})
        rules = json.dumps([{"copies": 1, "rse_expression": "JDOE_DATADISK", "lifetime": 3600, "activity": "User Subscriptions"}])
        return [f'$ {self.COMMAND_NAME} list subscription --account jdoe --name jdoes_txt_files_on_datadisk --priority 1\n   --filter "{filter_}"\n   --rules "{rules}"\n   --comments "keeping replica on jdoes disk for 60 mins"']

    def list(self):
        return list_subscriptions(self.args, self.logger)

    def add(self):
        return add_subscription(self.args, self.logger)

    def set(self):
        return update_subscription(self.args, self.logger)
