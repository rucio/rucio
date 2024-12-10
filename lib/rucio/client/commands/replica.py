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

from rucio.client.commands.bin_legacy.rucio import list_dataset_replicas, list_file_replicas, list_suspicious_replicas
from rucio.client.commands.bin_legacy.rucio_admin import declare_bad_file_replicas, declare_temporary_unavailable_replicas, quarantine_replicas, set_tombstone
from rucio.client.commands.command_base import CommandBase
from rucio.common.utils import StoreAndDeprecateWarningAction

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Replica(CommandBase):
    def module_help(self) -> str:
        return "Interact with a Data IDentifier at a specific Rucio Service Element"

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "List replicas for a given DID", "namespace": self.list_namespace},
            "remove": {
                "call": self.remove,
                "docs": "Set a replica for removal by adding a tombstone which will mark the replica as ready for deletion by a reaper daemon",
                "namespace": self.remove_namespace},
        }

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument(dest='dtype', choices=("file", "dataset"), help="List either the replicas of a file or a dataset (and its contents)")
        parser.add_argument("-d", "--did", dest="dids", nargs="+", action="store", help="List of space separated data identifiers.")
        parser.add_argument("--protocols", help="Protocol used to access a replicas (i.e. https, root, srm)", required=False)
        parser.add_argument(
            "--all-states",
            action="store_true",
            help="To select all replicas (including unavailable ones).\
                Also gets information about the current state of a DID in each RSE",
            required=False,
        )
        parser.add_argument("--pfns", action="store_true", help="Show only the PFNs", required=False)
        parser.add_argument("--domain", help="Force the networking domain. Available options: wan, lan, all", required=False)
        parser.add_argument(
            "--link",
            help="Symlink PFNs with directory substitution.\
                For example: rucio list-file-replicas --rse RSE_TEST --link /eos/:/eos/ scope:datasetname",
            required=False,
        )
        parser.add_argument("--missing", action="store_true", help="To list missing replicas at a RSE-Expression. Must be used with --rses option", required=False)
        parser.add_argument("--metalink", action="store_true", help="Output available replicas as metalink", required=False)
        parser.add_argument("--no-resolve-archives", action="store_true", help="Do not resolve archives which may contain the files", required=False)
        parser.add_argument("--sort", help="Replica sort algorithm. Available options: geoip (default), random", required=False)
        parser.add_argument("-r", "--rse", dest="rses", help="The RSE filter expression")
        parser.add_argument("--human", default=True, help=SUPPRESS)

        # Dataset options.
        parser.add_argument("--deep", action="store_true", help="Dataset option only: Make a deep check, checking the contents of datasets in datasets")
        parser.add_argument(
            "--csv",
            action="store_true",
            help="Dataset option only: Write output to comma separated values",
        )

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", help="DIDs to access, as comma separated values")
        parser.add_argument("-r", "--rse", help="RSE where the replica is")

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {"state": State}

    def usage_example(self) -> list[str]:
        return [
            "$ rucio replica list file --did user.jdoe:test_file  # Show all replicas for user.jdoe:test_file, with their pfn and rse",
            "$ rucio replica list dataset --did user.jdoe:test_dataset  # Show all replicas for the dataset user.jdoe:test_dataset",
            "$ rucio replica list file --did user.jdoe:test_file --pfns  # Show the PFNs for replicas of user.jdoe:test_file",
            "$ rucio replica remove --did user.jdoe:test_file --rse MyRSE  # Mark a replica for deletion by a reaper daemon"
        ]

    def list_(self):
        if self.args.dtype == "file":
            list_file_replicas(self.args, self.client, self.logger, self.console, self.spinner)

        elif self.args.dtype == "dataset":
            list_dataset_replicas(self.args, self.client, self.logger, self.console, self.spinner)
        else:
            raise NotImplementedError("Only 'file' and 'dataset' are listable")

    def remove(self):
        set_tombstone(self.args, self.client, self.logger, self.console, self.spinner)


class State(Replica):
    def module_help(self) -> str:
        return "Manage replica state."

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "List replicas filtered by state (implemented: (suspicious))", "namespace": self.list_namespace},
            "update": {"call": self.update, "docs": "Update the state of a replica. (implemented: (list as (bad, quarantined, or temporarily unavailable)))", "namespace": self.update_namespace},
        }

    def list_namespace(self, parser: "ArgumentParser"):
        parser.add_argument("state_type", choices=("suspicious",), help="State to filter by when listing")
        parser.add_argument("-r", "--rse", dest="rse", action="store", help="RSE name or expression")
        parser.add_argument("--younger-than", help='List files that have been marked suspicious since the date "younger_than", e.g. 2021-11-29T00:00:00')  # NOQA: E501
        parser.add_argument("--nattempts", dest="nattempts", action="store", help="Minimum number of failed attempts to access a suspicious file")

    def update_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("state_type", choices=("bad", "unavailable", "quarantine"))

        parser.add_argument("--files", nargs="*", dest="files", help="List of items to update. Each can be a PFN (for one replica) or an LFN (for all replicas of the LFN) or a collection DID (for all file replicas in the DID)")
        parser.add_argument("-r", "--rse", dest="rse", action="store", help="RSE name or expression")
        parser.add_argument("--input-file", dest="inputfile", nargs="?", action="store", help="File containing list of replicas to update state")

        parser.add_argument("--reason", dest="reason", action="store", help="Supply a reason for changing the replica state")

        bad_parser = parser.add_argument_group("Bad")
        bad_parser.add_argument("--lfns", dest="lfns", nargs="?", action="store", help="File containing list of LFNs for bad replicas. Requires --rse and --scope")
        bad_parser.add_argument("--scope", dest="scope", nargs="?", action="store", help="Common scope for bad replicas specified with LFN list, ignored without --lfns")

        unavailable_parser = parser.add_argument_group("Unavailable")
        unavailable_parser.add_argument("--expiration-date", "--duration", new_option_string="--duration", dest="duration", action=StoreAndDeprecateWarningAction, type=int, help="Timeout in seconds when the replicas will become available again")  # NOQA: E501

        parser.add_argument_group("Quarantine")

    def usage_example(self) -> list[str]:
        return [
            "$ rucio replica state update bad --files mock:test --rse RSE  # Declare the replica of did mock:test at RSE to be bad",
            "$ rucio replica state update unavailable --files mock:test --rse RSE --duration 10 # Declare mock:test at RSE to be unavailable for 10 seconds",
            "$ rucio replica state update quarantine --files mock:test --rse RSE  # Apply a quarantine to mock:test",
            "$ rucio replica state list suspicious --rse RSE  # Show all the suspicious replicas at RSE",
        ]

    def list_(self):
        list_suspicious_replicas(self.args, self.client, self.logger, self.console, self.spinner)

    def update(self):
        if self.args.state_type == "bad":
            self.args.listbadfiles = self.args.files
            declare_bad_file_replicas(self.args, self.client, self.logger, self.console, self.spinner)
        elif self.args.state_type == "unavailable":
            self.args.listbadfiles = self.args.files
            if not hasattr(self.args, "duration"):
                raise ValueError("Missing argument '--expiration-date/--duration")

            declare_temporary_unavailable_replicas(self.args, self.client, self.logger, self.console, self.spinner)
        elif self.args.state_type == "quarantine":
            self.args.paths_list = self.args.files
            quarantine_replicas(self.args, self.client, self.logger, self.console, self.spinner)

        else:
            raise NotImplementedError
