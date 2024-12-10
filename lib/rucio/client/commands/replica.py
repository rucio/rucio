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
from rucio.client.commands.bin_legacy.rucio_admin import declare_bad_file_replicas, declare_temporary_unavailable_replicas, list_pfns, quarantine_replicas, set_tombstone
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
            "list": {"call": self.list_, "docs": "List the replicas of a DID and its PFNs", "namespace": self.list_namespace},
            "dataset": {"call": self.dataset, "docs": "List replica datasets", "namespace": self.dataset_namespace},
            "pfn": {"call": self.pfn, "docs": "Show the pfn for replicas of a DID", "namespace": self.pfn_namespace},
            "tombstone": {"call": self.tombstone, "docs": "Add a tombstone which will mark the replica as ready for deletion by a reaper daemon", "namespace": self.tombstone_namespace},
        }

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", nargs="+", action="store", help="List of space separated data identifiers.")

        parser.add_argument("--protocols", help="List of comma separated protocols (i.e. https, root, srm)", required=False)
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

    def dataset_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", nargs="+", action="store", help="List of space separated data identifiers")
        parser.add_argument("--deep", action="store_true", help="Make a deep check")
        parser.add_argument(
            "--csv",
            action="store_true",
            help="Write output to comma separated values",
        )

    def pfn_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", help="List of DIDs (coma separated)")
        parser.add_argument("-r", "--rse", help="RSE")
        parser.add_argument("--protocol", choices={"srm", "root", "http", "https", "posix", None}, default=None, help="The protocol to access pfns")

    def tombstone_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", help="DIDs to access, as comma separated values")
        parser.add_argument("-r", "--rse", help="RSE where the replica is")

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {"state": State}

    def usage_example(self) -> list[str]:
        return [
            "$ rucio replica list --did user.jdoe:test_file  # Show all replicas for user.jdoe:test_file, with their pfn and rse",
            "$ rucio replica dataset --did user.jdoe:test_dataset  # Show all replicas for the dataset user.jdoe:test_dataset"]

    def list_(self):
        list_file_replicas(self.args, self.client, self.logger, self.console, self.spinner)

    def dataset(self):
        list_dataset_replicas(self.args, self.client, self.logger, self.console, self.spinner)

    def pfn(self):
        list_pfns(self.args, self.client, self.logger, self.console, self.spinner)

    def tombstone(self):
        set_tombstone(self.args, self.client, self.logger, self.console, self.spinner)


class State(Replica):
    def module_help(self) -> str:
        return "Manage replica state."

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {}

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "suspicious": {"call": self.suspicious, "docs": "Show existing replicas marked as suspicious", "namespace": self.sus_namespace},
            "quarantine": {"call": self.quarantine, "docs": "Quarantine replicas", "namespace": self.quarantine_namespace},
            "bad": {"call": self.bad, "docs": "Declare bad replicas", "namespace": self.bad_namespace},
            "temp-unavailable": {"call": self.temp_unavailable, "docs": "Declare temporary unavailable replicas", "namespace": self.unavail_namespace},
        }

    def sus_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-r", "--rse", dest="rse", action="store", help="RSE name or expression")
        parser.add_argument("--reason", dest="reason", action="store", help="Supply a reason for changing the replica state")
        parser.add_argument("--files", dest="listbadfiles", nargs="*", help="List of items to update. Each can be a PFN (for one replica) or an LFN (for all replicas of the LFN) or a collection DID (for all file replicas in the DID)")
        parser.add_argument("--input-file", dest="inputfile", nargs="?", action="store", help="File containing list of replicas to update state")
        parser.add_argument("--younger-than", help='List files that have been marked suspicious since the date "younger_than", e.g. 2021-11-29T00:00:00')  # NOQA: E501
        parser.add_argument("--nattempts", dest="nattempts", action="store", help="Minimum number of failed attempts to access a suspicious file")

    def bad_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--files", nargs="*", dest="listbadfiles", help="List of items to update. Each can be a PFN (for one replica) or an LFN (for all replicas of the LFN) or a collection DID (for all file replicas in the DID)")
        parser.add_argument("-r", "--rse", dest="rse", action="store", help="RSE name or expression")
        parser.add_argument("--reason", dest="reason", action="store", help="Supply a reason for changing the replica state")
        parser.add_argument("--input-file", dest="inputfile", nargs="?", action="store", help="File containing list of replicas to update state")
        parser.add_argument("--allow-collection", dest="allow_collection", action="store_true", help="Allow passing a collection DID as bad item")
        parser.add_argument("--lfns", dest="lfns", nargs="?", action="store", help="File containing list of LFNs for bad replicas. Requires --rse and --scope")
        parser.add_argument("--scope", dest="scope", nargs="?", action="store", help="Common scope for bad replicas specified with LFN list, ignored without --lfns")

    def unavail_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-r", "--rse", dest="rse", action="store", help="RSE name or expression")
        parser.add_argument("--reason", dest="reason", action="store", help="Supply a reason for changing the replica state")
        parser.add_argument("--files", nargs="*", dest="listbadfiles", help="List of items to update. Each can be a PFN (for one replica) or an LFN (for all replicas of the LFN) or a collection DID (for all file replicas in the DID)")
        parser.add_argument("--input-file", dest="inputfile", nargs="?", action="store", help="File containing list of replicas to update state")
        parser.add_argument("--expiration-date", "--duration", new_option_string="--duration", dest="duration", required=True, action=StoreAndDeprecateWarningAction, type=int, help="Timeout in seconds when the replicas will become available again")  # NOQA: E501

    def quarantine_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-r", "--rse", dest="rse", action="store", help="RSE name or expression")
        parser.add_argument("--reason", dest="reason", action="store", help="Supply a reason for changing the replica state")
        parser.add_argument("--files", dest="paths_list", nargs="*", help="List of items to update. Each can be a PFN (for one replica) or an LFN (for all replicas of the LFN) or a collection DID (for all file replicas in the DID)")
        parser.add_argument("--input-file", dest="inputfile", nargs="?", action="store", help="File containing list of replicas to update state")

    def usage_example(self) -> list[str]:
        return [
            "$ rucio replica state bad --files mock:test --rse RSE  # Declare the replica of did mock:test at RSE to be bad",
            "$ rucio replica state temp-unavailable --files mock:test --rse RSE --duration 10 # Declare mock:test at RSE to be unavailable for 10 seconds",
            "$ rucio replica state quarantine --files mock:test --rse RSE  # Apply a quarantine to mock:test",
            "$ rucio replica state suspicious --rse RSE  # Show all the suspicious replicas at RSE",
        ]

    def suspicious(self):
        list_suspicious_replicas(self.args, self.client, self.logger, self.console, self.spinner)

    def quarantine(self):
        quarantine_replicas(self.args, self.client, self.logger, self.console, self.spinner)

    def bad(self):
        declare_bad_file_replicas(self.args, self.client, self.logger, self.console, self.spinner)

    def temp_unavailable(self):
        declare_temporary_unavailable_replicas(self.args, self.client, self.logger, self.console, self.spinner)
