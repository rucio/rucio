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


from argparse import SUPPRESS, ArgumentParser, _SubParsersAction

from rucio.client.bin.rucio import list_dataset_replicas, list_file_replicas, list_suspicious_replicas
from rucio.client.bin.rucio_admin import declare_bad_file_replicas, declare_temporary_unavailable_replicas, list_pfns, quarantine_replicas, set_tombstone
from rucio.client.commands.base_command import CLIClientBase


class Replica(CLIClientBase):
    SUBCOMMAND_NAMES = ["pfn", "state", "tombstone"]

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)

        parser.add_argument(
            '--all-states',
            action='store_true',
            help='To select all replicas (including unavailable ones). Also gets information about the current state of a DID in each RSE.'
        )
        parser.add_argument("--replica-type", choices=["file", "container", "dataset"], default="file")
        parser.add_argument("--protocols", dest="protocols", action="store", help="List of comma separated protocols. (i.e. https, root, srm).")
        parser.add_argument("--dids", nargs="+", help="List of space separated data identifiers.", default=[])
        parser.add_argument("--domain", help="Force the networking domain.", choices=["wan", "lan", "all"], default="all")
        parser.add_argument("--missing", help="To list missing replicas at a RSE-Expression. Must be used with --rses option")
        parser.add_argument("--metalink", help="Output available replicas as metalink.")
        parser.add_argument("--no-resolve-archives", help="Do not resolve archives which may contain the files.")
        parser.add_argument("--sort", help="Replica sort algorithm.", default="geoip", choices=["geoip,", "random"])
        parser.add_argument("--rse", dest='rses', help="The RSE filter expression.")
        parser.add_argument("--deep", action="store_true", help="When listing datasets or containers, list the nested contents.")
        parser.add_argument("--monotonic", action="store_true", help="Monotonic status to True.")
        parser.add_argument("--lifetime", action="store", type=int, help="Lifetime in seconds.")
        parser.add_argument("--csv", action='store_true', help="Dump results to a csv output.")
        parser.add_argument('--human', action='store_true', default=True, help=SUPPRESS)
        parser.add_argument("--pfns", help=SUPPRESS)

        # Add the subcommands
        parser.add_argument("subcommand", nargs="?", choices=self.SUBCOMMAND_NAMES, default=None)
        ReplicaPFN(client=None, args=None, logger=None).parser(parser)  # type: ignore
        ReplicaState(client=None, args=None, logger=None).parser(parser)  # type: ignore
        ReplicaTombstone(client=None, args=None, logger=None).parser(parser)  # type: ignore

    def module_help(self) -> str:
        return f"Change the Rucio catalogue of replicas. \nSubcommands: {self.SUBCOMMAND_NAMES}"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} list replica  --replica-type dataset --dids mock:dataset_12345 --rse RSE-T0 # List the contents of the dataset",
        ]

    def list(self) -> None:
        if self.args.replica_type == "file":
            list_file_replicas(self.args, self.logger)
        elif self.args.replica_type == "dataset":
            list_dataset_replicas(self.args, self.logger)
        else:
            raise NotImplementedError


class ReplicaPFN(CLIClientBase):
    PARSER_NAME = "pfn"

    def module_help(self) -> str:
        return "View the pfn of a replica."

    def usage_example(self) -> list[str]:
        list_exp = f"$ {self.COMMAND_NAME} list replica {self.PARSER_NAME} --dids mock:file --rse TEST-RSE     # View the pfn's of mock:file on TEST-RSE"
        return [list_exp]

    def parser(self, subparser: "ArgumentParser") -> None:
        pfn_parser = self.subcommand_parser(subparser)
        pfn_parser.add_argument("--link", help="Symlink PFNs with directory substitution.")

    def list(self):
        if len(self.args.dids) > 1:
            self.logger.debug("Using only the first did to get pfns.")
        self.args.dids = self.args.dids[0]
        self.args.rse = self.args.rses
        self.args.protocol = self.args.protocols
        return list_pfns(self.args, self.logger)


class ReplicaState(CLIClientBase):
    PARSER_NAME = "state"

    def module_help(self) -> str:
        return "Modify a replica's state or view a replica by specific state."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} set replica state --bad --dids mock:did_12345 --rse RSE-T0 # Mark a replica as bad", f"$ {self.COMMAND_NAME} list replica state --suspicious --rse RSE-T0 # List suspicious replicas at an RSE"]

    def parser(self, subparser: "ArgumentParser") -> None:
        state_parser = self.subcommand_parser(subparser)

        state_parser.add_argument("--suspicious", action="store_true", help="List or set a suspicious replica")
        state_parser.add_argument("--bad", action="store_true", help="List or set a bad replica")
        state_parser.add_argument("--temporary-unavailable", action="store_true", help="List or set replicas as temporarily unavailable")
        state_parser.add_argument("--quarantine", action="store_true", help="")

        state_parser.add_argument("--pfn", help="Use a pfn instead of DID", action="store_true")
        state_parser.add_argument("--lfn", dest='lfns', help="Use a lfn instead of DID", action="store_true")
        state_parser.add_argument("--input-file", dest='inputfile', help="Supply an input .txt file to declare")
        state_parser.add_argument("--scope", help="Scope for pfn or lfn-identified replicas.")

        state_parser.add_argument("--younger_than")
        state_parser.add_argument("--n_attempts")
        state_parser.add_argument("--reason")
        state_parser.add_argument("--duration", help='How long temporarily unavailable will be unavailable. (Required)', type=int)
        state_parser.add_argument('--paths_file', help='file of paths of quarantine')

    def set(self) -> None:
        self.args.listbadfiles = self.args.dids
        if self.args.bad:
            declare_bad_file_replicas(self.args, self.logger)
        elif self.args.temporary_unavailable:
            declare_temporary_unavailable_replicas(self.args, self.logger)
        elif self.args.quarantine:
            self.args.paths_list = self.args.dids
            self.args.rse = self.args.rses
            quarantine_replicas(self.args, self.logger)
        else:
            raise NotImplementedError("Cannot set other states through cli.")

    def list(self) -> None:
        if self.args.suspicious:
            list_suspicious_replicas(self.args, self.logger)
        else:
            raise NotImplementedError("Can only list suspicious replicas through cli.")


class ReplicaTombstone(CLIClientBase):
    PARSER_NAME = "tombstone"

    def module_help(self) -> str:
        return "Add a tombstone for a list of replicas."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add replica tombstone --dids mock:file --rse MOCK"]

    def parser(self, subparser: "ArgumentParser") -> None:
        self.subcommand_parser(subparser)

    def add(self):
        self.args.rse = self.args.rses
        if len(self.args.dids) > 1:
            self.logger.debug("Using only the first did to add a tombstone - repeat this command with other DIDs to set other replica tombstones.")
        self.args.dids = self.args.dids[0]
        return set_tombstone(self.args, self.logger)
