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

from rucio.client.bin.rucio import add_container, add_dataset, attach, delete_metadata, detach, get_metadata, list_content_history, list_dids, list_parent_dids, set_metadata
from rucio.client.bin.rucio_admin import import_data
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class DID(CLIClientBase):
    SUBCOMMAND_NAMES = ["history", "metadata", "attachment"]

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)

        parser.add_argument("--did", help="Data IDentifier pattern, format {scope}:{did name}", default="*:*")
        parser.add_argument("--filter", help="Filter arguments in form `key=value,another_key=next_value`. Valid keys are name, type.")
        parser.add_argument("--recursive", action="store_true", help="List data identifiers recursively.")
        parser.add_argument("--stat", action="store_true", help="Provide stats for the listed DIDs")
        parser.add_argument("--type", dest="type_", help="Type of DID", choices={"dataset", "file", "container"}, default="file")
        parser.add_argument("--lifetime", help="Lifetime in seconds", type=float)
        parser.add_argument("--undo", action="store_true", help="Undo erase DIDs. Only works if has been less than 24 hours since erase operation.")
        parser.add_argument('--short', action='store_true', help='Just dump the list of DIDs.')
        parser.add_argument('--file_path', help='File path when importing single did.')

        # Add the subcommands
        parser.add_argument("subcommand", nargs="?", choices=self.SUBCOMMAND_NAMES, default=None)
        DIDHistory(client=None, args=None, logger=None).parser(parser)  # type: ignore
        DIDMetadata(client=None, args=None, logger=None).parser(parser)  # type: ignore
        DIDAttachment(client=None, args=None, logger=None).parser(parser)  # type: ignore

    def usage_example(self) -> list[str]:
        list_cmd = f"$ {self.COMMAND_NAME} list did --did mock:data  # List all DIDS in the dataset mock:data"
        stat_cmd = f"$ {self.COMMAND_NAME} list did --did mock:data  --stat  # Provide attributes and statuses for mock:data"
        add_container_cmd = f"$ {self.COMMAND_NAME} add did --type container --did scope:name  # Make a new container"
        add_dataset_cmd = f"$ {self.COMMAND_NAME} add did --type dataset --did scope:name  # Make a new dataset"
        erase_cmd = f"$ {self.COMMAND_NAME} remove did --did mock:scope   # Mark a DID for deletion in the next 24 hours"

        examples = [list_cmd, stat_cmd, add_container_cmd, add_dataset_cmd, erase_cmd]
        return examples

    def module_help(self) -> str:
        return f"Add different types of Data Identifiers, list existing Data Identifiers and their contents. Subcommands: {[command for command in self.SUBCOMMAND_NAMES if command is not None]}"

    def list(self):
        self.args.did = [self.args.did]
        return list_dids(self.args, self.logger)

    def add(self) -> None:
        {
            "file": import_data,
            "dataset": add_dataset,
            "container": add_container
        }[self.args.type_](self.args, self.logger)


class DIDHistory(CLIClientBase):
    PARSER_NAME = "history"

    def parser(self, subparser: "ArgumentParser") -> None:
        self.subcommand_parser(subparser)
        # TODO Add did as a secondary argument here

    def module_help(self) -> str:
        return "List the content history of a collection."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} list did history --did mock:dataset_12345 # List the content history of the dataset"]

    def list(self):
        self.args.dids = [self.args.did]
        return list_content_history(self.args, self.logger)


class DIDMetadata(CLIClientBase):
    PARSER_NAME = "metadata"

    def parser(self, subparser: "ArgumentParser"):
        metadata_parser = self.subcommand_parser(subparser)
        metadata_parser.add_argument("--plugin", help="Plugin to use with metadata operations.")
        metadata_parser.add_argument("--key", help="Key to update.")
        metadata_parser.add_argument("--value", help="Value to add to metadata key.")

    def module_help(self) -> str:
        return "View or modify Data Identifier metadata."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} list did metadata --did mock:did_12345 --plugin metadata_columns", f"$ {self.COMMAND_NAME} set did metadata --did mock:did_12345 --key upload_date --value 12:30:1969"]

    def set(self):
        self.args.dids = [self.args.did]
        return set_metadata(self.args, self.logger)

    def unset(self):
        self.args.dids = [self.args.did]

        return delete_metadata(self.args, self.logger)

    def list(self):
        self.args.dids = [self.args.did]

        return get_metadata(self.args, self.logger)


class DIDAttachment(CLIClientBase):
    PARSER_NAME = "attachment"

    def parser(self, subparser: "ArgumentParser") -> None:
        attachment_parser = self.subcommand_parser(subparser)

        attachment_parser.add_argument("--target", help="Target to attach/detach a DID to/from - must be a Dataset or Container")

        # For List
        attachment_parser.add_argument("--parent", action="store_true", help="View info about a DID parent")
        attachment_parser.add_argument("--child", action="store_true", help="View contents of a DID.")
        attachment_parser.add_argument("--pfns", nargs="+", help="List parent DIDs for these pfns.")
        attachment_parser.add_argument("--guids", nargs="+", help="List parent DIDs for these guids.")

        # For add
        attachment_parser.add_argument("--monotonic", action="store_true", help="Monotonic status to True.")
        attachment_parser.add_argument("--fromfile", action="store_true", help="Attach the DIDs contained in a file. The file should contain one did per line.")

    def module_help(self) -> str:
        return "Add to, remove from, or list the hierarchy for a given Data Identifier."

    def usage_example(self) -> list[str]:
        usage_list_parent = f"$ {self.COMMAND_NAME} list did attachment --parent --did mock:data  # List all the parents for mock:data"
        usage_list_parent_pfn = f"$ {self.COMMAND_NAME} list did attachment --parent --pfn 1234  # List the parents for a DID using its pfn"
        usage_add_attachment = f"$ {self.COMMAND_NAME} add did attachment --did mock:data --target mock:container  # Attach mock:data to mock:container"
        usage_add_attachment_from_file = f"$ {self.COMMAND_NAME} add did attachment --did /path/to/file --target mock:container # Attach DIDs in /file to mock:container"
        usage_remove_attachment = f"$ {self.COMMAND_NAME} remove did attachment --did mock:data --target mock:dataset  # Detach data from dataset"
        examples = [usage_list_parent, usage_list_parent_pfn, usage_add_attachment, usage_add_attachment_from_file, usage_remove_attachment]
        return examples

    def list(self):
        self.args.dids = [self.args.did]
        if self.args.child:
            return list_content_history(self.args, self.logger)
        elif self.args.parent:
            return list_parent_dids(self.args, self.logger)
        else:
            raise ValueError("Either `child` or `parent` argument is required")

    def add(self):
        self.args.todid = self.args.target
        self.args.dids = [self.args.did]
        return attach(self.args, self.logger)

    def remove(self):
        self.args.fromdid = self.args.target
        self.args.dids = [self.args.did]
        return detach(self.args, self.logger)
