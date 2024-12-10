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
import argparse
from typing import TYPE_CHECKING

from rucio.client.commands.bin_legacy.rucio import add_container, add_dataset, attach, close, delete_metadata, detach, erase, get_metadata, list_content, list_content_history, list_dids, list_parent_dids, reopen, set_metadata, stat, touch
from rucio.client.commands.command_base import CommandBase

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class DID(CommandBase):
    def module_help(self) -> str:
        return "Manage Data IDentifiers. Modify and access specific files and groups of files. DIDs are accessed by the pattern `scope`:`name`, where name can be a wildcard, but scope must be specified."

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--recursive", dest="recursive", action="store_true", help="List data identifiers recursively.")
        parser.add_argument("--filter", help="Filter arguments in form `key=value,another_key=next_value`. Valid keys are name, type.")
        parser.add_argument("--short", action="store_true", help="Just dump the list of DIDs.")
        parser.add_argument("-d", "--did", nargs=1, help="Data IDentifier pattern.")

    def add_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--type", dest='dtype', choices=("container", "dataset"), help="Add collection type DID.")
        parser.add_argument("--monotonic", action="store_true", help="Monotonic status to True.")
        parser.add_argument("-d", "--did", action="store", help="The name of the dataset to add.")
        parser.add_argument("--lifetime", dest="lifetime", action="store", type=int, help="Lifetime in seconds.")

    def update_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="List of space separated data identifiers.")
        parser.add_argument("-r", "--rse", help="The RSE of the DIDs that are touched.")

        parser.add_argument("--touch", action="store_true", help="Update the last updated time to the current time. Requires a RSE to be set.")
        parser.add_argument("--close", action="store_true", help="Set a collection-type DID to 'closed', so it cannot have more child DIDs added to it.")
        parser.add_argument("--open", action="store_true", help="Set a collection-type DID to 'open', so more DIDs may be added to it as children.")

    def show_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="List of space separated data identifiers.")
        parser.add_argument("--parent", action="store_true", help="List the parents of the DID.")

        # Both non-functional, but list_parents complains if not present
        # Planned to re-implement in a future release
        parser.add_argument("--pfn", dest="pfns", nargs="+", help=argparse.SUPPRESS)
        parser.add_argument("--guid", dest="guids", nargs="+", help=argparse.SUPPRESS)

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--undo", action="store_true", help="Undo erase DIDs. Only works if has been less than 24 hours since erase operation.")
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="List of space separated data identifiers.")

    def touch_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="List of space separated data identifiers.")
        parser.add_argument("-r", "--rse", help="The RSE of the DIDs that are touched.")

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "List the Data IDentifiers matching certain pattern. Only collection type DIDs are returned by default, use --filter 'type=all' to return all.", "namespace": self.list_namespace},
            "show": {"call": self.show, "docs": "List attributes and statuses about data identifiers.", "namespace": self.show_namespace},
            "add": {"call": self.add, "docs": "Create a new collection type data identifier", "namespace": self.add_namespace},
            "remove": {"call": self.remove, "docs": "Delete a DID. Can be recovered for up to 24 hours after deletion.", "namespace": self.remove_namespace},
            "update": {"call": self.update, "docs": "Touch one or more DIDs and set the last accessed date to the current date.", "namespace": self.update_namespace}
        }

    def implemented_subcommands(self) -> dict[str, type[CommandBase]]:
        return {"content": Content, "metadata": Metadata}

    def usage_example(self) -> list[str]:
        return [
            "$ rucio did list --did user.jdoe:*  # Show all collection level DIDs with the scope user.jdoe",
            "$ rucio did list --short --filter type=CONTAINER --did user.jdoe:* # Show the names of all container type DIDs",
            "$ rucio did list --filter type=all --did user.jdoe:*  # Show all DIDs with the scope user.jdoe",
            "$ rucio did add --type container --did user.jdoe:container_12345  # Create a new container-type did.",
            "$ rucio did remove --did user.jdoe:file_12345  # Disable file_12345. Will be deleted 24 after deletions.",
            "$ rucio did update --touch --did user.jdoe:file_12345  # Update the time the DID has been modified",
            "$ rucio did show --did user.jdoe:file_12345  # Get the stats for file_12345 - account holder, size, expiration, open status, type, etc",
            "$ rucio did show --parent --did user.jdoe:file_12345 # Show all the parent DIDs for file_12345",
        ]

    def list_(self):
        list_dids(self.args, self.client, self.logger, self.console, self.spinner)

    def show(self):
        if self.args.parent:
            self.args.did = self.args.dids[0]
            list_parent_dids(self.args, self.client, self.logger, self.console, self.spinner)
        else:
            stat(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        erase(self.args, self.client, self.logger, self.console, self.spinner)

    def update(self):
        if self.args.touch:
            touch(self.args, self.client, self.logger, self.console, self.spinner)
        elif self.args.open:
            reopen(self.args, self.client, self.logger, self.console, self.spinner)
        elif self.args.close:
            close(self.args, self.client, self.logger, self.console, self.spinner)
        else:
            raise NotImplementedError("No update option specified, please use `rucio did update -h` to see possible update fields.")

    def add(self):
        operations = {
            "container": add_container,
            "dataset": add_dataset
        }
        try:
            operations[self.args.dtype](self.args, self.client, self.logger, self.console, self.spinner)
        except KeyError:
            raise NotImplementedError("Can only add collection type DIDs.")


class Content(DID):
    def module_help(self) -> str:
        return "View the content of collection-type DIDs (datasets and containers), and update their open/closed status."

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show the contents of a collection-type DID.", "namespace": self.namespace},
            "history": {"call": self.history, "docs": "Show the content history of a collection-type DID, when DIDs were created, modified, or deleted.", "namespace": self.namespace},
            "add": {"call": self.add, "docs": "Attach a list of Data IDentifiers (file, dataset or container) to an other Data IDentifier (dataset or container).", "namespace": self.add_namespace},
            "remove": {"call": self.remove, "docs": "Detach a list of Data Identifiers (file, dataset or container) from an other Data Identifier (dataset or container).", "namespace": self.remove_namespace},
        }

    def usage_example(self) -> list[str]:
        return [
            "$ rucio did content list --did user.jdoe:test12345  # Show the content of a collection-like DID",
            "$ rucio did content history --did user.jdoe:test12345  # Show the history of a DID's content",
            "$ rucio did content add --did user.jdoe:file_12345 --to user.jdoe:dataset_123  # Make dataset_123 the parent of file_12345",
            "$ rucio did content remove --did user.jdoe:file_12345 --from user.jdoe:datset_123  # Orphan file_12345"
        ]

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--did", dest="dids", nargs="+", action="store", help="DIDs to manage the contents of, space separated list.")
        parser.add_argument("--short", dest="short", action="store_true", help="Only show the list of DIDs.")

    def add_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--to", dest="todid", help="Destination Data IDentifier (either dataset or container).")
        parser.add_argument("-f", "--from-file", dest="fromfile", action="store_true", help="Attach the DIDs contained in a file. The file should contain one did per line.")
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="List of space separated data identifiers, or path to file of DIDs when using from-file.")

    def remove_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("--from", dest="fromdid", help="Target Data IDentifier (dataset or container), from which to detach.")
        parser.add_argument("-d", "--did", dest="dids", nargs="+", help="List of space separated data identifiers.")

    def list_(self):
        list_content(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        attach(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        detach(self.args, self.client, self.logger, self.console, self.spinner)

    def history(self):
        list_content_history(self.args, self.client, self.logger, self.console, self.spinner)


class Metadata(DID):
    def module_help(self) -> str:
        return "Manage metadata attached to DIDs via a metadata plugin."

    def _operations(self) -> dict[str, "OperationDict"]:
        return {
            "list": {"call": self.list_, "docs": "Show current metadata for a DID.", "namespace": self.list_namespace},
            "add": {"call": self.add, "docs": "Add new metadata for a DID."},
            "remove": {"call": self.remove, "docs": "Delete an existing metadata field for a DID."},
        }

    def usage_example(self) -> list[str]:
        return [
            "$ rucio did metadata add --did user.jdoe:test12345 --key project --value MyShinyNewProject # Update the project field for the DID",
            "$ rucio did metadata list --did user.jdoe:test1245  # Show all the metadata for a DID",
            "$ rucio did metadata list --did user.jdoe:test1245 user.jdoe:test67890  # Show all the metadata for both test12345 and test67890",
        ]

    def list_namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", nargs="+", dest="dids", help="List of space separated data identifiers.")
        parser.add_argument("--plugin", help="Filter down to metadata from specific metadata plugin")

    def namespace(self, parser: "ArgumentParser") -> None:
        parser.add_argument("-d", "--did", help="Single DID to modify.")
        parser.add_argument("--plugin", help="Filter down to metadata from specific metadata plugin")
        parser.add_argument("--key", help="Attribute key")
        parser.add_argument("--value", help="Attribute value")

    def list_(self):
        get_metadata(self.args, self.client, self.logger, self.console, self.spinner)

    def add(self):
        set_metadata(self.args, self.client, self.logger, self.console, self.spinner)

    def remove(self):
        delete_metadata(self.args, self.client, self.logger, self.console, self.spinner)
