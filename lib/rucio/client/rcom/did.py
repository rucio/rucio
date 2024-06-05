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

import math
import uuid
from typing import TYPE_CHECKING, Any

from rucio.client.rcom.base_command import CLIClientBase
from rucio.client.rcom.utils import get_scope
from rucio.common.config import config_get
from rucio.common.exception import InvalidObject, RucioException
from rucio.common.utils import chunks, parse_did_filter_from_string_fe

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class DID(CLIClientBase):
    SUBCOMMAND_NAMES = ["history", "metadata", "attachment"]

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)

        parser.add_argument("--did", nargs="+", help="Data IDentifier pattern, format {scope}:{did name}, space separated")
        parser.add_argument("--filter", help="Filter arguments in form `key=value,another_key=next_value`. Valid keys are name, type.")
        parser.add_argument("--recursive", action="store_true", help="List data identifiers recursively.")
        parser.add_argument("--stat", action="store_true", help="Provide stats for the listed DIDs")
        parser.add_argument("--type", dest="type_", help="Type of DID", choices={"dataset", "file", "container"}, default="file")
        parser.add_argument("--lifetime", help="Lifetime in seconds", type=float)
        parser.add_argument("--undo", action="store_true", help="Undo erase DIDs. Only works if has been less than 24 hours since erase operation.")

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

    def list(self) -> list[dict[str, Any]]:
        did_info = []
        if not self.args.stat:
            filters = {}
            try:
                scope, name = get_scope(self.args.did[0], self.client)
                if name == "":
                    name = "*"
                    self.logger.debug("DID Name came back as null, using *")
            except InvalidObject as error:
                self.logger.debug(f"Error getting scope, assuming did format - <scope>:*, {error}")
                scope = self.args.did[0]
                name = "*"

            if scope not in self.client.list_scopes():
                raise ValueError("Scope not found")

            if self.args.recursive and "*" in name:
                raise ValueError("Option recursive cannot be used with wildcards")
            else:
                if filters:
                    if ("name" in filters) and (name != "*"):
                        raise ValueError("Must have a wildcard in did name if filtering by name")

            filters, type_ = parse_did_filter_from_string_fe(self.args.filter, name)

            self.logger.debug(f"Querying for did with type {type_}")
            self.logger.debug(f"Filtering search with {filters}")
            for did in self.client.list_dids(scope, filters=filters, did_type=type_, long=True, recursive=self.args.recursive):
                did_info.append(did)

        # stat them instead
        else:
            for did in self.args.did:
                scope, name = get_scope(did, self.client)
                info = self.client.get_did(scope=scope, name=name, dynamic_depth="DATASET")
                did_info.append(info)
        return did_info

    def add(self) -> None:
        if self.args.type_ == "container":
            self._add_container()
        elif self.args.type_ == "dataset":
            self._add_dataset()
        elif self.args.type_ == "file":
            self._add_did_file()
        else:
            raise NotImplementedError

    def _add_container(self) -> None:
        scope, name = get_scope(self.args.did[0], self.client)
        self.client.add_container(scope=scope, name=name, statuses={"monotonic": self.args.monotonic}, lifetime=self.args.lifetime)
        self.logger.info(f"Added {scope}: {name} as a container")

    def _add_dataset(self) -> None:
        scope, name = get_scope(self.args.did[0], self.client)
        self.client.add_dataset(scope=scope, name=name, statuses={"monotonic": self.args.monotonic}, lifetime=self.args.lifetime)
        self.logger.info(f"Added {scope}: {name} as a dataset")

    def _add_did_file(self) -> None:
        raise NotImplementedError

    def remove(self) -> None:
        for did in self.args.did:
            if "*" in did:
                self.logger.warning("This command doesn't support wildcards! Skipping DID: %s" % did)
                continue
            try:
                scope, name = get_scope(did, self.client)
            except RucioException as error:
                self.logger.warning("DID is in wrong format: %s" % did)
                self.logger.debug("Error: %s" % error)
                continue

            if self.args.undo:
                try:
                    self.client.set_metadata(scope=scope, name=name, key="lifetime", value=None)
                    self.logger.info(f"Erase undo for DID: {scope}:{name}")
                except Exception:
                    self.logger.warning(f"Cannot undo erase operation on DID {scope}:{name}. DID not existent or grace period of 24 hours already expired.")
            else:
                try:
                    self.client.set_metadata(scope=scope, name=name, key="lifetime", value=86400)
                    self.logger.info(f"CAUTION! erase operation is irreversible after 24 hours. To cancel this operation you can run the following command:\nrucio erase --undo {scope}:{name}")
                except RucioException as error:
                    self.logger.warning(f"Failed to erase DID: {did}")
                    self.logger.debug(f"Error: {error}")


class DIDHistory(CLIClientBase):
    PARSER_NAME = "history"

    def parser(self, subparser: "ArgumentParser") -> None:
        self.subcommand_parser(subparser)
        # TODO Add did as a secondary argument here

    def module_help(self) -> str:
        return "List the content history of a collection."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} list did history --did mock:dataset_12345 # List the content history of the dataset"]

    def list(self) -> list[dict[str, Any]]:
        history = []
        for did in self.args.did:
            scope, name = get_scope(did, self.client)
            for content in self.client.list_content_history(scope=scope, name=name):
                history.append(content)

        return history


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

    def set(self) -> None:
        value = self.args.value if self.args.key != "lifetime" else float(self.args.value)
        for did in self.args.did:
            scope, name = get_scope(did, self.client)
            self.client.set_metadata(scope=scope, name=name, key=self.args.key, value=value)
            self.logger.info(f"Updated {scope}:{name} with metadata field {self.args.key} = {value}")

    def unset(self) -> None:
        for did in self.args.did:
            scope, name = get_scope(did, self.client)
            self.client.delete_metadata(scope=scope, name=name, key=self.args.key)
            self.logger.info(f"Removed metadata key {self.args.key} from {scope}:{name}")

    def list(self) -> list[dict[str, Any]]:
        if self.args.plugin:
            plugin = self.args.plugin
        else:
            plugin = config_get("client", "metadata_default_plugin", default="DID_COLUMN")
        did_metadata = []
        for did in self.args.did:
            scope, name = get_scope(did, self.client)
            meta = self.client.get_metadata(scope=scope, name=name, plugin=plugin)
            if self.args.key is not None:
                try:
                    meta = {self.args.key: meta[self.args.key]}
                except KeyError:
                    self.logger.warning(f"Key {self.args.key} not found in metadata")
                    meta = {self.args.key: None}

            did_metadata.append(meta)

        return did_metadata


class DIDAttachment(CLIClientBase):
    PARSER_NAME = "attachment"

    def parser(self, subparser: "ArgumentParser") -> None:
        attachment_parser = self.subcommand_parser(subparser)

        attachment_parser.add_argument("--target", help="Target to attach/detach a DID to/from - must be a Dataset or Container")

        # For List
        attachment_parser.add_argument("--parent", action="store_true", help="View info about a DID parent")
        attachment_parser.add_argument("--child", action="store_true", help="View contents of a DID.")
        attachment_parser.add_argument("--pfn", nargs="+", help="List parent DIDs for these pfns.")
        attachment_parser.add_argument("--guid", nargs="+", help="List parent DIDs for these guids.")

        # For add
        attachment_parser.add_argument("--monotonic", action="store_true", help="Monotonic status to True.")
        attachment_parser.add_argument("--from_file", action="store_true", help="Attach the DIDs contained in a file. The file should contain one did per line.")

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

    def _list_parent(self) -> list[dict[str, Any]]:
        if self.args.pfn is not None:
            parents = []
            for dids_from_pfn in self.client.get_did_from_pfns(self.args.pfn):
                for pfn, did in dids_from_pfn.items():
                    rules = self.client.list_associated_rules_for_file(did["scope"], did["name"])
                    for rule in rules:
                        rule["child_pfn"] = pfn
                        parents.append(rule)
            return parents

        elif self.args.guid is not None:
            guid = []
            for input_ in self.args.guid:
                try:
                    uuid.UUID(input_)
                except ValueError:
                    continue
            parents = []
            for guid in guid:
                for did in self.client.get_dataset_by_guid(guid):
                    rules = self.client.list_associated_rules_for_file(did["scope"], did["name"])
                    for rule in rules:
                        rule["child_guid"] = guid
                        parents.append(rule)
            return parents

        elif self.args.did:
            table = []
            for did in self.args.did:
                scope, name = get_scope(did, self.client)
                for dataset in self.client.list_parent_dids(scope=scope, name=name):
                    dataset["parent_scope"] = scope
                    dataset["parent_name"] = name
                    table.append(dataset)
            return table

        else:
            raise ValueError("Must check parent by did, guid, or pfn. Use list did -h for more info.")

    def list(self) -> list[dict[str, Any]]:
        if self.args.parent and self.args.child:
            raise ValueError("Pick either child or parent.")

        if self.args.parent:
            contents = self._list_parent()
        if self.args.child:
            for did in self.args.did:
                scope, name = get_scope(did, self.client)
                contents = [i for i in self.client.list_content(scope=scope, name=name)]
        return contents

    def add(self) -> None:
        scope, name = get_scope(self.args.target, self.client)
        dids = self.args.did
        limit = 499

        if self.args.from_file:
            if len(dids) > 1:
                self.logger.error("If --fromfile option is active, only one file is supported. The file should contain a list of dids, one per line.")
                return None
            try:
                f = open(dids[0], "r")
                dids = [did.rstrip() for did in f.readlines()]
            except OSError:
                self.logger.error("Can't open file '" + dids[0] + "'.")
                return None

        dids = [{"scope": get_scope(did, self.client)[0], "name": get_scope(did, self.client)[1]} for did in dids]
        if len(dids) <= limit:
            self.client.attach_dids(scope=scope, name=name, dids=dids)
        else:
            self.logger.warning("You are trying to attach too many DIDs. Therefore they will be chunked and attached in multiple commands.")
            missing_dids = []
            for chunk_index, chunk in enumerate(chunks(dids, limit)):
                self.logger.info(f"Try to attach chunk {chunk_index}/{int(math.ceil(len(dids) / limit))}")

                try:
                    self.client.attach_dids(scope=scope, name=name, dids=chunk)
                except Exception:
                    content = [{"scope": did["scope"], "name": did["name"]} for did in self.client.list_content(scope=scope, name=name)]
                    missing_dids += [did for did in chunk if did not in content]

            if missing_dids:
                self.logger.debug("Failed to attach some of the chunks, retrying just the missing DIDs...")
                for chunk in chunks(missing_dids, limit):
                    self.client.attach_dids(scope=scope, name=name, dids=chunk)

        self.logger.info(f"Successfully added attachment to {scope}:{name} for DIDs")

    def remove(self) -> None:
        scope, name = get_scope(self.args.target, self.client)
        dids = []
        for did in self.args.did:
            child_scope, child_name = get_scope(did, self.client)
            dids.append({"scope": child_scope, "name": child_name})
        self.client.detach_dids(scope=scope, name=name, dids=dids)
        self.logger.info(f"Successfully removed attachment to {scope}:{name} for DIDs")
