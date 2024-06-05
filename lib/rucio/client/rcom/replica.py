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

import itertools
import os
from typing import TYPE_CHECKING, Optional

from rucio.client.rcom.base_command import CLIClientBase
from rucio.client.rcom.utils import get_dids, get_scope, resolve_to_contents
from rucio.common.constants import ReplicaState as replica_states
from rucio.common.utils import deep_merge_dict, detect_client_location

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Replica(CLIClientBase):
    SUBCOMMAND_NAMES = ["pfn", "state", "tombstone"]

    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)

        parser.add_argument("--replica-state", nargs="+", choices=[state.name for state in replica_states], default=[state.name for state in replica_states], help="")
        parser.add_argument("--replica-type", choices=["file", "container", "dataset"], default="file")
        parser.add_argument("--protocols", dest="protocols", action="store", help="List of comma separated protocols. (i.e. https, root, srm).")
        parser.add_argument("--dids", nargs="+", help="List of space separated data identifiers.")
        parser.add_argument("--domain", help="Force the networking domain.", choices=["wan", "lan", "all"], default="all")
        parser.add_argument("--missing", help="To list missing replicas at a RSE-Expression. Must be used with --rses option")
        parser.add_argument("--metalink", help="Output available replicas as metalink.")
        parser.add_argument("--no-resolve-archives", help="Do not resolve archives which may contain the files.")
        parser.add_argument("--sort", help="Replica sort algorithm.", default="geoip", choices=["geoip,", "random"])
        parser.add_argument("--rse", help="The RSE filter expression.")
        parser.add_argument("--deep", action="store_true", help="When listing datasets or containers, list the nested contents.")
        parser.add_argument("--monotonic", action="store_true", help="Monotonic status to True.")
        parser.add_argument("--lifetime", dest="lifetime", action="store", type=int, help="Lifetime in seconds.")

        # Add the subcommands
        parser.add_argument("subcommand", nargs="?", choices=self.SUBCOMMAND_NAMES, default=None)
        ReplicaPFN(client=None, args=None, logger=None).parser(parser)  # type: ignore
        ReplicaState(client=None, args=None, logger=None).parser(parser)  # type: ignore
        ReplicaTombstone(client=None, args=None, logger=None).parser(parser)  # type: ignore

    def module_help(self) -> str:
        return f"Change the Rucio catalogue of replicas. \nSubcommands: {self.SUBCOMMAND_NAMES}"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} -v add replica --replica-type dataset --rse RSE-T0 --dids mock:dataset_12345 # Add a new dataset",
            f"$ {self.COMMAND_NAME} remove replica --dids mock:did_12345, mock:did_67890 --rse RSE-T0 # Remove multiple replicas from RSE-T0",
            f"$ {self.COMMAND_NAME} list replica  --replica-type dataset --dids mock:dataset_12345 --rse RSE-T0 # List the contents of the dataset",
        ]

    def _list_dataset(self) -> list[dict[str, str]]:
        split_dids = [{"scope": scope, "name": name} for scope, name in [get_scope(did, self.client) for did in self.args.dids]]
        datasets = []
        for did_metadata, did in zip(self.client.get_metadata_bulk(dids=split_dids), split_dids):
            if did_metadata["did_type"] == "CONTAINER":
                datasets += resolve_to_contents(did["scope"], did["name"], self.client, original_level=did_metadata["did_type"], resolve_to="FILE")
            else:
                datasets.append(did)

        result = {}
        if self.args.deep or len(datasets) < 2:
            for did in datasets:
                for rep in self.client.list_dataset_replicas(scope=did["scope"], name=did["name"], deep=self.args.deep):
                    scope, name, rse = did["scope"], did["name"], rep["rse"]
                    replica = {(scope, name, rse): {"found": rep["available_length"], "total": rep["length"]}}
                    result = deep_merge_dict(source=replica, destination=result)
        else:
            for rep in self.client.list_dataset_replicas_bulk(dids=datasets):
                scope, name, rse = rep["scope"], rep["name"], rep["rse"]
                replica = {(scope, name, rse): {"found": rep["available_length"], "total": rep["length"]}}
                result = deep_merge_dict(source=replica, destination=result)

        result_formatted = [{"did": f"{key[0]}:{key[1]}", "rse": key[-1], "found": values["found"], "total": values["total"]} for key, values in result]
        return result_formatted

    def list(self) -> "Optional[list[dict[str, str]]]":
        replica_type = self.args.replica_type
        return {"file": self._list_file, "container": self._list_container, "dataset": self._list_dataset}[replica_type]()

    def _list_file(self) -> "list[dict[str, str]]":
        protocols = None
        if self.args.protocols is not None:
            protocols = self.args.protocols.split(",")

        table = []
        dids = []
        if self.args.missing and not self.args.rse:
            raise ValueError("Cannot use --missing without specifying a RSE")

        dids = get_dids(self.args.dids, self.client)

        all_states = True if len(self.args.replica_state) else False
        replicas = self.client.list_replicas(
            dids,
            schemes=protocols,
            ignore_availability=True,
            all_states=all_states,
            rse_expression=self.args.rse,
            metalink=self.args.metalink,
            client_location=detect_client_location(),
            sort=self.args.sort,
            domain=self.args.domain,
            resolve_archives=not self.args.no_resolve_archives,
        )
        rses = [rse["rse"] for rse in self.client.list_rses(rse_expression=self.args.rse)]

        if self.args.metalink:
            return [replica for replica in replicas]

        if self.args.missing:
            for replica, rse in itertools.product(replicas, rses):
                if "states" in replica and rse in replica["states"] and replica["states"].get(rse) != "AVAILABLE":
                    table.append({"scope": replica["scope"], "name": replica["name"], "state": replica_states[replica["states"].get(rse)].value, "rse": rse})

        else:
            # TODO Make this loop have less malice in it
            for replica in replicas:
                if "bytes" in replica:
                    for rse in replica["rses"]:
                        for pfn in replica["rses"][rse]:
                            if self.args.rse:
                                for selected_rse in rses:
                                    if rse == selected_rse:
                                        table.append({"scope": replica["scope"], "name": replica["name"], "bytes": replica["bytes"], "adler32": replica["adler32"], "rse": rse, "pfn": pfn, "state": replica_states[replica["states"][rse]].value})
                            else:
                                table.append({"scope": replica["scope"], "name": replica["name"], "bytes": replica["bytes"], "adler32": replica["adler32"], "rse": rse, "pfn": pfn, "state": replica_states[replica["states"][rse]].value})
        return table

    def _list_container(self) -> None:
        raise NotImplementedError("Cannot list contents of a container")

    def add(self) -> None:
        replica_type = self.args.replica_type
        {"file": self._add_file, "container": self._add_container, "dataset": self._add_dataset}[replica_type]()

    def _add_dataset(self) -> None:
        for did in self.args.dids:
            scope, name = get_scope(did, self.client)
            if self.client.add_dataset(scope=scope, name=name, statuses={"monotonic": self.args.monotonic}, lifetime=self.args.lifetime):
                self.logger.info(f"Added new dataset- {scope}:{name}")

    def _add_container(self) -> None:
        for did in self.args.dids:
            scope, name = get_scope(did, self.client)
            if self.client.add_container(scope=scope, name=name, statuses={"monotonic": self.args.monotonic}, lifetime=self.args.lifetime):
                self.logger.info(f"Added new container- {scope}:{name}")

    def _add_file(self) -> None:
        raise NotImplementedError("Cannot add a single file replica - please make a rule instead.")

    def remove(self) -> None:
        files = get_dids(self.args.dids, self.client)
        self.client.delete_replicas(files=files, rse=self.args.rse)
        removed_files = ",".join([f"{f['scope']}:{f['name']}" for f in files])
        self.logger.info(f"Removed files from rse={self.args.rse}: {removed_files}")


class ReplicaPFN(CLIClientBase):
    PARSER_NAME = "pfn"

    def module_help(self) -> str:
        return "View or modify the pfn of a replica."

    def usage_example(self) -> list[str]:
        list_exp = f"$ {self.COMMAND_NAME} list replica {self.PARSER_NAME} --dids mock:file --rse TEST-RSE     # View the pfn's of mock:file on TEST-RSE"
        link_exp = f"$ {self.COMMAND_NAME} set replica {self.PARSER_NAME} --dids mock:file --link /pfn/dir:/dst/dir  # Make a PFN Symlink"
        return [list_exp, link_exp]

    def parser(self, subparser: "ArgumentParser") -> None:
        pfn_parser = self.subcommand_parser(subparser)
        pfn_parser.add_argument("--link", help="Symlink PFNs with directory substitution.")

    def _get(self) -> tuple[list, list]:
        protocols = None
        if self.args.protocols is not None:
            protocols = self.args.protocols.split(",")

        dids = get_dids(self.args.dids, self.client)
        all_states = True if len(self.args.replica_state) else False

        replicas = [
            replica
            for replica in self.client.list_replicas(
                dids,
                schemes=protocols,
                ignore_availability=True,
                all_states=all_states,
                rse_expression=self.args.rse,
                metalink=self.args.metalink,
                client_location=detect_client_location(),
                sort=self.args.sort,
                domain=self.args.domain,
                resolve_archives=not self.args.no_resolve_archives,
            )
        ]
        rses = [rse["rse"] for rse in self.client.list_rses(rse_expression=self.args.rse)]
        return replicas, rses

    def list(self) -> list[dict[str, str]]:
        replicas, rses = self._get()
        resolved_pfns = []
        if self.args.rse:
            for replica, rse in itertools.product(replicas, rses):
                if rse in list(replica["rses"].keys()) and replica["rses"][rse]:
                    for pfn in replica["rses"][rse]:
                        resolved_pfns.append({"pfn": pfn, "scope": replica["scope"], "name": replica["name"], "rse": rse})
        else:
            for replica in replicas:
                for rse in replica["rses"]:
                    if replica["rses"][rse]:
                        for pfn in replica["rses"][rse]:
                            resolved_pfns.append({"pfn": pfn, "scope": replica["scope"], "name": replica["name"], "rse": rse})

        return resolved_pfns

    def set(self) -> None:
        if self.args.link is not None:
            link = self.args.link
            if ":" not in link:
                raise ValueError('Links have to supplied as: --link "/pfn/dir:/dst/dir"')
        else:
            raise ValueError("'--link' is required to set a pfn.")

        replicas, rses = self._get()
        pfn_dir, dst_dir = link.split(":")
        if self.args.rse:
            for replica, rse in itertools.product(replicas, rses):
                if rse in list(replica["rses"].keys()) and replica["rses"][rse]:
                    for pfn in replica["rses"][rse]:
                        os.symlink(dst_dir + pfn.rsplit(pfn_dir)[-1], replica["name"])
                        self.logger.info(f"Added symlink to pfn={pfn} for {replica['name']} on {rse}")
        else:
            for replica in replicas:
                for rse in replica["rses"]:
                    if replica["rses"][rse]:
                        for pfn in replica["rses"][rse]:
                            os.symlink(dst_dir + pfn.rsplit(pfn_dir)[-1], replica["name"])
                            self.logger.info(f"Added symlink to pfn={pfn} for {replica['name']}")


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
        state_parser.add_argument("--lfn", help="Use a lfn instead of DID", action="store_true")
        state_parser.add_argument("--input_file", help="Supply an input .txt file to declare")
        state_parser.add_argument("--scope", help="Scope for pfn or lfn-identified replicas.")

        state_parser.add_argument("--younger_than")
        state_parser.add_argument("--n_attempts")
        state_parser.add_argument("--reason")

    def _verify_states(self) -> None:
        possible_states = [self.args.suspicious, self.args.bad, self.args.temporary_unavailable, self.args.quarantine]

        if not any(possible_states):
            raise ValueError(f"No state set. See {self.COMMAND_NAME} list replica state -h for options.")

        if sum([int(state) for state in possible_states]) != 1:
            raise ValueError("Cannot set more than one state.")

    def _state_string(self) -> str:
        if self.args.bad:
            return "BAD"
        elif self.args.temporary_unavailable:
            return "TEMPORARY_UNAVAILABLE"
        else:
            return "SUSPICIOUS"

    def _parse_replica_list(self) -> tuple[list[str], list[str]]:
        scopes = []
        replica_names = []
        if self.args.input_file:
            if self.args.scope is None:
                raise ValueError("Scope required when declaring from a file")

            for line in open(self.args.input_file):
                line = line.strip()  # Clear whitespace
                if line:
                    scope, name = self.input_to_did(line)

                    replica_names.append(name)
                    scopes.append(scope)

        elif self.args.dids is not None:
            for did in self.args.dids:
                scope, name = get_scope(did, self.client)
                replica_names.append(name)
                scopes.append(scope)
        else:
            raise ValueError("Missing replicas to declare. Supply them as an input file or DIDs.")

        return scopes, replica_names

    def input_to_did(self, line: str) -> tuple[str, str]:
        line = line.rstrip("\n")
        if "://" in line:
            return self.args.scope, line
        else:
            raise ValueError("Entries in files as either pfns")

    def set(self) -> None:
        self._verify_states()
        if self.args.rse is None:
            raise ValueError("An RSE must be included.")

        scopes, replica_list = self._parse_replica_list()
        # Set quarantine
        if self.args.quarantine:
            chunk = []
            # send requests in chunks
            chunk_size = 1000
            for replica in replica_list:
                chunk.append(dict(path=replica))
                if len(chunk) >= chunk_size:
                    self.client.quarantine_replicas(chunk, rse=self.args.rse)
                    chunk = []
            if chunk:
                self.client.quarantine_replicas(chunk, rse=self.args.rse)
            self.logger.info(f"Quarantined replicas by pfn: {[pfn for pfn in replica_list]}")

        # Set bad, temp unaval, suspicious
        else:
            state_string = self._state_string()
            for scope, replica in zip(scopes, replica_list):
                marking_replicas = [{"scope": scope, "rse": self.args.rse, "name": replica, "state": state_string} for replica in replica_list]

                did_errors = self.client.declare_bad_file_replicas(marking_replicas, reason=self.args.reason)
                if len(did_errors) != 0:
                    for rse, errors in did_errors.items():
                        for error in errors:
                            self.logger.warn(f"Unable to declare replicas for rse: {rse}, {error}")
                else:
                    self.logger.info(f"Successfully declared replicas {replica_list} as {state_string}")

    def unset(self) -> None:
        # Return the state to default
        scopes, names = self._parse_replica_list()
        to_declare = []
        for scope, name in zip(scopes, names):
            to_declare.append(
                {
                    "state": "A",
                    "scope": scope,
                    "name": name,
                }
            )

        self.client.update_replicas_states(self.args.rse, to_declare)
        self.logger.info(f"On RSE {self.args.rse} set replicas to 'Available': {to_declare}")

    def list(self) -> Optional[list[dict[str, str]]]:
        self._verify_states()
        if self.args.rse is None:
            raise ValueError("An RSE must be included.")

        if self.args.suspicious:
            replicas = self.client.list_suspicious_replicas(self.args.rse, self.args.younger_than, self.args.n_attempts)
            return [replica for replica in replicas]

        elif self.args.quarantine:
            raise NotImplementedError("Cannot view quarantined replicas through the client.")

        else:
            state_name = "BAD" if self.args.bad else "TEMPORARY_UNAVAILABLE"
            protocols = None
            if self.args.protocols is not None:
                protocols = self.args.protocols.split(",")

            dids = get_dids(self.args.dids, self.client)
            replicas = [
                replica
                for replica in self.client.list_replicas(
                    dids,
                    schemes=protocols,
                    ignore_availability=True,
                    all_states=True,
                    rse_expression=self.args.rse,
                    metalink=self.args.metalink,
                    client_location=detect_client_location(),
                    sort=self.args.sort,
                    domain=self.args.domain,
                    resolve_archives=not self.args.no_resolve_archives,
                )
            ]
            rses = [rse["rse"] for rse in self.client.list_rses(rse_expression=self.args.rse)]
            results = []
            for replica, rse in itertools.product(replicas, rses):
                include_condition = rse in list(replica["rses"].keys()) and replica["rses"][rse] and replica["states"][rse] == state_name
                if include_condition:
                    results.append({"scope": replica["scope"], "name": replica["name"], "rse": rse})

            return results


class ReplicaTombstone(CLIClientBase):
    PARSER_NAME = "tombstone"

    def module_help(self) -> str:
        return "Add a tombstone for a list of replicas."

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} add replica tombstone --dids mock:file --rse MOCK"]

    def parser(self, subparser: "ArgumentParser") -> None:
        self.subcommand_parser(subparser)

    def add(self) -> None:
        replicas = []
        for did in self.args.dids:
            scope, name = get_scope(did, self.client)
            replicas.append({"scope": scope, "name": name, "rse": self.args.rse})
        self.client.set_tombstone(replicas)
        self.logger.info(f"Set tombstone successfully on {[did for did in self.args.dids]}")
