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

import os
from argparse import SUPPRESS, ArgumentParser, _SubParsersAction

from rucio.client.rcom.base_command import CLIClientBase
from rucio.common.utils import parse_did_filter_from_string


class Download(CLIClientBase):
    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)
        parser.add_argument("--dir", dest="dir", default=".", help="The directory to store the downloaded file.")
        parser.add_argument("--dids", nargs="*", help="List of space separated data identifiers to download.")
        parser.add_argument("--allow-tape", action="store_true", help="Also consider tape endpoints as source of the download.")
        parser.add_argument("--rse", help="RSE Expression to specify allowed sources")
        parser.add_argument("--impl", help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone).")
        parser.add_argument("--protocol", help="Force the protocol to use.")
        parser.add_argument("--nrandom", type=int, help="Download N random files from the DID.")
        parser.add_argument("--ndownloader", type=int, default=3, help="Choose the number of parallel processes for download.")
        parser.add_argument("--no-subdir", action="store_true", help="Don't create a subdirectory for the scope of the files.")
        parser.add_argument("--pfns", help="Specify the exact PFN for the download.")
        parser.add_argument("--no-resolve-archives", action="store_true", help="If set archives will not be considered for download.")
        parser.add_argument("--ignore-checksum", action="store_true", help="Don't validate checksum for downloaded files.")
        parser.add_argument("--check-local-with-filesize", action="store_true", help="Use filesize instead instead of checksum for already downloaded files..")
        parser.add_argument("--transfer-timeout", type=float, help="Transfer timeout (in seconds). If set to any value >= 0, --transfer-speed-timeout is ignored.")  # NOQA: E501
        parser.add_argument("--transfer-speed-timeout", type=float, default=500, help="Minimum allowed average transfer speed (in KBps). Used to dynamically compute the timeout if --transfer-timeout not set. Is not supported for --pfn.")  # NOQA: E501
        parser.add_argument("--aria", action="store_true", help="Use aria2c utility if possible. (EXPERIMENTAL)")

        parser.add_argument("--trace-appid", default=os.environ.get("RUCIO_TRACE_APPID", None), help=SUPPRESS)
        parser.add_argument("--trace-dataset", default=os.environ.get("RUCIO_TRACE_DATASET", None), help=SUPPRESS)
        parser.add_argument("--trace-datasetscope", default=os.environ.get("RUCIO_TRACE_DATASETSCOPE", None), help=SUPPRESS)
        parser.add_argument("--trace-eventtype", default=os.environ.get("RUCIO_TRACE_EVENTTYPE", None), help=SUPPRESS)
        parser.add_argument("--trace-pq", default=os.environ.get("RUCIO_TRACE_PQ", None), help=SUPPRESS)
        parser.add_argument("--trace-taskid", default=os.environ.get("RUCIO_TRACE_TASKID", None), help=SUPPRESS)
        parser.add_argument("--trace-usrdn", default=os.environ.get("RUCIO_TRACE_USRDN", None), help=SUPPRESS)

        parser.add_argument("--filter", help="Filter files by key-value pairs like guid=2e2232aafac8324db452070304f8d745.")
        parser.add_argument("--scope", help="Scope to use when --filter is active")
        parser.add_argument("--metalink", help="Path to a metalink file.")
        parser.add_argument("--ignore-exceptions", action="store_true", help="Do not raise NoFilesDownloaded, NotAllFilesDownloaded or incorrect number of output queue files Exception.")
        parser.add_argument("--replica-selection", help="Select the best replica using a replica sorting algorithm provided by replica sorter (e.g., random, geoip).")

    def module_help(self) -> str:
        return "Download files from Rucio using new threaded model and RSE expression support"

    def usage_example(self) -> list[str]:
        return [
            f"$ {self.COMMAND_NAME} download --did mock:file_1234 mock:file_5678 mock:9012 --dir ./rucio_downloads/ # Download file_1234, file_5678 and file_9012",
            f"$ {self.COMMAND_NAME} download --did mock:file_1234 --rse RSE-T # Download mock:file_1234 from an rse matching RSE-T",
            f"$ {self.COMMAND_NAME} download --scope mock --filter guid=2e2232aafac8324db452070304f8d745  # Download based on filter matching",
            f"$ {self.COMMAND_NAME} download --pfns /data/scope/dataset/file_run_012345 # Download a file based on specific pfn",
        ]

    def validate_arguments(self):
        if not self.args.dids and not self.args.filter and not self.args.metalink:
            raise ValueError("At least one DID is mandatory")

        elif not self.args.dids and self.args.filter and not self.args.scope:
            raise ValueError("The argument scope is mandatory")

        if self.args.filter and self.args.metalink:
            raise ValueError("Arguments filter and metalink cannot be used together.")

        if self.args.dids and self.args.metalink:
            raise ValueError("Arguments dids and metalink cannot be used together.")

        if self.args.ignore_checksum and self.args.check_local_with_filesize_only:
            raise ValueError("Arguments ignore-checksum and check-local-with-filesize-only cannot be used together.")

        if self.args.metalink and self.args.replica_selection:
            self.logger.warning("Ignoring --replica-selection option because --metalink option given")

        if self.args.pfns:
            if self.args.aria:
                self.logger.warning("Ignoring --aria option because --pfns option given")
            if self.args.impl:
                self.logger.warning("Ignoring --impl option because --pfns option given")
            if self.args.protocol:
                self.logger.warning("Ignoring --protocol option because --pfns option given")
            if self.args.transfer_speed_timeout:
                self.logger.warning("Download with --pfns doesn't support --transfer-speed-timeout")

            num_dids = len(self.args.dids)
            if num_dids > 1:
                self.logger.warning(f"Download with --pfns option only supports one DID but {num_dids} DIDs were given. Considering only first DID: {self.args.dids[0]}")
                self.logger.debug(f"Given DIDs include: {self.args.dids}")

    def __call__(self) -> dict[str, int]:
        self.validate_arguments()

        try:
            timeout = self.client.get_config("upload", "transfer_timeout")
        except:
            timeout = 360
        timeout = self.args.transfer_timeout if self.args.transfer_timeout is not None else timeout

        try:
            speed_timeout = self.client.get_config("download", "transfer_speed_timeout")
        except:
            speed_timeout = 500
        speed_timeout = self.args.transfer_speed_timeout if self.args.transfer_speed_timeout is not None else speed_timeout

        # Add in all the trace arguments
        trace_pattern = {}
        trace_arguments = [self.args.trace_appid, self.args.trace_dataset, self.args.trace_datasetscope, self.args.trace_eventtype, self.args.trace_pq, self.args.trace_taskid, self.args.trace_usrdn]
        trace_argument_names = ["appid", "dataset", "datasetScope", "eventType", "pq", "taskid", "usrdn"]
        for arg, arg_name in zip(trace_arguments, trace_argument_names):
            if arg is not None:
                trace_pattern[arg_name] = arg

        from rucio.client.downloadclient import DownloadClient

        download_client = DownloadClient(client=self.client, logger=self.logger, check_admin=self.args.allow_tape)

        # These are shared between all download requests
        items_common = {
            "rse": self.args.rse,
            "base_dir": self.args.dir,
            "no_subdir": self.args.no_subdir,
            "transfer_timeout": self.args.transfer_timeout,
            "no_resolve_archives": self.args.no_resolve_archives,
            "ignore_checksum": self.args.ignore_checksum,
            "check_local_with_filesize_only": self.args.check_local_with_filesize,
        }

        # Get filters
        filters = {}
        if self.args.filter:
            filters, _ = parse_did_filter_from_string(self.args.filter)
            if self.args.scope:
                filters["scope"] = self.args.scope  # Scope arg is used as a filter
            items_common["filters"] = filters

        result = False

        if not self.args.pfns:
            items_common["impl"] = self.args.impl
            items_common["force_scheme"] = self.args.protocol
            items_common["nrandom"] = self.args.nrandom
            items_common["transfer_speed_timeout"] = speed_timeout

            items = []
            if self.args.dids:
                for did in self.args.dids:
                    item = {"did": did}
                    item.update(items_common)
                    items.append(item)
            else:
                items.append(items_common)

            if self.args.aria:
                result = download_client.download_aria2c(items, trace_pattern, deactivate_file_download_exceptions=self.args.ignore_exceptions, sort=self.args.replica_selection)
            elif self.args.metalink:
                result = download_client.download_from_metalink_file(items[0], self.args.metalink, deactivate_file_download_exceptions=self.args.ignore_exceptions)
            else:  # standard download
                result = download_client.download_dids(items, self.args.ndownloader, trace_pattern, deactivate_file_download_exceptions=self.args.ignore_exceptions, sort=self.args.replica_selection)
        else:  # Download from pfn
            items_common["pfn"] = self.args.pfns
            items_common["did"] = self.args.dids[0]
            result = download_client.download_pfns([items_common], 1, trace_pattern, deactivate_file_download_exceptions=self.args.ignore_exceptions)
        if not result:
            raise RuntimeError("Download API failure.")

        summary = {}
        for item in result:
            for did, did_stats in item.get("input_dids", {}).items():
                did_str = f"{did.scope}:{did.name}"
                did_summary = summary.setdefault(did_str, {"length": did_stats.get("length"), "DONE": 0, "ALREADY_DONE": 0, "_total": 0})
                did_summary["_total"] += 1
                state = item["clientState"].upper()
                if state in did_summary:
                    did_summary[state] += 1

        return summary
