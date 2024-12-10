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
import os
from typing import TYPE_CHECKING

from rucio.client.commands.bin_legacy.rucio import download
from rucio.client.commands.command_base import CommandBase
from rucio.common.config import config_get_float
from rucio.common.utils import StoreAndDeprecateWarningAction

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Download(CommandBase):
    def module_help(self) -> str:
        return "Download a file."

    def parser(self, parser: "argparse._SubParsersAction[ArgumentParser]") -> None:

        command_parser = parser.add_parser(self.PARSER_NAME, description=self._help(), formatter_class=argparse.RawDescriptionHelpFormatter)

        command_parser.add_argument("-d", "--did", nargs="*", dest="dids", help="DIDs to download, as a space separated list.", required=True)
        command_parser.add_argument("-r", "--rse", help="The Rucio Storage Element (RSE) name or expression to download from.", dest="rses")
        command_parser.add_argument("--dir", dest="dir", default=".", action="store", help="The directory to store the downloaded file.")
        command_parser.add_argument("--allow-tape", action="store_true", default=False, help="Also consider tape endpoints as source of the download.")
        command_parser.add_argument("--impl", dest="impl", action="store", help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone).")
        command_parser.add_argument("--protocol", action="store", help="Force the protocol to use.")
        command_parser.add_argument("--nrandom", type=int, action="store", help="Download N random files from the DID.")
        command_parser.add_argument("--ndownloader", type=int, default=3, action="store", help="Choose the number of parallel processes for download.")
        command_parser.add_argument("--no-subdir", action="store_true", default=False, help="Don't create a subdirectory for the scope of the files.")
        command_parser.add_argument("--pfn", dest="pfn", action="store", help="Specify the exact PFN for the download.")
        command_parser.add_argument("--archive-did", action="store", dest="archive_did", help="Download from archive is transparent. This option is obsolete.")
        command_parser.add_argument("--no-resolve-archives", action="store_true", default=False, help="If set archives will not be considered for download.")
        command_parser.add_argument("--ignore-checksum", action="store_true", default=False, help="Don't validate checksum for downloaded files.")
        command_parser.add_argument("--check-local-with-filesize-only", action="store_true", default=False, help="Don't use checksum verification for already downloaded files, use filesize instead.")
        command_parser.add_argument(
            "--transfer-timeout",
            dest="transfer_timeout",
            type=float,
            action="store",
            default=config_get_float("download", "transfer_timeout", False, None),
            help="Transfer timeout (in seconds). Default: computed dynamically from --transfer-speed-timeout. If set to any value >= 0, --transfer-speed-timeout is ignored.",
        )  # NOQA: E501
        command_parser.add_argument(
            "--transfer-speed-timeout",
            dest="transfer_speed_timeout",
            type=float,
            action="store",
            default=None,
            help="Minimum allowed average transfer speed (in KBps). Default: 500. Used to dynamically compute the timeout if --transfer-timeout not set. Is not supported for --pfn.",
        )  # NOQA: E501
        command_parser.add_argument("--aria", action="store_true", default=False, help="Use aria2c utility if possible. (EXPERIMENTAL)")
        command_parser.add_argument("--trace_appid", "--trace-appid", new_option_string="--trace-appid", dest="trace_appid", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_APPID", None), help=argparse.SUPPRESS)
        command_parser.add_argument("--trace_dataset", "--trace-dataset", new_option_string="--trace-dataset", dest="trace_dataset", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_DATASET", None), help=argparse.SUPPRESS)
        command_parser.add_argument(
            "--trace_datasetscope", "--trace-datasetscope", new_option_string="--trace-datasetscope", dest="trace_datasetscope", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_DATASETSCOPE", None), help=argparse.SUPPRESS
        )  # NOQA: E501
        command_parser.add_argument("--trace_eventtype", "--trace-eventtype", new_option_string="--trace-eventtype", dest="trace_eventtype", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_EVENTTYPE", None), help=argparse.SUPPRESS)  # NOQA: E501
        command_parser.add_argument("--trace_pq", "--trace-pq", new_option_string="--trace-pq", dest="trace_pq", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_PQ", None), help=argparse.SUPPRESS)
        command_parser.add_argument("--trace_taskid", "--trace-taskid", new_option_string="--trace-taskid", dest="trace_taskid", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_TASKID", None), help=argparse.SUPPRESS)
        command_parser.add_argument("--trace_usrdn", "--trace-usrdn", new_option_string="--trace-usrdn", dest="trace_usrdn", action=StoreAndDeprecateWarningAction, default=os.environ.get("RUCIO_TRACE_USRDN", None), help=argparse.SUPPRESS)
        command_parser.add_argument("--filter", dest="filter", action="store", help="Filter files by key-value pairs like guid=2e2232aafac8324db452070304f8d745.")
        command_parser.add_argument("--scope", dest="scope", action="store", help="Scope if you are using the filter option and no full DID.")
        command_parser.add_argument("--metalink", dest="metalink_file", action="store", help="Path to a metalink file.")
        command_parser.add_argument("--deactivate-file-download-exceptions", dest="deactivate_file_download_exceptions", action="store_true", help="Does not raise NoFilesDownloaded, NotAllFilesDownloaded or incorrect number of output queue files Exception.")  # NOQA: E501
        command_parser.add_argument("--replica-selection", dest="sort", help="Select the best replica using a replica sorting algorithm provided by replica sorter (e.g., random, geoip).")

    def usage_example(self):
        return [
            "$ rucio download --did my/scope:my/file/name --dir .  # Download to your current dir"
        ]

    def _operations(self) -> dict[str, "OperationDict"]:
        return {}

    def __call__(self):
        download(self.args, self.client, self.logger, self.console, self.spinner)
