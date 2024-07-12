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

from rucio.client.bin.rucio import download
from rucio.client.commands.base_command import CLIClientBase


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

    def __call__(self) -> None:
        download(self.args, self.logger)
