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

from rucio.client.commands.bin_legacy.rucio import upload
from rucio.client.commands.command_base import CommandBase
from rucio.common.config import config_get_float

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from rucio.client.commands.utils import OperationDict


class Upload(CommandBase):
    def module_help(self) -> str:
        return "Upload (a) DID(s)"

    def parser(self, parser: "argparse._SubParsersAction[ArgumentParser]") -> None:

        command_parser = parser.add_parser(self.PARSER_NAME, description=self._help(), formatter_class=argparse.RawDescriptionHelpFormatter)

        command_parser.add_argument("--files", nargs="+", dest="args", help="Files and datasets to upload")
        command_parser.add_argument('--rse', "--rse-name", dest='rse', action='store', help='Rucio Storage Element (RSE) name.',)
        command_parser.add_argument("--lifetime", type=int, help="Lifetime of the rule in second.")
        command_parser.add_argument("--expiration-date", help="The date when the rule expires in UTC, format: <year>-<month>-<day>-<hour>:<minute>:<second>. E.g. 2022-10-20-20:00:00")
        command_parser.add_argument("--scope", help="Scope name to assign new files")
        command_parser.add_argument("--impl", help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone)")
        # The --no-register option is hidden. This is pilot ONLY. Users should not use this. Will lead to unregistered data on storage!
        command_parser.add_argument("--no-register", action="store_true", default=False, help=argparse.SUPPRESS)
        command_parser.add_argument("--register-after-upload", action="store_true", default=False, help="Register the file only after successful upload")
        command_parser.add_argument("--summary", action="store_true", default=False, help="Create rucio_upload.json summary file")
        command_parser.add_argument("--guid", help="Manually specify the GUID for the file")
        command_parser.add_argument("--protocol", help="Force the protocol to use")
        command_parser.add_argument("--pfn", help="Specify the exact PFN for the upload")
        command_parser.add_argument("--name", help="Specify the exact LFN for the upload")
        command_parser.add_argument("--transfer-timeout", type=float, default=config_get_float("upload", "transfer_timeout", False, 360), help="Transfer timeout (in seconds)")
        command_parser.add_argument("--recursive", action="store_true", default=False, help="Convert recursively the folder structure into collections")

    def usage_example(self):
        return [
            "$ rucio upload --files [files1 file2 file3]  --rse MyRSE  # Upload files to a specific RSE",
            "$ rucio upload --files [files1 file2 file3]  --rse MyRSE  --register-after-upload # Upload files to a specific RSE, registering it automatically"
        ]

    def _operations(self) -> dict[str, "OperationDict"]:
        return {}

    def __call__(self):
        upload(self.args, self.client, self.logger, self.console, self.spinner)
