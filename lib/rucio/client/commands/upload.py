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

from rucio.client.bin.rucio import upload
from rucio.client.commands.base_command import CLIClientBase

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction


class Upload(CLIClientBase):
    def parser(self, subparsers: "_SubParsersAction[ArgumentParser]") -> None:
        parser = super().parser(subparsers)
        parser.add_argument("--files", nargs="+", help="Files and datasets.")
        parser.add_argument("--rse", help="Rucio Storage Element (RSE) name.")
        parser.add_argument("--name", help="DID name.")
        parser.add_argument("--lifetime", type=int, help="Lifetime of the rule in seconds.")
        parser.add_argument("--expiration-date", help="The date when the rule expires in UTC, format: <year>-<month>-<day>-<hour>:<minute>:<second>. E.g. 2022-10-20-20:00:00")
        parser.add_argument("--scope", help="Scope name.")
        parser.add_argument("--dataset", help="Dataset name")
        parser.add_argument("--impl", help="Transfer protocol implementation to use")
        parser.add_argument("--register-after-upload", action="store_true", help="Register the file only after successful upload.")
        parser.add_argument("--summary", action="store_true", help="Create rucio_upload.json summary file")
        parser.add_argument("--guid", help="Manually specify the GUID for the file.")
        parser.add_argument("--protocol", help="Force the protocol to use")
        parser.add_argument("--pfn", help="Specify the exact PFN for the upload.")
        parser.add_argument("--lfn", help="Specify the exact LFN for the upload.")
        parser.add_argument("--transfer-timeout", type=float, help="Transfer timeout (in seconds).")
        parser.add_argument("--recursive", action="store_true", help="Convert recursively the folder structure into collections")

    def module_help(self) -> str:
        return "Upload files into Rucio for a specific RSE"

    def usage_example(self) -> list[str]:
        return [f"$ {self.COMMAND_NAME} upload --file [scope:datasetname] [folder/] [files1 file2 file3] --rse RSE_12345"]

    def __call__(self) -> None:
        upload(self.args, self.logger)
