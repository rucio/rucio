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


from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rucio.client.rcom.base_command import CLIClientBase

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

    def validate_arguments(self) -> None:
        if self.args.rse is None:
            raise ValueError("--rse is required.")

        if (self.args.lifetime is not None) and (self.args.expiration_date is not None):
            raise ValueError("--lifetime and --expiration-date cannot be specified at the same time.")

        elif self.args.expiration_date is not None:
            expiration_date = datetime.strptime(self.args.expiration_date, "%Y-%m-%d-%H:%M:%S").astimezone(timezone.utc)
            if expiration_date < datetime.now(timezone.utc):
                raise ValueError("The specified expiration date should be in the future!")

            self.args.lifetime = (expiration_date - datetime.now(timezone.utc)).total_seconds()

        if self.args.pfn is not None:
            if self.args.impl:
                self.logger.warning("Ignoring --impl option because --pfn option given")
                self.args.impl = None

        if len(self.args.files) < 1:
            raise ValueError("No files could be extracted from the given arguments")

        if len(self.args.files) > 1 and self.args.guid:
            raise ValueError(
                "A single GUID was specified on the command line, but there are multiple files to upload. \
                If GUID auto-detection is not used, only one file may be uploaded at a time"
            )

        if len(self.args.files) > 1 and self.args.lfn:
            raise ValueError(
                "A single LFN was specified on the command line, but there are multiple files to upload. \
                If LFN auto-detection is not used, only one file may be uploaded at a time"
            )

        if self.args.recursive and self.args.pfn:
            raise ValueError(
                "It is not possible to create the folder structure into collections with a non-deterministic way.\
                If PFN is specified, you cannot use --recursive"
            )

    def __call__(self) -> None:
        self.validate_arguments()
        try:
            timeout = self.client.get_config("upload", "transfer_timeout")
        except:
            timeout = 360
        timeout = self.args.transfer_timeout if self.args.transfer_timeout is not None else timeout

        dataset_scope = None
        dataset_name = None
        if self.args.dataset is not None:
            did = self.args.dataset.split(":")
            if len(did) == 2:
                dataset_scope = did[0]
                dataset_name = did[1]
        else:
            # If there isn't a scope name but there is a file with a did-like format, use that
            for file in self.args.files:
                did = file.split(":")
                if len(did) == 2:
                    dataset_scope = did[0]
                    dataset_name = did[1]

        items = []
        for file in self.args.files:
            # Ignore the ones with DID's format
            if file.count(":") > 0:
                self.logger.debug(f"Ignoring {file}, formatted like a DID.")
                continue

            items.append(
                {
                    "path": file,
                    "rse": self.args.rse,
                    "did_scope": self.args.scope,
                    "did_name": self.args.name,
                    "impl": self.args.impl,
                    "dataset_scope": dataset_scope,
                    "dataset_name": dataset_name,
                    "force_scheme": self.args.protocol,
                    "pfn": self.args.pfn,
                    "lifetime": self.args.lifetime,
                    "register_after_upload": self.args.register_after_upload,
                    "transfer_timeout": timeout,
                    "guid": self.args.guid,
                    "recursive": self.args.recursive,
                }
            )

        from rucio.client.uploadclient import UploadClient

        upload_client = UploadClient(self.client, logger=self.logger)
        summary_file_path = "rucio_upload.json" if self.args.summary else None
        upload_client.upload(items, summary_file_path)
