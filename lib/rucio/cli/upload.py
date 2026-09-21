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
from datetime import datetime
from typing import TYPE_CHECKING, Optional

import click

from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get_float
from rucio.common.exception import InputValidationError

if TYPE_CHECKING:
    from rucio.common.types import FileToUploadDict


@click.command("upload")
@click.argument("file-paths", nargs=-1)
@click.option("--rse", "--rse-name", help="Rucio Storage Element (RSE) name", required=True)
@click.option("--lifetime", type=int, help="Lifetime of the rule in seconds")
@click.option("--expiration-date", help="The date when the rule expires in UTC, format: <year>-<month>-<day>-<hour>:<minute>:<second>. E.g. 2022-10-20-20:00:00")
@click.option("--scope", help="Scope name.")
# TODO enumerate the allowed impls
@click.option("--impl", help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone)")
# The --no-register option is hidden. This is pilot ONLY. Users should not use this. Will lead to unregistered data on storage!
@click.option("--no-register", is_flag=True, default=False, hidden=True)
@click.option("--register-after-upload", is_flag=True, default=False, help="Register the file _only_ after successful upload")
@click.option("--summary", is_flag=True, default=False, help="Create rucio_upload.json summary file")
@click.option("--guid", help="Manually specify the GUID for the file.")
@click.option("--protocol", help="Force the protocol to use")
@click.option("--pfn", help="Specify the exact PFN for the upload")
@click.option("--lfn", help="Specify the exact LFN for the upload")
@click.option("--transfer-timeout", type=float, default=config_get_float("upload", "transfer_timeout", False, 360), help="Transfer timeout (in seconds)")
@click.option("-r", "--recursive", is_flag=True, default=False, help="Convert recursively the folder structure into collections")
@click.pass_context
def upload_command(
    ctx: click.Context,
    file_paths: tuple[str, ...],
    rse: str,
    lifetime: Optional[int],
    expiration_date: Optional[str],
    scope: Optional[str],
    impl: Optional[str],
    no_register: bool,
    register_after_upload: bool,
    summary: bool,
    guid: Optional[str],
    protocol: Optional[str],
    pfn: Optional[str],
    lfn: Optional[str],
    transfer_timeout: Optional[float],
    recursive: bool
) -> None:
    """Upload file(s) to a Rucio RSE"""
    if lifetime and expiration_date:
        raise InputValidationError("--lifetime and --expiration-date cannot be specified at the same time.")
    elif expiration_date:
        converted_exp_date = datetime.strptime(expiration_date, "%Y-%m-%d-%H:%M:%S")
        if converted_exp_date < datetime.utcnow():
            raise ValueError("The specified expiration date should be in the future!")
        lifetime = int((converted_exp_date - datetime.utcnow()).total_seconds())

    dsscope = None
    dsname = None
    for arg in file_paths:
        did = arg.split(':')
        if not dsscope and len(did) == 2:
            dsscope = did[0]
            dsname = did[1]
        elif len(did) == 2:
            ctx.obj.logger.warning('Ignoring input {} because dataset DID is already set {}:{}'.format(arg, dsscope, dsname))

    items: list["FileToUploadDict"] = []
    for arg in file_paths:
        if arg.count(':') > 0:
            continue
        if pfn and impl:
            ctx.obj.logger.warning('Ignoring --impl option because --pfn option given')
            impl = None

        item: "FileToUploadDict" = {'path': arg, 'rse': rse}

        if scope:
            item['did_scope'] = scope
        if lfn:
            item['did_name'] = lfn
        if dsscope:
            item['dataset_scope'] = dsscope
        if dsname:
            item['dataset_name'] = dsname
        if impl:
            item['impl'] = impl
        if protocol:
            item['force_scheme'] = protocol
        if pfn:
            item['pfn'] = pfn
        if no_register:
            item['no_register'] = True
        if register_after_upload:
            item['register_after_upload'] = True
        if lifetime is not None:
            item['lifetime'] = int(lifetime)
        if transfer_timeout is not None:
            item['transfer_timeout'] = int(transfer_timeout)
        if guid:
            item['guid'] = guid
        if recursive:
            item['recursive'] = True

        items.append(item)

    if len(items) < 1:
        raise InputValidationError('No files could be extracted from the given arguments')

    if len(items) > 1 and guid:
        ctx.obj.logger.error("A single GUID was specified on the command line, but there are multiple files to upload.")
        ctx.obj.logger.error("If GUID auto-detection is not used, only one file may be uploaded at a time")
        raise InputValidationError('Invalid input argument composition')

    if len(items) > 1 and lfn:
        ctx.obj.logger.error("A single LFN was specified on the command line, but there are multiple files to upload.")
        ctx.obj.logger.error("If LFN auto-detection is not used, only one file may be uploaded at a time")
        raise InputValidationError('Invalid input argument composition')

    if recursive and pfn:
        ctx.obj.logger.error("It is not possible to create the folder structure into collections with a non-deterministic way.")
        ctx.obj.logger.error("If PFN is specified, you cannot use --recursive")
        raise InputValidationError('Invalid input argument composition')

    upload_client = UploadClient(ctx.obj.client, logger=ctx.obj.logger)
    summary_file_path = 'rucio_upload.json' if summary else None
    upload_client.upload(items=items, summary_file_path=summary_file_path)
