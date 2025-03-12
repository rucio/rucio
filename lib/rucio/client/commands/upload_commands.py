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
import click

from rucio.client.commands.bin_legacy.rucio import upload
from rucio.client.commands.utils import Arguments
from rucio.common.config import config_get_float


@click.command("upload")
@click.argument("file-paths", nargs=-1)
@click.option("--rse", "--rse-name", help="Rucio Storage Element (RSE) name", required=True)
@click.option("--lifetime", type=int, help="Lifetime of the rule in seconds")
@click.option("--expiration-date", help="The date when the rule expires in UTC, format: <year>-<month>-<day>-<hour>:<minute>:<second>. E.g. 2022-10-20-20:00:00")
@click.option("--scope", help="Scope name.")
@click.option("--impl", type=click.Choice([]), help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone)")
# The --no-register option is hidden. This is pilot ONLY. Users should not use this. Will lead to unregistered data on storage!
@click.option("--register/--no-register", default=False, hidden=True)
@click.option("--register-after-upload/--no-register-after-upload", default=False, help="Register the file only after successful upload")
@click.option("--summary/--no-summary", default=False, help="Create rucio_upload.json summary file")
@click.option("--guid", help="Manually specify the GUID for the file.")
@click.option("--protocol", help="Force the protocol to use")
@click.option("--pfn", help="Specify the exact PFN for the upload")
@click.option("--lfn", help="Specify the exact LFN for the upload")
@click.option("--transfer-timeout", type=float, default=config_get_float("upload", "transfer_timeout", False, 360), help="Transfer timeout (in seconds)")
@click.option("-r", "--recursive/--no-recursive", default=False, help="Convert recursively the folder structure into collections")
@click.pass_context
def upload_command(ctx, file_paths, rse, lifetime, expiration_date, scope, impl, register, register_after_upload, summary, guid, protocol, pfn, lfn, transfer_timeout, recursive):
    """Upload file(s) to a Rucio RSE"""
    args = Arguments(
        {
            "args": file_paths,
            "rse": rse,
            "lifetime": lifetime,
            "expiration_date": expiration_date,
            "scope": scope,
            "impl": impl,
            "register": register,
            "register_after_upload": register_after_upload,
            "protocol": protocol,
            "summary": summary,
            "guid": guid,
            "pfn": pfn,
            "name": lfn,
            "transfer_timeout": transfer_timeout,
            "recursive": recursive,
        }
    )
    upload(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
