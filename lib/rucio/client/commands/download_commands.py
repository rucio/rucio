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

import click

from rucio.client.commands.bin_legacy.rucio import download as download_exe
from rucio.client.commands.utils import Arguments
from rucio.common.config import config_get_float


@click.command()
@click.argument("dids", nargs=-1)
@click.option("--dir", default=".", help="The directory to store the downloaded file.")
@click.option("--allow-tape/--no-allow-tape", default=False, help="Also consider tape endpoints as source of the download.")
@click.option("--rses", "--rse-exp", help="RSE Expression to specify allowed sources")
@click.option("--impl", help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone).")
@click.option("--protocol", help="Force the protocol to use.")
@click.option("--nrandom", type=int, help="Download N random files from the DID.")
@click.option("--ndownloader", type=int, default=3, help="Choose the number of parallel processes for download.")
@click.option("--no-subdir/--subdir", default=False, help="Don't create a subdirectory for the scope of the files.")
@click.option("--pfn", help="Specify the exact PFN for the download.")
@click.option("--no-resolve-archives/--resolve-archives", default=False, help="If set archives will not be considered for download.")
@click.option("--ignore-checksum/--no-ignore-checksum", default=False, help="Don't validate checksum for downloaded files.")
@click.option("--check-local-with-filesize-only/--no-check-local-with-filesize-only", default=False, help="Don't use checksum verification for already downloaded files, use filesize instead.")
@click.option(
    "--transfer-timeout",
    type=float,
    default=config_get_float("download", "transfer_timeout", False, None),
    help="Transfer timeout (in seconds). Default: computed dynamically from --transfer-speed-timeout. If set to any value >= 0, --transfer-speed-timeout is ignored.",
)  # NOQA: E501
@click.option("--transfer-speed-timeout", type=float, default=None, help="Minimum allowed average transfer speed (in KBps). Default: 500. Used to dynamically compute the timeout if --transfer-timeout not set. Is not supported for --pfn.")  # NOQA: E501
@click.option("--aria/--no-aria", default=False, help="Use aria2c utility if possible. (EXPERIMENTAL)")
@click.option("--archive-did", hidden=True)  # Download from archive is transparent. This option is obsolete.
@click.option("--trace-appid", default=os.environ.get("RUCIO_TRACE_APPID", None), hidden=True)
@click.option("--trace-dataset", default=os.environ.get("RUCIO_TRACE_DATASET", None), hidden=True)
@click.option("--trace-datasetscope", default=os.environ.get("RUCIO_TRACE_DATASETSCOPE", None), hidden=True)
@click.option("--trace-eventtype", default=os.environ.get("RUCIO_TRACE_EVENTTYPE", None), hidden=True)
@click.option("--trace-pq", default=os.environ.get("RUCIO_TRACE_PQ", None), hidden=True)
@click.option("--trace-taskid", default=os.environ.get("RUCIO_TRACE_TASKID", None), hidden=True)
@click.option("--trace-usrdn", default=os.environ.get("RUCIO_TRACE_USRDN", None), hidden=True)
@click.option("--filter", help="Filter files by key-value pairs like guid=2e2232aafac8324db452070304f8d745.")
@click.option("--scope", help="Scope if you are using the filter option and no full DID.")
@click.option("--metalink", help="Path to a metalink file.")
@click.option("--no-show-download-exceptions/--show-download-exceptions", default=False, help="Does not raise NoFilesDownloaded, NotAllFilesDownloaded or incorrect number of output queue files Exception.")  # NOQA: E501
@click.option("--replica-selection", help="Select the best replica using a replica sorting algorithm provided by replica sorter (e.g., random, geoip).")
@click.pass_context
def download(
    ctx,
    dids,
    dir,
    allow_tape,
    rses,
    impl,
    protocol,
    nrandom,
    ndownloader,
    no_subdir,
    pfn,
    no_resolve_archives,
    ignore_checksum,
    check_local_with_filesize_only,
    transfer_timeout,
    transfer_speed_timeout,
    aria,
    archive_did,
    trace_appid,
    trace_dataset,
    trace_datasetscope,
    trace_eventtype,
    trace_pq,
    trace_taskid,
    trace_usrdn,
    filter,
    scope,
    metalink,
    no_show_download_exceptions,
    replica_selection,
):
    """
    Download DID(s) (in the form of scope:name) to a local dir
    """
    args = Arguments(
        {
            "dids": dids,
            "dir": dir,
            "allow_tape": allow_tape,
            "rses": rses,
            "impl": impl,
            "protocol": protocol,
            "nrandom": nrandom,
            "ndownloader": ndownloader,
            "no_subdir": no_subdir,
            "pfn": pfn,
            "no_resolve_archives": no_resolve_archives,
            "ignore_checksum": ignore_checksum,
            "check_local_with_filesize_only": check_local_with_filesize_only,
            "transfer_timeout": transfer_timeout,
            "transfer_speed_timeout": transfer_speed_timeout,
            "aria": aria,
            "archive_did": archive_did,
            "trace_appid": trace_appid,
            "trace_dataset": trace_dataset,
            "trace_datasetscope": trace_datasetscope,
            "trace_eventtype": trace_eventtype,
            "trace_pq": trace_pq,
            "trace_taskid": trace_taskid,
            "trace_usrdn": trace_usrdn,
            "filter": filter,
            "scope": scope,
            "metalink_file": metalink,
            "deactivate_file_download_exceptions": no_show_download_exceptions,
            "sort": replica_selection,
        }
    )
    download_exe(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
