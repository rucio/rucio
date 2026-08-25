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
from typing import Literal, Optional

import click

from rucio.client.downloadclient import DownloadClient
from rucio.common.client import detect_client_location
from rucio.common.config import config_get_float
from rucio.common.exception import InputValidationError, InvalidType, RSENotFound, RucioException
from rucio.common.utils import parse_did_filter_from_string


def _get_rse_for_pfn(replicas, pfn) -> Optional[str]:
    # Check each rse in the replica list for the pfn. If no pfn is found, returns None.
    # If it is found, stop the generator and return the item.
    for replica in replicas:
        try:
            download_rse = next(
                rse for rse in replica['rses']
                if pfn in replica['rses'][rse]
            )
        except StopIteration:
            continue
        else:
            return download_rse


@click.command()
@click.argument("dids", nargs=-1)
@click.option("--dir", default=".", help="The directory to store the downloaded file.")
@click.option("--allow-tape", is_flag=True, default=False, help="Also consider tape endpoints as source of the download.")
@click.option("--rses", "--rse-exp", help="RSE Expression to specify allowed sources")
@click.option("--impl", help="Transfer protocol implementation to use (e.g: xrootd, gfal.NoRename, webdav, ssh.Rsync, rclone).")
@click.option("--protocol", help="Force the protocol to use.")
@click.option("--nrandom", type=int, help="Download N random files from the DID.")
@click.option("--ndownloader", type=int, default=3, help="Choose the number of parallel processes for download.")
@click.option("--no-subdir", is_flag=True, default=False, help="Don't create a subdirectory for the scope of the files.")
@click.option("--pfn", help="Specify the exact PFN for the download.")
@click.option("--no-resolve-archives", is_flag=True, default=False, help="If set archives will not be considered for download.")
@click.option("--ignore-checksum", is_flag=True, default=False, help="Don't validate checksum for downloaded files.")
@click.option("--check-local-with-filesize-only", is_flag=True, default=False, help="Don't use checksum verification for already downloaded files, use filesize instead.")
@click.option(
    "--transfer-timeout",
    type=float,
    default=config_get_float("download", "transfer_timeout", False, None),
    help="Transfer timeout (in seconds). Default: computed dynamically from --transfer-speed-timeout. If set to any value >= 0, --transfer-speed-timeout is ignored.",
)  # NOQA: E501
@click.option("--transfer-speed-timeout", type=float, default=None, help="Minimum allowed average transfer speed (in KBps). Default: 500. Used to dynamically compute the timeout if --transfer-timeout not set. Is not supported for --pfn.")  # NOQA: E501
@click.option("--aria", default=False, help="Use aria2c utility if possible. (EXPERIMENTAL)")
@click.option("--trace-appid", envvar="RUCIO_TRACE_APPID", hidden=True)
@click.option("--trace-dataset", envvar="RUCIO_TRACE_DATASET", hidden=True)
@click.option("--trace-datasetscope", envvar="RUCIO_TRACE_DATASETSCOPE", hidden=True)
@click.option("--trace-eventtype", envvar="RUCIO_TRACE_EVENTTYPE", hidden=True)
@click.option("--trace-pq", envvar="RUCIO_TRACE_PQ", hidden=True)
@click.option("--trace-taskid", envvar="RUCIO_TRACE_TASKID", hidden=True)
@click.option("--trace-usrdn", envvar="RUCIO_TRACE_USRDN", hidden=True)
@click.option("--filter", help="Filter files by key-value pairs like guid=2e2232aafac8324db452070304f8d745.")
@click.option("--scope", help="Scope to use as a filter or to use with DID names.")
@click.option("--metalink", help="Path to a metalink file.")
@click.option("--no-show-download-exceptions", default=False, is_flag=True, help="Does not raise NoFilesDownloaded, NotAllFilesDownloaded or incorrect number of output queue files Exception.")  # NOQA: E501
@click.option(
    "--replica-selection",
    help="Select the best replica using a replica sorting algorithm provided by replica sorter (e.g., random, geoip).",
    type=click.Choice(['random', 'geoip', 'custom_table']))
@click.pass_context
def download(
    ctx: click.Context,
    dids: tuple[str, ...],
    dir: str,
    allow_tape: bool,
    rses: Optional[str],
    impl: Optional[str],
    protocol: Optional[str],
    nrandom: Optional[int],
    ndownloader: int,
    no_subdir: bool,
    pfn: Optional[str],
    no_resolve_archives: bool,
    ignore_checksum: bool,
    check_local_with_filesize_only: bool,
    transfer_timeout: int,
    transfer_speed_timeout: Optional[float],
    aria: Optional[str],
    trace_appid: Optional[str],
    trace_dataset: Optional[str],
    trace_datasetscope: Optional[str],
    trace_eventtype: Optional[str],
    trace_pq: Optional[str],
    trace_taskid: Optional[str],
    trace_usrdn: Optional[str],
    filter: Optional[str],
    scope: Optional[str],
    metalink: Optional[str],
    no_show_download_exceptions: bool,
    replica_selection: Optional[Literal['geoip', 'custom_table', 'random']]
) -> None:
    """
    Download DID(s) (in the form of scope:name) to a local dir
    """
    if not dids and not filter and not metalink:
        raise InputValidationError('At least one did is mandatory')
    elif not dids and filter and not scope:
        raise InputValidationError('The argument scope is mandatory')

    if filter and metalink:
        raise InputValidationError('Arguments filter and metalink cannot be used together.')

    if dids and metalink:
        raise InputValidationError('Arguments dids and metalink cannot be used together.')

    if ignore_checksum and check_local_with_filesize_only:
        raise InputValidationError('Arguments ignore-checksum and check-local-with-filesize-only cannot be used together.')

    trace_pattern = {}

    if trace_appid:
        trace_pattern['appid'] = trace_appid
    if trace_dataset:
        trace_pattern['dataset'] = trace_dataset
    if trace_datasetscope:
        trace_pattern['datasetScope'] = trace_datasetscope
    if trace_eventtype:
        trace_pattern['eventType'] = trace_eventtype
    if trace_pq:
        trace_pattern['pq'] = trace_pq
    if trace_taskid:
        trace_pattern['taskid'] = trace_taskid
    if trace_usrdn:
        trace_pattern['usrdn'] = trace_usrdn
    deactivate_file_download_exceptions = no_show_download_exceptions if no_show_download_exceptions is not None else False

    download_client = DownloadClient(client=ctx.obj.client, logger=ctx.obj.logger, check_admin=allow_tape)

    result = None
    item_defaults = {}
    item_defaults['rse'] = rses
    item_defaults['base_dir'] = dir
    item_defaults['no_subdir'] = no_subdir
    item_defaults['transfer_timeout'] = transfer_timeout
    item_defaults['no_resolve_archives'] = no_resolve_archives
    item_defaults['ignore_checksum'] = ignore_checksum
    item_defaults['check_local_with_filesize_only'] = check_local_with_filesize_only

    # Get filters
    filters = {}
    type_ = 'all'
    if filter:
        try:
            filters, type_ = parse_did_filter_from_string(filter)
            if scope:
                filters['scope'] = scope
        except (InvalidType, ValueError) as error:
            ctx.obj.logger.error(error)
            raise error
        except Exception as error:
            ctx.obj.logger.error("Invalid Filter. Filter must be 'key=value', 'key>=value', 'key>value', 'key<=value', 'key<value'")
            raise error
        item_defaults['filters'] = filters

    if not pfn:
        item_defaults['impl'] = impl
        item_defaults['force_scheme'] = protocol
        item_defaults['nrandom'] = nrandom
        item_defaults['transfer_speed_timeout'] = transfer_speed_timeout \
            if transfer_speed_timeout is not None \
            else config_get_float('download', 'transfer_speed_timeout', False, 500)
        items = []
        if dids:
            for did in dids:
                if scope:
                    did = f"{scope}:{did}"
                item = {'did': did}
                item.update(item_defaults)
                items.append(item)
        else:
            items.append(item_defaults)

        if aria:
            result = download_client.download_aria2c(items, trace_pattern, deactivate_file_download_exceptions=deactivate_file_download_exceptions, sort=replica_selection)
        elif metalink:
            result = download_client.download_from_metalink_file(items[0], metalink, deactivate_file_download_exceptions=deactivate_file_download_exceptions)
            if replica_selection:
                ctx.obj.logger.warning('Ignoring --replica-selection option because --metalink option given')
        else:
            result = download_client.download_dids(items, ndownloader, trace_pattern, deactivate_file_download_exceptions=deactivate_file_download_exceptions, sort=replica_selection)
    else:
        if aria:
            ctx.obj.logger.warning('Ignoring --aria option because --pfn option given')
        if impl:
            ctx.obj.logger.warning('Ignoring --impl option because --pfn option given')
        if protocol:
            ctx.obj.logger.warning('Ignoring --protocol option because --pfn option given')
        if transfer_speed_timeout:
            ctx.obj.logger.warning("Download with --pfn doesn't support --transfer-speed-timeout")
        num_dids = len(dids)
        did_str = dids[0]
        if num_dids > 1:
            ctx.obj.logger.warning('Download with --pfn option only supports one DID but {} DIDs were given. Considering only first DID: {}'.format(num_dids, did_str))
            ctx.obj.logger.debug(dids)
        item_defaults['pfn'] = pfn
        item_defaults['did'] = did_str
        if rses is None:
            ctx.obj.logger.warning("No RSE was given, selecting one.")
            if not scope:
                scope = did_str.split(':')[0]
                did = did_str.split(':')[-1]
            else:
                did = did_str.split(':')[-1]

            replicas = ctx.obj.client.list_replicas(
                [{"scope": scope, "name": did}],
                schemes=protocol,
                ignore_availability=False,
                client_location=detect_client_location(),
                resolve_archives=not no_resolve_archives
            )

            download_rse = _get_rse_for_pfn(replicas, pfn)
            if download_rse is None:
                raise RSENotFound("Could not find RSE for pfn %s" % pfn)
            else:
                item_defaults['rse'] = download_rse

        result = download_client.download_pfns([item_defaults], 1, trace_pattern, deactivate_file_download_exceptions=deactivate_file_download_exceptions)

    if not result:
        raise RucioException('Download API failed')

    summary = {}
    for item in result:
        for did, did_stats in item.get('input_dids', {}).items():
            did_summary = summary.setdefault(did, {'length': did_stats.get('length'), 'DONE': 0, 'ALREADY_DONE': 0, '_total': 0})
            did_summary['_total'] += 1
            state = item['clientState'].upper()
            if state in did_summary:
                did_summary[state] += 1

    print('----------------------------------')
    print('Download summary')
    if not len(summary):
        print('-' * 40)
        print('No DID matching the pattern')

    for summary_key, did_summary in summary.items():
        print('-' * 40)
        print('DID %s' % summary_key)
        length = did_summary['length']
        ds_total = did_summary['_total']
        downloaded_files = did_summary['DONE']
        local_files = did_summary['ALREADY_DONE']
        not_downloaded_files = ds_total - downloaded_files - local_files

        if length:
            print('{0:40} {1:6d}'.format('Total files (DID): ', length))
            print('{0:40} {1:6d}'.format('Total files (filtered):   ', ds_total))
        else:
            print('{0:40} {1:6d}'.format('Total files:   ', ds_total))
        print('{0:40} {1:6d}'.format('Downloaded files: ', downloaded_files))
        print('{0:40} {1:6d}'.format('Files already found locally: ', local_files))
        print('{0:40} {1:6d}'.format('Files that cannot be downloaded: ', not_downloaded_files))
