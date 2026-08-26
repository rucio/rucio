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
from copy import deepcopy
from datetime import datetime

import click

from rucio.cli.utils import get_scope
from rucio.common.exception import InputValidationError
from rucio.common.utils import chunks


def __resolve_containers_to_datasets(scope, name, client):
    """
    Helper function to resolve a container into its dataset content.
    """
    datasets = []
    for did in client.list_content(scope, name):
        if did['type'] == 'DATASET':
            datasets.append({'scope': did['scope'], 'name': did['name']})
        elif did['type'] == 'CONTAINER':
            datasets.extend(__resolve_containers_to_datasets(did['scope'], did['name'], client))
    return datasets


@click.group()
def lifetime_exception():
    """Interact with the lifetime exception model"""


@lifetime_exception.command("add")
@click.option("-f", "--input-file", required=True, help="File where the list of datasets requested to be extended are located")
@click.option("--reason", required=True, help="The reason for the extension")
@click.option("-x", "--expiration", required=True, help="The expiration date format YYYY-MM-DD")
@click.pass_context
def add_(ctx: click.Context, input_file: str, reason: str, expiration: str) -> None:
    """Add an exception to the lifetime model"""

    if not reason:
        raise InputValidationError('reason for the extension is mandatory')
    if not expiration:
        raise InputValidationError('expiration is mandatory')
    try:
        expiration_date = datetime.strptime(expiration, "%Y-%m-%d")
    except Exception as err:
        msg = f'Cannot parse expiration date: {err}'
        raise ValueError(msg)

    if not input_file:
        raise InputValidationError('inputfile is mandatory')
    with open(input_file) as infile:
        # Deduplicate the content of the input file and ignore empty lines.
        dids = set(did for line in infile if (did := line.strip()))

    dids_list = []
    containers = []
    datasets = []
    for did in dids:
        scope, name = get_scope(did, ctx.obj.client)
        dids_list.append({'scope': scope, 'name': name})
    error_summary = {
        "total_dids": {"description": "Total DIDs", "count": len(dids_list)},
        "files_ignored": {"description": "DID not submitted because it is a file", "count": 0},
        "containers_resolved": {"description": "DID that are containers and were resolved", "count": 0},
        "not_in_lifetime_model": {"description": "DID not submitted because it is not part of the lifetime campaign", "count": 0},
        "successfully_submitted": {"description": "DID successfully submitted including the one from containers resolved", "count": 0},
    }
    chunk_limit = 500  # Server should be able to accept 1000
    dids_list_copy = deepcopy(dids_list)
    for chunk in chunks(dids_list_copy, chunk_limit):
        for meta in ctx.obj.client.get_metadata_bulk(chunk):
            scope, name = meta['scope'], meta['name']
            dids_list.remove({'scope': scope, 'name': name})
            if meta['did_type'] == 'FILE':
                ctx.obj.logger.warning('%s:%s is a file. Will be ignored' % (scope, name))
                error_summary["files_ignored"]["count"] += 1
            elif meta['did_type'] == 'CONTAINER':
                ctx.obj.logger.warning('%s:%s is a container. It needs to be resolved' % (scope, name))
                containers.append({'scope': scope, 'name': name})
                error_summary["containers_resolved"]["count"] += 1
            elif not meta['eol_at']:
                ctx.obj.logger.warning('%s:%s is not affected by the lifetime model' % (scope, name))
                error_summary["not_in_lifetime_model"]["count"] += 1
            else:
                ctx.obj.logger.info('%s:%s will be declared' % (scope, name))
                datasets.append({'scope': scope, 'name': name})
                error_summary["successfully_submitted"]["count"] += 1

    for did in dids_list:
        scope = did['scope']
        name = did['name']
        ctx.obj.logger.warning('%s:%s does not exist' % (scope, name))

    if containers:
        ctx.obj.logger.warning('One or more DIDs are containers. They will be resolved into a list of datasets to request exception. Full list below')
        for container in containers:
            ctx.obj.logger.info('Resolving %s:%s into datasets :' % (container['scope'], container['name']))
            list_datasets = __resolve_containers_to_datasets(container['scope'], container['name'], ctx.obj.client)
            for chunk in chunks(list_datasets, chunk_limit):
                for meta in ctx.obj.client.get_metadata_bulk(chunk):
                    scope, name = meta['scope'], meta['name']
                    ctx.obj.logger.debug('%s:%s' % (scope, name))
                    if not meta['eol_at']:
                        ctx.obj.logger.warning('%s:%s is not affected by the lifetime model' % (scope, name))
                        error_summary["not_in_lifetime_model"]["count"] += 1
                    else:
                        ctx.obj.logger.info('%s:%s will be declared' % (scope, name))
                        datasets.append({'scope': scope, 'name': name})
                        error_summary["successfully_submitted"]["count"] += 1
    if not datasets:
        ctx.obj.logger.error('Nothing to submit')
        return

    ctx.obj.client.add_exception(dids=datasets, account=ctx.obj.client.account, pattern='', comments=reason, expires_at=expiration_date)

    ctx.obj.logger.info('Exception successfully submitted. Summary below:')
    for key, data in error_summary.items():
        print('{0:100} {1:6d}'.format(data["description"], data["count"]))
