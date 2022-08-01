# -*- coding: utf-8 -*-
# Copyright CERN since 2019
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

import datetime
import logging
import os

from rucio.common.config import config_get, config_get_int, get_config_dirs
from rucio.common.extra import import_extras
from rucio.core.monitor import record_counter

EXTRA_MODULES = import_extras(['globus_sdk'])

if EXTRA_MODULES['globus_sdk']:
    from globus_sdk import NativeAppAuthClient, RefreshTokenAuthorizer, TransferClient, TransferData, DeleteData  # pylint: disable=import-error
    import yaml  # pylint: disable=import-error

GLOBUS_AUTH_APP = config_get('conveyor', 'globus_auth_app', False, None)


def load_config(cfg_file='globus-config.yml', logger=logging.log):
    config = None
    config_dir = get_config_dirs()[0]
    if os.path.isfile(os.path.join(config_dir, cfg_file)):
        config = os.path.join(config_dir, cfg_file)
    else:
        logger(logging.ERROR, 'Could not find globus config file')
        raise Exception
    return yaml.safe_load(open(config).read())


def get_transfer_client(logger=logging.log):
    cfg = load_config(logger=logger)
    # cfg = yaml.safe_load(open("/opt/rucio/lib/rucio/transfertool/config.yml"))
    client_id = cfg['globus']['apps'][GLOBUS_AUTH_APP]['client_id']
    auth_client = NativeAppAuthClient(client_id)
    refresh_token = cfg['globus']['apps'][GLOBUS_AUTH_APP]['refresh_token']
    logger(logging.INFO, 'authorizing token...')
    authorizer = RefreshTokenAuthorizer(refresh_token=refresh_token, auth_client=auth_client)
    logger(logging.INFO, 'initializing TransferClient...')
    tc = TransferClient(authorizer=authorizer)
    return tc


def auto_activate_endpoint(tc, ep_id, logger=logging.log):
    r = tc.endpoint_autoactivate(ep_id, if_expires_in=3600)
    if r['code'] == 'AutoActivationFailed':
        logger(logging.CRITICAL, 'Endpoint({}) Not Active! Error! Source message: {}'.format(ep_id, r['message']))
        # sys.exit(1) # TODO: don't want to exit; hook into graceful exit
    elif r['code'] == 'AutoActivated.CachedCredential':
        logger(logging.INFO, 'Endpoint({}) autoactivated using a cached credential.'.format(ep_id))
    elif r['code'] == 'AutoActivated.GlobusOnlineCredential':
        logger(logging.INFO, ('Endpoint({}) autoactivated using a built-in Globus credential.').format(ep_id))
    elif r['code'] == 'AlreadyActivated':
        logger(logging.INFO, 'Endpoint({}) already active until at least {}'.format(ep_id, 3600))
    return r['code']


def submit_xfer(source_endpoint_id, destination_endpoint_id, source_path, dest_path, job_label, recursive=False, logger=logging.log):
    tc = get_transfer_client(logger=logger)
    # as both endpoints are expected to be Globus Server endpoints, send auto-activate commands for both globus endpoints
    auto_activate_endpoint(tc, source_endpoint_id, logger=logger)
    auto_activate_endpoint(tc, destination_endpoint_id, logger=logger)

    # from Globus... sync_level=checksum means that before files are transferred, Globus will compute checksums on the source and
    # destination files, and only transfer files that have different checksums are transferred. verify_checksum=True means that after
    # a file is transferred, Globus will compute checksums on the source and destination files to verify that the file was transferred
    # correctly.  If the checksums do not match, it will redo the transfer of that file.
    # tdata = TransferData(tc, source_endpoint_id, destination_endpoint_id, label=job_label, sync_level="checksum", verify_checksum=True)
    tdata = TransferData(tc, source_endpoint_id, destination_endpoint_id, label=job_label,
                         sync_level="checksum", notify_on_succeeded=False, notify_on_failed=False)
    tdata.add_item(source_path, dest_path, recursive=recursive)

    # logging.info('submitting transfer...')
    transfer_result = tc.submit_transfer(tdata)
    # logging.info("task_id =", transfer_result["task_id"])

    return transfer_result["task_id"]


def bulk_submit_xfer(submitjob, recursive=False, logger=logging.log):
    cfg = load_config(logger=logger)
    client_id = cfg['globus']['apps'][GLOBUS_AUTH_APP]['client_id']
    auth_client = NativeAppAuthClient(client_id)
    refresh_token = cfg['globus']['apps'][GLOBUS_AUTH_APP]['refresh_token']
    source_endpoint_id = submitjob[0].get('metadata').get('source_globus_endpoint_id')
    destination_endpoint_id = submitjob[0].get('metadata').get('dest_globus_endpoint_id')
    authorizer = RefreshTokenAuthorizer(refresh_token=refresh_token, auth_client=auth_client)
    tc = TransferClient(authorizer=authorizer)

    # make job_label for task a timestamp
    now = datetime.datetime.now()
    job_label = now.strftime('%Y%m%d%H%M%s')

    # retrieve globus_task_deadline value to enforce time window to complete transfers
    # default is 2880 minutes or 48 hours
    globus_task_deadline = config_get_int('conveyor', 'globus_task_deadline', False, 2880)
    deadline = now + datetime.timedelta(minutes=globus_task_deadline)

    # from Globus... sync_level=checksum means that before files are transferred, Globus will compute checksums on the source
    # and destination files, and only transfer files that have different checksums are transferred. verify_checksum=True means
    # that after a file is transferred, Globus will compute checksums on the source and destination files to verify that the
    # file was transferred correctly.  If the checksums do not match, it will redo the transfer of that file.
    tdata = TransferData(tc, source_endpoint_id, destination_endpoint_id, label=job_label, sync_level="checksum", deadline=str(deadline))

    for file in submitjob:
        source_path = file.get('sources')[0]
        dest_path = file.get('destinations')[0]
        filesize = file['metadata']['filesize']
        # TODO: support passing a recursive parameter to Globus
        # md5 = file['metadata']['md5']
        # tdata.add_item(source_path, dest_path, recursive=False, external_checksum=md5)
        tdata.add_item(source_path, dest_path, recursive=False)
        record_counter('daemons.conveyor.transfer_submitter.globus.transfers.submit.filesize', filesize)

    # logging.info('submitting transfer...')
    transfer_result = tc.submit_transfer(tdata)
    logger(logging.INFO, "transfer_result: %s" % transfer_result)

    return transfer_result["task_id"]


def check_xfer(task_id, logger=logging.log):
    tc = get_transfer_client(logger=logger)
    transfer = tc.get_task(task_id)
    status = str(transfer["status"])
    return status


def bulk_check_xfers(task_ids, logger=logging.log):
    tc = get_transfer_client(logger=logger)

    logger(logging.DEBUG, 'task_ids: %s' % task_ids)

    responses = {}

    for task_id in task_ids:
        transfer = tc.get_task(str(task_id))
        logger(logging.DEBUG, 'transfer: %s' % transfer)
        status = str(transfer["status"])
        if status == 'SUCCEEDED':
            record_counter('daemons.conveyor.transfer_submitter.globus.transfers.bytes_transferred', transfer['bytes_transferred'])
            record_counter('daemons.conveyor.transfer_submitter.globus.transfers.effective_bytes_per_second', transfer['effective_bytes_per_second'])
        responses[str(task_id)] = status

    logger(logging.DEBUG, 'responses: %s' % responses)

    return responses


def send_delete_task(endpoint_id=None, path=None, logger=logging.log):
    tc = get_transfer_client(logger=logger)
    ddata = DeleteData(tc, endpoint_id, recursive=True)
    ddata.add_item(path)
    delete_result = tc.submit_delete(ddata)

    return delete_result


def send_bulk_delete_task(endpoint_id=None, pfns=None, logger=logging.log):
    tc = get_transfer_client(logger=logger)
    ddata = DeleteData(tc, endpoint_id, recursive=True)
    for pfn in pfns:
        logger(logging.DEBUG, 'pfn: %s' % pfn)
        ddata.add_item(pfn)
    bulk_delete_result = tc.submit_delete(ddata)

    return bulk_delete_result
