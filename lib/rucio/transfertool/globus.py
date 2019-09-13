from exceptions import NotImplementedError
from rucio.common.config import config_get
from rucio.transfertool.transfertool import Transfertool
from rucio.db.sqla.constants import RequestState
from globusLibrary import bulk_submit_xfer, submit_xfer, bulk_check_xfers, check_xfer
import logging

class GlobusTransferTool(Transfertool):
    """
    Globus implementation of Transfertool abstract base class
    """
    def __init__(self, external_host):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """
        # TODO: initialize vars from config file here

    def submit(self, files, job_params, timeout=None):
        """
        Submit transfers to globus API

        :param files:        List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            Globus transfer identifier.
        """

        source_path = files[0]['sources'][0]
        logging.info('source_path: %s' % source_path)

        source_endpoint_id = files[0]['metadata']['source_globus_endpoint_id']

        # TODO: use prefix from rse_protocol to properly construct destination url
        # parse and assemble dest_path for Globus endpoint
        dest_path = files[0]['destinations'][0]
        logging.info('dest_path: %s' % dest_path)

        # TODO: rucio.common.utils.construct_url logic adds unnecessary '/other' into file path
        # s = dest_path.split('/') # s.remove('other') # dest_path = '/'.join(s)

        destination_endpoint_id = files[0]['metadata']['dest_globus_endpoint_id']
        job_label = files[0]['metadata']['request_id']

        task_id = submit_xfer(source_endpoint_id, destination_endpoint_id, source_path, dest_path, job_label, recursive=False)

        return task_id

    def bulk_submit(self, submitjob, timeout=None):
        """
        Submit a bulk transfer to globus API

        :param files:        List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            Globus transfer identifier.
        """

        # TODO: support passing a recursive parameter to Globus
        task_id = bulk_submit_xfer(submitjob, recursive = False)

        return task_id

    def bulk_query(self, transfer_ids, timeout=None):
        """
        Query the status of a bulk of transfers in globus API

        :param transfer_ids: Globus task identifiers as a list.
        :returns: Transfer status information as a dictionary.
        """

        jobs = None

        if not isinstance(transfer_ids, list):
            transfer_ids = [transfer_ids]

        job_responses = bulk_check_xfers(transfer_ids)

        return job_responses

    def bulk_update(resps, request_ids):
        """
        bulk update request_state for globus transfers

        :param resps: dictionary containing task IDs and current status
        # TODO: do we need request IDs?
        :param request_ids original list of rucio request IDs

        counter = 0
        for task_id in resps:
            requests = get_requests_by_transfer(external_host=None, transfer_id=task_id, session=None)
            logging.debug('requests: %s' % requests)
            for request_id in requests:
                transfer_core.update_transfer_state(external_host=None, transfer_id=request_id, state=resps[task_id][file_state])
                counter += 1

        return counter
        """

    def cancel():
        pass

    def query(self, transfer_ids, details=False, timeout=None):
        """
        Query the status of a transfer in Globus Online.

        :param transfer_ids: transfer identifiers as list of strings.
        :param details:      Switch if detailed information should be listed.
        :param timeout:      Timeout in seconds.
        :returns:            Transfer status information as a list of dictionaries.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('Globus Transfer Client not bulk ready. Only one task ID at a time')

        transfer_id = transfer_ids[0]

        status = check_xfer(transfer_id)

        pass
    def update_priority():
        pass
