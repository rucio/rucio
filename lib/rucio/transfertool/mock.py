from rucio.transfertool.transfertool import Transfertool
import uuid


class MockTransfertool(Transfertool):
    """
    Mock implementation of a Rucio transfertool
    """

    def __init__(self, external_host, token=None):
        super(FTS3Transfertool, self).__init__(external_host)

    def submit(self, files, job_params, timeout=None):
        return uuid.uuid1()

    def query(self, transfer_ids, details=False, timeout=None):
        return [{'status': 'ok', 'idontknowthefields': True}]

    def cancel(self, transfer_ids, timeout=None):
        return True

    def update_priority(self, transfer_id, priority, timeout=None):
        return True
