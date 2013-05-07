# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
This submits a transfer to FTS3 via the transfertool.
"""

from rucio.common.utils import generate_uuid
from rucio.transfertool.fts3 import submit

if __name__ == "__main__":

    src_urls = ['srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/atlasscratchdisk/rucio_tests/tests/e0/f4/1k-file-7776DF9328AE48408830DE561D2A7A15']
    dest_urls = ['srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/atlasscratchdisk/rucio_tests/tests/e0/f4/1k-file-%s' % generate_uuid()]

    src_spacetoken = 'ATLASSCRATCHDISK'
    dest_spacetoken = 'ATLASSCRATCHDISK'
    filesize = 1024000L
    checksum = 'adler32:a0e10001'
    overwrite = False
    job_metadata = {'request_id': generate_uuid()}
    mock = False

    submit(src_urls, dest_urls, src_spacetoken, dest_spacetoken, filesize, checksum, overwrite, job_metadata, mock)
