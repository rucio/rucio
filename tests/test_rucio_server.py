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

from os import remove
from os.path import basename

import pytest

from rucio.common.utils import execute
from rucio.common.utils import generate_uuid as uuid

MARKER = '$ > '


def delete_rules(did):
    # get the rules for the file
    print('Deleting rules')
    cmd = "rucio rule list {0} | grep {0} | cut -f1 -d\\ ".format(did)
    print(cmd)
    exitcode, out, err = execute(cmd)
    print(out, err)
    rules = out.split()
    # delete the rules for the file
    for rule in rules:
        cmd = "rucio rule remove {0}".format(rule)
        print(cmd)
        exitcode, out, err = execute(cmd)


@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestRucioServer:

    def test_ping(self):
        """CLIENT (USER): rucio ping"""
        cmd = 'rucio ping'
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

    def test_whoami(self):
        """CLIENT (USER): rucio whoami"""
        cmd = 'rucio whoami'
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

    def test_upload_download(self, file_factory, scope_and_rse):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""

        scope, rse = scope_and_rse

        if rse is None:
            return

        tmp_file1 = file_factory.file_generator()
        tmp_file2 = file_factory.file_generator()
        tmp_file3 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_' + uuid()

        # Adding files to a new dataset
        cmd = 'rucio -v did upload --rse {0} --scope {1} --files {2} {3} {4} {1}:{5}'.format(rse, scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        assert exitcode == 0

        # List the files
        cmd = 'rucio did content list --did {0}:{1}'.format(scope, tmp_dsn)
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the replicas
        cmd = 'rucio replica list --did {0}:{1}'.format(scope, tmp_dsn)
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # Downloading dataset
        cmd = 'rucio did download --dir /tmp/ --did {0}:{1}'.format(scope, tmp_dsn)
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn)
        print(MARKER + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        assert exitcode == 0

        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn) + basename(tmp_file1))
        remove('/tmp/{0}/'.format(tmp_dsn) + basename(tmp_file2))
        remove('/tmp/{0}/'.format(tmp_dsn) + basename(tmp_file3))
        added_dids = ['{0}:{1}'.format(scope, did) for did in (basename(tmp_file1), basename(tmp_file2), basename(tmp_file3), tmp_dsn)]

        # Delete rules
        for did in added_dids:
            delete_rules(did)
