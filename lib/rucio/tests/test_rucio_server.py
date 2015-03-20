# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

import nose.tools
import subprocess
from os import remove
from rucio.common.utils import generate_uuid as uuid


def execute(cmd):
    """
    Executes a command in a subprocess. Returns a tuple
    of (exitcode, out, err), where out is the string output
    from stdout and err is the string output from stderr when
    executing the command.

    :param cmd: Command string to execute
    """
    process = subprocess.Popen(cmd,
                               shell=True,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out = ''
    err = ''
    exitcode = 0

    result = process.communicate()
    (out, err) = result
    exitcode = process.returncode
    return exitcode, out, err


def file_generator(size=2048, namelen=10):
    """ Create a bogus file and returns it's name.
    :param size: size in bytes
    :returns: The name of the generated file.
    """
    fn = '/tmp/rucio_testfile_' + uuid()
    execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fn, size))
    return fn


def delete_rules(did):
    # get the rules for the file
    print 'Deleting rules'
    cmd = "rucio list-rules --did {0} | grep {0} | cut -f1 -d\ ".format(did)
    print cmd
    exitcode, out, err = execute(cmd)
    print out, err
    rules = out.split()
    # delete the rules for the file
    for rule in rules:
        cmd = "rucio delete-rule {0}".format(rule)
        print cmd
        exitcode, out, err = execute(cmd)


class TestRucioClient():

    def setup(self):
        self.marker = '$ > '
        self.scope = 'mock'
        self.rse = 'MOCK-POSIX'
        self.generated_dids = []

    def tearDown(self):
        for did in self.generated_dids:
            delete_rules(did)
            self.generated_dids.remove(did)

    def test_ping(self):
        """CLIENT (USER): rucio ping"""
        cmd = 'rucio ping'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal(0, exitcode)

    def test_whoami(self):
        """CLIENT (USER): rucio whoami"""
        cmd = 'rucio whoami'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal(0, exitcode)

    def test_upload_download(self):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_' + uuid()

        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {1}:{5}'.format(self.rse, self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_equal(0, exitcode)

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_equal(0, exitcode)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_equal(0, exitcode)

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1}'.format(self.scope, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(self.scope)
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print err, out
        nose.tools.assert_equal(0, exitcode)
        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file1[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file2[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file3[5:])
        self.generated_dids + '{0}:{1} {0}:{2} {0}:{3} {0}:{4}'.format(self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn).split(' ')
