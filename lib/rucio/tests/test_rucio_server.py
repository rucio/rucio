# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2014

import nose.tools
import subprocess


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


class TestRucioClient():

    def setup(self):
        self.marker = '$ > '

    def test_ping(self):
        """Client (USER): rucio ping"""
        cmd = 'rucio ping'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal(0, exitcode)
