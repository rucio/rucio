#!/usr/bin/env python
#
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne(CERN PH-ADP), <vincent.garonne@cern.ch>, 2011


import subprocess
import sys


def _run_shell_command(cmd):
    output = subprocess.Popen(["/bin/sh", "-c", cmd],
                              stdout=subprocess.PIPE)
    return output.communicate()[0].strip()

if __name__ == '__main__':

    cmd = 'nosetests -v --with-coverage --cover-package=rucio'
    _run_shell_command(cmd)

    cmd = 'pep8 --repeat --ignore=E501 lib'
    _run_shell_command(cmd)
