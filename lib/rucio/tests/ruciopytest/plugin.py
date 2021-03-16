# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
#
# Authors:
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

import os
import sys

import pytest


def pytest_configure(config):
    config.addinivalue_line('markers', 'dirty: marks test as dirty, i.e. tests are leaving structures behind')
    config.addinivalue_line(
        'markers',
        'noparallel(reason): marks test being unable to run in parallel to other tests, i.e. changing global state',
    )
    if sys.version_info >= (3, 6) and config.pluginmanager.hasplugin('xdist'):
        from rucio.tests.ruciopytest.rucioxdist import NoParallelXDist

        config.pluginmanager.register(NoParallelXDist(config))


if sys.version_info >= (3, 6):
    def pytest_addoption(parser, pluginmanager):
        if pluginmanager.hasplugin('xdist'):
            group = parser.getgroup('xdist', 'distributed and subprocess testing')
            option_appended = False
            for opt in group.options:
                if '--dist' in opt.names():
                    option_choices = opt._attrs['choices']
                    option_choices.append('rucio')
                    option_appended = True
                    break

            if not option_appended:
                raise pytest.UsageError('rucio pytest plugin must be loaded after xdist plugin')


def pytest_cmdline_main(config):
    # prevent bad behavior
    if os.environ.get('GITHUB_ACTIONS', '') == 'true':
        if config.getoption('usepdb', False):
            raise pytest.UsageError('Cannot use pdb on GitHub Actions')
