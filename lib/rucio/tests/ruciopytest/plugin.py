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
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import xdist.dsession


def pytest_configure(config):
    config.addinivalue_line('markers', 'dirty: marks test as dirty, i.e. tests are leaving structures behind')
    config.addinivalue_line(
        'markers',
        'noparallel(reason): marks test being unable to run in parallel to other tests, i.e. changing global state',
    )
    if config.pluginmanager.hasplugin('xdist'):
        from rucio.tests.ruciopytest.rucioxdist import NoParallelXDist

        config.pluginmanager.register(NoParallelXDist(config))


def pytest_addoption(parser):
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


def pytest_xdist_make_scheduler(config, log):
    dist = config.getoption('dist', default='load')

    if dist == 'rucio':
        from rucio.tests.ruciopytest.rucioxdist import NoParallelAndLoadScheduling

        return NoParallelAndLoadScheduling(config=config, log=log)
    else:
        dsession = config.pluginmanager.getplugin('dsession')  # type: xdist.dsession.DSession
        return dsession.pytest_xdist_make_scheduler(config=config, log=log)
