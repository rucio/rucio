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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021

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

        # Initialization hook to add --artifacts option, can be used by integration or TPC tests to further check non-dev container states
        parser.addoption(
            "--export-artifacts-from",
            action="append",
            dest="artifacts",
            default=[],
            help="A csv string with test names that should persist their artifacts"
        )

    def pytest_generate_tests(metafunc):
        tests_with_artifacts = metafunc.config.getoption('artifacts')
        if len(tests_with_artifacts) > 1:
            raise pytest.UsageError('--export-artifacts-from must be used only once. It should contain a CSV string of test names that can manage artifacts.')

        if len(tests_with_artifacts) == 1:
            tests_with_artifacts = tests_with_artifacts[0].split(',')
            test_function_name = metafunc.function.__name__
            if "artifact" in metafunc.fixturenames:
                if test_function_name in tests_with_artifacts:
                    metafunc.parametrize(
                        "artifact",
                        ['/tmp/{function}.artifact'.format(function=test_function_name)]
                    )
                else:
                    metafunc.parametrize("artifact", [None])
        else:
            if "artifact" in metafunc.fixturenames:
                metafunc.parametrize("artifact", [None])


def pytest_cmdline_main(config):
    # prevent bad behavior
    if os.environ.get('GITHUB_ACTIONS', '') == 'true':
        if config.getoption('usepdb', False):
            raise pytest.UsageError('Cannot use pdb on GitHub Actions')
