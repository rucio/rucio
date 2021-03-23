# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021

import pytest

import rucio.common.test_rucio_server as server_test


@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestRucioServer(server_test.TestRucioServer):
    # moved to rucio.common.test_rucio_server.TestRucioServer
    pass
