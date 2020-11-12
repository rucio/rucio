# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Cheng-Hsi Chao <cheng-hsi.chao@cern.ch>, 2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2016
# - Frank Berghaus <frank.berghaus@cern.ch>, 2017-2018
# - Tobias Wegner <twegner@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from rucio.common.utils import execute


class TestModuleImport():
    def test_import(self):
        """ """
        cmd = 'rucio --version'
        exitcode, out, err = execute(cmd)
        assert 'ImportError' not in err
        assert 'ImportError' not in out
        assert 'Exception' not in err
        assert 'Exception' not in out
