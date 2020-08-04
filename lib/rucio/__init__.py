# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2012
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import gettext
import sys

if sys.version_info < (3,):
    gettext.install('rucio', unicode=1)  # pylint: disable=unexpected-keyword-arg
else:
    gettext.install('rucio')
