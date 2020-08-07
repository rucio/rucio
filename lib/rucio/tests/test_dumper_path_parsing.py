# Copyright 2015-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Fernando Lopez <fernando.e.lopez@gmail.com>, 2015
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from rucio.common.dumper.path_parsing import components
from rucio.common.dumper.path_parsing import remove_prefix


class TestPathParsing(object):
    def test_remove_prefix(self):
        prefix = ['a', 'b', 'c', 'd']

        full = ['a', 'b', 'c', 'd', 'e', 'f']  # -> e,f
        relative = ['c', 'd', 'e', 'f']  # -> e,f
        exclusive = ['e', 'f', 'g']  # -> e,f,g
        mixed = ['c', 'a', 'e', 'f']  # -> c,a,e,f
        mixed2 = ['d', 'a', 'e']  # -> a,e

        assert remove_prefix(prefix, full) == ['e', 'f']
        assert remove_prefix(prefix, relative) == ['e', 'f']
        assert remove_prefix(prefix, exclusive) == ['e', 'f', 'g']
        assert remove_prefix(prefix, mixed) == ['c', 'a', 'e', 'f']
        assert remove_prefix(prefix, mixed2) == ['a', 'e']
        assert remove_prefix(prefix, prefix) == []
        assert remove_prefix([], relative) == relative
        assert remove_prefix(prefix, []) == []

    def test_real_sample(self):
        prefix = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/')
        path_regular = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/rucio/group10/perf-jets/02/1a/group10.perf-jets.data12_8TeV.periodI.physics_HadDelayed.jmr.2015.01.29.v01.log.4770484.000565.log.tgz')
        path_user = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/rucio/user/zxi/fd/73/user.zxi.361100.PowhegPythia8EvtGen.DAOD_TOPQ1.e3601_s2576_s2132_r6630_r6264_p2363.08-12-15.log.6249615.000015.log.tgz')
        path_group = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/rucio/group/det-ibl/00/5d/group.det-ibl.6044653.BTAGSTREAM._000014.root')
        path_sam = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/SAM/testfile17-GET-ATLASSCRATCHDISK')

        assert '/'.join(remove_prefix(prefix, path_regular)) == 'rucio/group10/perf-jets/02/1a/group10.perf-jets.data12_8TeV.periodI.physics_HadDelayed.jmr.2015.01.29.v01.log.4770484.000565.log.tgz', 'Normal path inside directory rucio/'
        assert '/'.join(remove_prefix(prefix, path_user)) == 'rucio/user/zxi/fd/73/user.zxi.361100.PowhegPythia8EvtGen.DAOD_TOPQ1.e3601_s2576_s2132_r6630_r6264_p2363.08-12-15.log.6249615.000015.log.tgz', 'User path inside rucio/'
        assert '/'.join(remove_prefix(prefix, path_group)) == 'rucio/group/det-ibl/00/5d/group.det-ibl.6044653.BTAGSTREAM._000014.root', 'Group path inside rucio/'
        assert '/'.join(remove_prefix(prefix, path_sam)) == 'SAM/testfile17-GET-ATLASSCRATCHDISK', 'SAM path (outside rucio/)'
