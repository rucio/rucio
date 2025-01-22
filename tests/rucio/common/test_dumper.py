# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from unittest.mock import Mock, patch

import pytest

from rucio.common import config, dumper
from rucio.common.dumper.path_parsing import components, remove_prefix


class TestDumper:
    @pytest.mark.parametrize("code", [2, 3, 500])
    def test_error(self, code):
        with pytest.raises(SystemExit) as excinfo:
            dumper.error('message', code)
        assert excinfo.value.code == code

    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('client', 'ca_cert', '/opt/rucio/etc/web/ca.crt')]},
    ], indirect=True)
    def test_cacert_config_exists(self, temp_config_file, file_config_mock):
        with patch('os.path.exists', Mock(return_value=True)):
            assert dumper.cacert_config(config, '.') == '/opt/rucio/etc/web/ca.crt'

    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('client', 'ca_cert', '')]},
        {"overrides": [('client', '', '')]},
        {"overrides": [('', '', '')]}],
        ids=[
            "ca_cert_empty",
            "no_option",
            "no_section"
        ],
        indirect=True)
    def test_cacert_config_not_set(self, temp_config_file, file_config_mock):
        with patch('os.path.exists', Mock(return_value=True)):
            assert dumper.cacert_config(config, '.') is False

    def test_cacert_config_no_cfg_found(self):
        with patch('os.path.exists', Mock(return_value=True)):
            assert dumper.cacert_config(config, '.') is False

    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('client', 'ca_cert', '/opt/rucio/etc/web/ca.crt')]},
    ], indirect=True)
    def test_cacert_config_set_but_does_not_exist(self, temp_config_file, file_config_mock):
        with patch('os.path.exists', Mock(return_value=False)):
            assert dumper.cacert_config(config, '.') is False


class TestDumperPathParsing:
    @pytest.mark.parametrize("input_path, expected_output", [
        (['a', 'b', 'c', 'd', 'e', 'f'], ['e', 'f']),
        (['c', 'd', 'e', 'f'], ['e', 'f']),
        (['e', 'f', 'g'], ['e', 'f', 'g']),
        (['c', 'a', 'e', 'f'], ['c', 'a', 'e', 'f']),
        (['d', 'a', 'e'], ['a', 'e']),
        (['a', 'b', 'c', 'd'], []),
        (['a', 'b', 'c', 'd'], []),
    ], ids=[
        "full",
        "relative",
        "exclusive",
        "mixed",
        "mixed2",
        "prefix",
        "empty_path",
    ])
    def test_remove_prefix(self, input_path, expected_output):
        prefix = ['a', 'b', 'c', 'd']
        assert remove_prefix(prefix, input_path) == expected_output

    @pytest.mark.parametrize("expected_output", [
        ('rucio/group10/perf-jets/02/1a/group10.perf-jets.data12_8TeV.periodI.physics_HadDelayed.jmr.2015.01.29.v01.log.4770484.000565.log.tgz'),
        ('rucio/user/zxi/fd/73/user.zxi.361100.PowhegPythia8EvtGen.DAOD_TOPQ1.e3601_s2576_s2132_r6630_r6264_p2363.08-12-15.log.6249615.000015.log.tgz'),
        ('rucio/group/det-ibl/00/5d/group.det-ibl.6044653.BTAGSTREAM._000014.root'),
        ('SAM/testfile17-GET-ATLASSCRATCHDISK'),
    ], ids=[
        "normal_path",
        "user_path",
        "group_path",
        "sam_path",
    ])
    def test_real_sample(self, expected_output):
        prefix = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/')
        input = prefix + components(expected_output)
        assert '/'.join(remove_prefix(prefix, input)) == expected_output

    def test_remove_prefix_empty_prefix(self):
        prefix = []
        path = ['a', 'b', 'c', 'd']
        assert remove_prefix(prefix, path) == path
