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


def test_default_profiles():
    # Test the basic set without config added
    from rucio.daemons.rsedecommissioner.profiles import PROFILE_MAP
    assert set(PROFILE_MAP.keys()) == set(["generic_delete", "generic_move", "atlas_move"])


def test_custom_profile():
    from rucio.daemons.rsedecommissioner.profiles.generic import RSEDecommisionerProfilePlugin
    mock_profile_name = "mock_profile"

    class MockTransferProfile(RSEDecommisionerProfilePlugin):
        @staticmethod
        def policy(rse="", config=""):
            return None

    MockTransferProfile.register(mock_profile_name, MockTransferProfile.policy)

    # Able to pull the specific profile
    plugin_profile = RSEDecommisionerProfilePlugin.get_algorithm(mock_profile_name)
    assert plugin_profile() is None
