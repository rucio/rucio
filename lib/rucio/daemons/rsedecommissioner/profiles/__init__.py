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

"""Decommissioning profile definitions."""
from rucio.common.config import config_get_list

from .atlas import atlas_move
from .generic import RSEDecommisionerProfilePlugin

PROFILE_MAP = {"atlas_move": atlas_move}

profile_names = ["generic_move", "generic_delete"] + config_get_list("rse-decommissioner", "custom_profile", raise_exception=False, default=[])
for profile_name in profile_names:
    plugin_profile = RSEDecommisionerProfilePlugin.get_algorithm(profile_name)
    PROFILE_MAP[profile_name] = RSEDecommisionerProfilePlugin.policy
