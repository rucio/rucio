# -*- coding: utf-8 -*-
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

"""ATLAS-specific decommissioning profiles."""

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from rucio.core.did import get_metadata

from .generic import _call_for_attention, generic_move

if TYPE_CHECKING:
    from .types import DecommissioningProfile


def atlas_move(rse: dict[str, Any], config: dict[str, Any]) -> 'DecommissioningProfile':
    """Return a profile for moving rules that satisfy conditions to a specific destination.

    The "ATLAS move" profile lists out all rules that are locking replicas
    at the given RSE, and moves them to the specified destination if either
    one of the following is true:

    - The RSE expression of the rule is trivial (the RSE name itself).
    - There are no replicas locked by the rule that reside on another RSE.
    - The datatype of the DID is not "log".

    :param rse: RSE to decommission.
    :param config: Decommissioning configuration dictionary.
    :returns: A decommissioning profile dictionary.
    """
    profile = generic_move(rse, config)
    # Insert before the trivial RSE expression handler
    idx = next(pos for pos, handler in enumerate(profile.handlers)
               if handler[0].__name__ == '_has_trivial_rse_expression')
    profile.handlers.insert(idx, (_is_log_file, _call_for_attention))
    return profile


def _is_log_file(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    """Check if the datatype metadata is 'log'."""
    return get_metadata(rule['scope'], rule['name'])['datatype'] == 'log'
