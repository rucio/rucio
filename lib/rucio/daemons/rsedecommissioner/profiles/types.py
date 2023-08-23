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

"""Types used for profile definitions."""
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any


class HandlerOutcome(Enum):
    """Possible outcomes of the handler functions."""
    UNTOUCHED = "Untouched"
    REMOVED = "Removed"
    NEED_ATTENTION = "NeedAttention"


@dataclass
class DecommissioningProfile:
    """Collection of functions that define the action of the decommissioning daemon on an RSE.

    :param rse: RSE to decommission.
    :param initializer: Profile initialization function.
    :param discoverer: Function to find and list the rules to process.
    :param handlers: A list of (condition, action) functions.
    :param finalizer: Finalization function.
    """

    rse: dict[str, Any]
    initializer: Callable[..., None]
    discoverer: Callable[..., Iterable[dict[str, Any]]]
    handlers: list[tuple[Callable[..., bool], Callable[..., HandlerOutcome]]]
    finalizer: Callable[..., bool]

    def initialize(
        self,
        *,
        logger: Callable[..., None] = logging.log
    ) -> None:
        """Call the initializer."""
        self.initializer(self.rse, logger=logger)

    def discover(
        self,
        *,
        logger: Callable[..., None] = logging.log
    ) -> Iterable[dict[str, Any]]:
        """Call the discoverer."""
        return self.discoverer(self.rse, logger=logger)

    def process(
        self,
        rule: dict[str, Any],
        *,
        logger: Callable[..., None] = logging.log
    ) -> HandlerOutcome:
        """Process a rule.

        :param rule: Rule dict.
        :returns: Boolean indicating whether the rule was removed. None if no condition matches.
        """
        for condition, action in self.handlers:
            if condition(rule, self.rse, logger=logger):
                return action(rule, self.rse, logger=logger)

        logger(logging.INFO,
               '(%s) No handler matched rule %s for %s:%s',
               rule['rse'], rule['id'], rule['scope'], rule['name'])
        return HandlerOutcome.NEED_ATTENTION

    def finalize(
        self,
        *,
        logger: Callable[..., None] = logging.log
    ) -> bool:
        """Call the finalizer."""
        return self.finalizer(self.rse, logger=logger)
