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
import logging
from typing import Callable, Optional
import json
import sys

from rucio.core.plugins import PolicyPackageAlgorithms
from rucio.common.config import config_get_int, config_get_items
from configparser import NoSectionError

from rucio.common.exception import InvalidRequest


class FTS3MetadataPlugin(PolicyPackageAlgorithms):
    """
    Add a "archive_metadata" field to a file's transfer parameters.
    Plugins are registered during initialization and called during a transfer with FTS3
    """

    ALGORITHM_NAME = "fts3_plugins"
    HINTS_NAME = "fts3_plugins_init"
    DEFAULT = "def"

    def __init__(self, policy_algorithm: str):
        """
        :param policy_algorithm: policy algorithm indentifier - choose from any of the policy package algorithms registered under the `fts3_plugins` group.
        :type policy_algorithm: str
        """
        super().__init__()
        self.register("activity", func=self._activity_hints, init_func=self._init_activity_hints)
        self.register(self.DEFAULT, func=lambda x: self._collocation(self._default, x))
        self.register("cms_collocation", func=lambda x: self._collocation(self._cms_collocation, x))
        self.register("test", func=lambda x: self._collocation(self._test_collocation, x))

        self.transfer_limit = config_get_int(
            "transfers",
            option="metadata_byte_limit",
            raise_exception=False,
            default=4096,
        )

        # Use a default if the algorithm isn't supported
        if not self._supports(self.ALGORITHM_NAME, policy_algorithm):
            logging.debug(f"Policy Algorithm {policy_algorithm} not found, ignoring.")
            policy_algorithm = self.DEFAULT

        # If the policy has a supplied and registered init function
        if self._supports(self.HINTS_NAME, policy_algorithm):
            self._get_one_algorithm(self.HINTS_NAME, name=policy_algorithm)()

        self.set_in_hints = self._get_one_algorithm(self.ALGORITHM_NAME, name=policy_algorithm)

    @classmethod
    def register(cls, name: str, func: Callable, init_func: Optional[Callable] = None) -> None:
        """
        Register a fts3 transfer plugin

        :param name: name to register under
        :type name: str
        :param func: function called by the plugin
        :type func: Callable
        :param init_func: Initialization requirements for the plugin, defaults to None
        :type init_func: Optional[Callable], optional
        """
        super()._register(cls.ALGORITHM_NAME, algorithm_dict={name: func})
        if init_func is not None:
            super()._register(cls.HINTS_NAME, algorithm_dict={name: init_func})

    def _init_activity_hints(self):
        try:
            self.prority_table = dict(config_get_items("tape_priority"))
        except NoSectionError:
            self.prority_table = {}

    def _activity_hints(self, activity_kwargs: dict[str, str], default_prority: str = '20') -> dict[str, dict]:
        """ Activity Hints - assign a prorioty based on activity"""
        if "activity" in activity_kwargs:
            activity = activity_kwargs["activity"].lower()

        else:
            raise InvalidRequest("`activity` field not found in passed metadata")

        default_prority = self.prority_table.get("default", default_prority)
        priority = self.prority_table.get(activity, default_prority)

        return {"scheduling_hints": {"priority": priority}}

    def _collocation(self, collocation_func: Callable, hints: dict) -> dict[str, dict]:
        """
        Wraps a 'collacation' style plugin for formatting

        :param collocation_func: Function that defines the collocation rules
        :type collocation_func: Callable
        :param hints: kwargs utilized by the collocation rules
        :type hints: dict
        :return: Collocation hints produced by the collocation_func, wrapped
        :rtype: dict
        """
        return {"collocation_hints": collocation_func(*hints)}

    def _test_collocation(self, *hint: dict) -> dict:
        return {"0": "", "1": "", "2": "", "3": ""}

    def _default(self, *hints: dict) -> dict:
        return {}

    def _cms_collocation(self, *hints: dict) -> None:
        # Placeholder - should not be used
        raise NotImplementedError

    def _verify_in_format(self, hint_dict: dict) -> None:
        """Check the to-be-submitted file transfer params are both json encodable and under the size limit for transfer"""
        try:
            hints_json = json.dumps(hint_dict)
            assert sys.getsizeof(hints_json) < self.transfer_limit

        except TypeError as e:
            raise InvalidRequest("Request malformed, cannot encode to JSON", e)
        except AssertionError as e:
            raise InvalidRequest(
                f"Request too large, decrease to less than {self.transfer_limit}", e
            )

    def hints(self, hint_kwargs: dict) -> dict:
        """
        Produce "archive_metadata" hints for how a transfer should be executed by fts3.

        :param hint_kwargs: Args passed forward to the plugin algorithm
        :type hint_kwargs: dict
        :return: Archiving metadata in the format {archive_metadata: {<plugin produced hints>}}
        :rtype: dict
        """
        hints = self.set_in_hints(hint_kwargs)
        self._verify_in_format(hints)
        return {"archive_metadata": hints}


# Register the policies
FTS3MetadataPlugin("")
