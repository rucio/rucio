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

import json
import sys
from typing import TYPE_CHECKING, Any, Optional, TypeVar

from rucio.common.config import config_get_int
from rucio.common.exception import InvalidRequest
from rucio.common.plugins import PolicyPackageAlgorithms

if TYPE_CHECKING:
    from collections.abc import Callable

FTS3TapeMetadataPluginType = TypeVar('FTS3TapeMetadataPluginType', bound='FTS3TapeMetadataPlugin')


class FTS3TapeMetadataPlugin(PolicyPackageAlgorithms):
    """
    Add a "archive_metadata" field to a file's transfer parameters.
    Plugins are registered during initialization and called during a transfer with FTS3
    """

    ALGORITHM_NAME = "fts3_tape_metadata_plugins"
    _INIT_FUNC_NAME = "fts3_plugins_init"
    DEFAULT = "def"

    def __init__(self, policy_algorithm: str) -> None:
        """
        :param policy_algorithm: policy algorithm identifier - choose from any of the policy package algorithms registered under the `fts3_tape_metadata_plugins` group.
        """
        super().__init__()
        self.transfer_limit = config_get_int(
            "transfers",
            option="metadata_byte_limit",
            raise_exception=False,
            default=4096,
        )

        if not self._supports(self.ALGORITHM_NAME, policy_algorithm):
            raise ValueError(f'Policy Algorithm {policy_algorithm} not found')

        if self._supports(self._INIT_FUNC_NAME, policy_algorithm):
            init_func = self._get_one_algorithm(self._INIT_FUNC_NAME, name=policy_algorithm)
            init_func()

        self.set_in_hints = self._get_one_algorithm(self.ALGORITHM_NAME, name=policy_algorithm)

    @classmethod
    def _module_init(cls: type[FTS3TapeMetadataPluginType]) -> None:
        cls.register(cls.DEFAULT, func=lambda x: cls._default(cls, x))  # type: ignore

    @classmethod
    def register(cls: type[FTS3TapeMetadataPluginType], name: str, func: 'Callable', init_func: Optional['Callable'] = None) -> None:
        """
        Register a fts3 transfer plugin

        :param name: name to register under
        :param func: function called by the plugin
        :param init_func: Initialization requirements for the plugin, defaults to None
        """
        super()._register(cls.ALGORITHM_NAME, algorithm_dict={name: func})
        if init_func is not None:
            super()._register(cls._INIT_FUNC_NAME, algorithm_dict={name: init_func})

    @staticmethod
    def _collocation(collocation_func: 'Callable', hints: dict[str, Any]) -> dict[str, dict]:
        """
        Wraps a 'collocation' style plugin for formatting

        :param collocation_func: Function that defines the collocation rules
        :param hints: kwargs utilized by the collocation rules
        :return: Collocation hints produced by the collocation_func, wrapped
        """
        return {"collocation_hints": collocation_func(**hints)}

    def _default(self, *hints: dict) -> dict:
        return {}

    def _verify_in_format(self, hint_dict: dict[str, Any]) -> None:
        """Check the to-be-submitted file transfer params are both json encodable and under the size limit for transfer"""
        try:
            hints_json = json.dumps(hint_dict)
            in_tranfer_limit = sys.getsizeof(hints_json) < self.transfer_limit

        except TypeError as e:
            raise InvalidRequest("Request malformed, cannot encode to JSON", e)

        if not in_tranfer_limit:
            raise InvalidRequest(
                f"Request too large, decrease to less than {self.transfer_limit}"
            )

    def hints(self, hint_kwargs: dict) -> dict[str, Any]:
        """
        Produce "archive_metadata" hints for how a transfer should be executed by fts3.

        :param hint_kwargs: Args passed forward to the plugin algorithm
        :return: Archiving metadata in the format {archive_metadata: {<plugin produced hints>}}
        """
        hints = self.set_in_hints(hint_kwargs)
        self._verify_in_format(hints)
        return {"archive_metadata": hints}


class ActivityBasedTransferPriorityPlugin(FTS3TapeMetadataPlugin):
    def __init__(self, policy_algorithm: str = 'activity') -> None:
        self.register(
            policy_algorithm,
            func=lambda x: self._get_activity_priority(x),
            init_func=self._init_default_priority)
        super().__init__(policy_algorithm)

    def _init_default_priority(self) -> None:
        self.default_priority = config_get_int(
            "tape_priority",
            option="default",
            raise_exception=False,
            default=20,
        )

    def _get_activity_priority(self, activity_kwargs: dict[str, str]) -> dict[str, dict]:
        """ Activity Hints - assign a priority based on activity"""
        if "activity" in activity_kwargs:
            activity = activity_kwargs["activity"]
        else:
            raise InvalidRequest("`activity` field not found in passed metadata")

        priority = config_get_int(
            "tape_priority",
            option=activity,
            raise_exception=False,
            default=self.default_priority,
        )

        return {"scheduling_hints": {"priority": priority}}


# Register the policies
FTS3TapeMetadataPlugin._module_init()
ActivityBasedTransferPriorityPlugin()
