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

"""Functions to manage decommissioning configurations."""

import json
from enum import Enum
from typing import Any

from rucio.common.constants import RseAttr
from rucio.core.rse import add_rse_attribute, get_rse_attribute


class DecommissioningStatus(Enum):
    """Decommissioning status flags."""

    PROCESSING = 'processing'
    DONE = 'done'
    SUSPENDED = 'suspended'


class InvalidStatusName(Exception):
    """Exception for invalid decommissioning status name set from command line."""


def config_to_attr(config: dict[str, Any]) -> str:
    """Form the attribute string from a config dictionary.

    :param config: Decommissioning configuration dictionary.
    :returns: Comma-separated key-value string encoding the configuration.
    """
    json_compat = config.copy()
    if isinstance(json_compat.get("status"), DecommissioningStatus):
        json_compat["status"] = json_compat["status"].value

    return json.dumps(json_compat, separators=(',', ':'))


def attr_to_config(attr: str) -> dict[str, Any]:
    """Form the config dictionary from an attribute string.

    :param attr: Comma-separated key-value string encoding the configuration.
    :returns: Decommissioning configuration dictionary.
    """
    config: dict[str, Any]

    try:
        config = json.loads(attr)
    except json.JSONDecodeError:
        config = dict(map(lambda s: s.split('=', 1), attr.split(',')))
        config = {k: v.strip().strip('"') for k, v in config.items()}

    if "status" in config:
        try:
            config["status"] = DecommissioningStatus[config["status"].upper()]
        except KeyError:
            raise InvalidStatusName(config["status"])
    else:
        config["status"] = DecommissioningStatus.PROCESSING

    return config


def set_status(
    rse_id: str,
    status: DecommissioningStatus
) -> None:
    """Update the decommission attribute of the RSE.

    :param rse_id: RSE ID.
    :param status: RSE decommissioning status.
    """
    config_raw: str | None = get_rse_attribute(rse_id, RseAttr.DECOMMISSION)
    config_str: str = config_raw if config_raw is not None else '{}'
    config = attr_to_config(config_str)
    config["status"] = status
    add_rse_attribute(rse_id, RseAttr.DECOMMISSION, config_to_attr(config))
