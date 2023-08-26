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

import importlib
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


def import_extras(module_list: list[str]) -> "dict[str, Any]":
    out = dict()
    for mod in module_list:
        out[mod] = None
        try:
            with warnings.catch_warnings():
                # TODO: remove when https://github.com/paramiko/paramiko/issues/2038 is fixed
                warnings.filterwarnings('ignore', 'Blowfish has been deprecated', module='paramiko')
                # TODO: deprecated python 2 and 3.6 too ...
                warnings.filterwarnings('ignore', 'Python .* is no longer supported', module='paramiko')
                out[mod] = importlib.import_module(mod)
        except ImportError:
            pass
    return out
